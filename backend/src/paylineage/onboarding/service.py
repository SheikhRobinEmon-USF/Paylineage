"""Onboarding and bank change workflows on PostgreSQL (I1, I7, I11).

Every action: (1) the state machine says the transition exists, (2) the policy
says this actor may perform it with this evidence, (3) the database applies it
with optimistic locking, (4) an audit event records who did what. Invoice or
email content can create a *request* but never verifies anything (I1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from paylineage.audit.chain import append
from paylineage.db.models import OnboardingRequest, Supplier, SupplierBankAccount
from paylineage.db.vault import account_token, mask_account, normalize_account, store_account
from paylineage.domain.clock import to_ms
from paylineage.domain.context import Actor, ConflictError, Ctx, NotFoundError, PolicyRefusedError
from paylineage.domain.enums import AccountStatus, OldAccountOutcome, RequestKind, SupplierStatus
from paylineage.onboarding import simulated
from paylineage.onboarding.machine import IllegalTransitionError, OnbAction, OnbState, next_state
from paylineage.policy.record import decide

COOLING_OFF_MS = {"low": 86_400_000, "medium": 172_800_000, "high": 432_000_000}
UNTRUSTED_CHANNELS = frozenset({"email", "invoice", "phone_inbound"})


def _onboarding_input(
    ctx: Ctx,
    req: OnboardingRequest | None,
    action: OnbAction,
    actor: Actor,
    *,
    supplier_id: str,
    kind: RequestKind,
    assignee_id: str | None = None,
    verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "request_kind": "onboarding",
        "now_ms": to_ms(ctx.now()),
        "onboarding": {
            "action": action.value,
            "kind": kind.value,
            "actor_id": actor.id,
            "actor_roles": sorted(r for r in actor.roles if r != "system"),
            "supplier_id": supplier_id,
            "requester_id": req.requester_id if req else None,
            "verifier_id": req.verifier_id if req else None,
            "assignee_id": assignee_id,
            "verification": verification,
        },
    }


def _authorize(
    ctx: Ctx, policy_input: dict[str, Any], actor: Actor, subject_id: str, action: OnbAction
) -> None:
    d = decide(ctx, policy_input, actor=actor, stage=f"onboarding.{action.value}", subject_id=subject_id)
    if not d.allowed:
        raise PolicyRefusedError(d, f"{action.value} refused: {', '.join(d.reasons)}")


def _transition(req: OnboardingRequest | None, kind: RequestKind, action: OnbAction) -> OnbState:
    try:
        return next_state(
            kind,
            OnbState(req.state) if req else None,
            action,
            verifier_assigned=bool(req and req.verifier_id),
        )
    except IllegalTransitionError as exc:
        raise ConflictError("ILLEGAL_TRANSITION", str(exc)) from exc


def _audit(ctx: Ctx, actor: Actor, kind: str, subject: str, payload: dict[str, Any]) -> None:
    append(ctx.session, actor=actor.id, kind=kind, subject_id=subject, payload=payload, now=ctx.now())


def get_request(ctx: Ctx, request_id: str, *, lock: bool = True) -> OnboardingRequest:
    q = select(OnboardingRequest).where(OnboardingRequest.id == request_id)
    if lock:
        q = q.with_for_update()
    req = ctx.session.execute(q).scalar_one_or_none()
    if req is None:
        raise NotFoundError("NOT_FOUND", "onboarding request not found")
    return req


# ---------------- new supplier ----------------


@dataclass(frozen=True)
class NewSupplier:
    legal_name: str
    verified_domains: list[str]
    registry_id: str | None
    contact_on_file: dict[str, Any] | None
    bank_account_raw: str
    bank_name: str
    channel: str = "user_entered"


def request_new_supplier(ctx: Ctx, actor: Actor, data: NewSupplier) -> OnboardingRequest:
    """Requested -> Unverified. Record exists, not payable."""
    now = ctx.now()
    _transition(None, RequestKind.NEW_SUPPLIER, OnbAction.REQUEST_SUPPLIER)
    supplier = Supplier(
        legal_name=data.legal_name,
        verified_domains=[],  # domains become trusted only on verification
        status=SupplierStatus.REQUESTED.value,
        contact_on_file=data.contact_on_file,
        contact_recorded_at=now if data.contact_on_file else None,
        registry_id=data.registry_id,
        created_from=data.channel,
        requested_by=actor.id,
        created_at=now,
        updated_at=now,
    )
    ctx.session.add(supplier)
    ctx.session.flush()
    _authorize(
        ctx,
        _onboarding_input(
            ctx,
            None,
            OnbAction.REQUEST_SUPPLIER,
            actor,
            supplier_id=supplier.id,
            kind=RequestKind.NEW_SUPPLIER,
        ),
        actor,
        supplier.id,
        OnbAction.REQUEST_SUPPLIER,
    )
    token = store_account(ctx.session, data.bank_account_raw)
    acct = SupplierBankAccount(
        supplier_id=supplier.id,
        account_token=token,
        last4=normalize_account(data.bank_account_raw)[-4:],
        bank_name=data.bank_name,
        status=AccountStatus.PENDING.value,
        created_at=now,
    )
    ctx.session.add(acct)
    ctx.session.flush()
    req = OnboardingRequest(
        supplier_id=supplier.id,
        kind=RequestKind.NEW_SUPPLIER.value,
        state=OnbState.REQUESTED.value,
        bank_account_id=acct.id,
        channel=data.channel,
        requester_id=actor.id,
        risk_tier="high" if data.channel in UNTRUSTED_CHANNELS else "medium",
        verification={"claimed_domains": data.verified_domains},
        created_at=now,
        updated_at=now,
    )
    ctx.session.add(req)
    ctx.session.flush()
    _audit(
        ctx,
        actor,
        "supplier.requested",
        supplier.id,
        {
            "request_id": req.id,
            "legal_name": data.legal_name,
            "account": mask_account(data.bank_account_raw),
            "account_token": token,
            "channel": data.channel,
        },
    )
    req.state = _transition(req, RequestKind.NEW_SUPPLIER, OnbAction.OPEN_RECORD).value
    supplier.status = SupplierStatus.UNVERIFIED.value
    supplier.updated_at = now
    req.updated_at = now
    _audit(ctx, actor, "supplier.record_opened", supplier.id, {"request_id": req.id})
    ctx.session.flush()
    return req


# ---------------- bank change ----------------


def record_bank_change(
    ctx: Ctx,
    actor: Actor,
    *,
    supplier_id: str,
    new_account_raw: str,
    bank_name: str,
    channel: str,
    old_account_outcome: OldAccountOutcome,
) -> OnboardingRequest:
    """Verified -> Verifying for the new account. Old account per the three outcome rule."""
    now = ctx.now()
    supplier = ctx.session.execute(
        select(Supplier).where(Supplier.id == supplier_id).with_for_update()
    ).scalar_one_or_none()
    if supplier is None:
        raise NotFoundError("NOT_FOUND", "supplier not found")
    if supplier.status != SupplierStatus.VERIFIED.value:
        raise ConflictError("ILLEGAL_TRANSITION", "bank changes apply to verified suppliers")
    open_case = ctx.session.execute(
        select(OnboardingRequest).where(
            OnboardingRequest.supplier_id == supplier_id,
            OnboardingRequest.kind == RequestKind.BANK_CHANGE.value,
            OnboardingRequest.closed_at.is_(None),
        )
    ).first()
    if open_case is not None:
        raise ConflictError("ILLEGAL_TRANSITION", "a bank change for this supplier is already open")
    _transition(None, RequestKind.BANK_CHANGE, OnbAction.RECORD_BANK_CHANGE)
    _authorize(
        ctx,
        _onboarding_input(
            ctx,
            None,
            OnbAction.RECORD_BANK_CHANGE,
            actor,
            supplier_id=supplier_id,
            kind=RequestKind.BANK_CHANGE,
        ),
        actor,
        supplier_id,
        OnbAction.RECORD_BANK_CHANGE,
    )
    token = store_account(ctx.session, new_account_raw)
    existing = ctx.session.execute(
        select(SupplierBankAccount).where(
            SupplierBankAccount.supplier_id == supplier_id, SupplierBankAccount.account_token == token
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("ILLEGAL_TRANSITION", "account already on file for this supplier")
    old = (
        ctx.session.execute(
            select(SupplierBankAccount)
            .where(
                SupplierBankAccount.supplier_id == supplier_id,
                SupplierBankAccount.status == AccountStatus.VERIFIED.value,
            )
            .with_for_update()
        )
        .scalars()
        .first()
    )
    acct = SupplierBankAccount(
        supplier_id=supplier_id,
        account_token=token,
        last4=normalize_account(new_account_raw)[-4:],
        bank_name=bank_name,
        status=AccountStatus.PENDING.value,
        created_at=now,
    )
    ctx.session.add(acct)
    ctx.session.flush()
    if old is not None and old_account_outcome in (OldAccountOutcome.COMPROMISED, OldAccountOutcome.CLOSED):
        old.status = AccountStatus.SUSPENDED.value
        old.reported_compromised_at = now
        _audit(
            ctx,
            actor,
            "supplier.account_suspended",
            supplier_id,
            {"account_id": old.id, "reason": old_account_outcome.value},
        )
    req = OnboardingRequest(
        supplier_id=supplier_id,
        kind=RequestKind.BANK_CHANGE.value,
        state=OnbState.VERIFYING.value,
        bank_account_id=acct.id,
        old_account_id=old.id if old else None,
        old_account_outcome=old_account_outcome.value,
        channel=channel,
        requester_id=actor.id,
        risk_tier="high" if channel in UNTRUSTED_CHANNELS else "medium",
        created_at=now,
        updated_at=now,
    )
    ctx.session.add(req)
    ctx.session.flush()
    _audit(
        ctx,
        actor,
        "supplier.bank_change_recorded",
        supplier_id,
        {
            "request_id": req.id,
            "new_account_id": acct.id,
            "account": mask_account(new_account_raw),
            "channel": channel,
            "old_account_outcome": old_account_outcome.value,
        },
    )
    return req


# ---------------- verification workflow ----------------


def assign_verifier(ctx: Ctx, actor: Actor, request_id: str, assignee: Actor) -> OnboardingRequest:
    req = get_request(ctx, request_id)
    kind = RequestKind(req.kind)
    to = _transition(req, kind, OnbAction.ASSIGN_VERIFIER)
    _authorize(
        ctx,
        _onboarding_input(
            ctx,
            req,
            OnbAction.ASSIGN_VERIFIER,
            actor,
            supplier_id=req.supplier_id,
            kind=kind,
            assignee_id=assignee.id,
        ),
        actor,
        req.supplier_id,
        OnbAction.ASSIGN_VERIFIER,
    )
    if "verifier" not in assignee.roles or not assignee.active:
        raise ConflictError("ROLE_REQUIRED", "assignee is not an active verifier")
    req.verifier_id = assignee.id
    req.assigned_by = actor.id
    req.state = to.value
    req.updated_at = ctx.now()
    if kind is RequestKind.NEW_SUPPLIER:
        supplier = ctx.session.get(Supplier, req.supplier_id)
        assert supplier is not None
        supplier.status = SupplierStatus.VERIFYING.value
        supplier.updated_at = ctx.now()
    _audit(
        ctx,
        actor,
        "supplier.verifier_assigned",
        req.supplier_id,
        {"request_id": req.id, "verifier_id": assignee.id},
    )
    ctx.session.flush()
    return req


@dataclass(frozen=True)
class VerificationClaim:
    """What the verifier attests. Registry and contact facts are computed by the server."""

    method: str  # callback_on_file | simulated_validation_service
    callback_confirmed: bool = False
    note: str = ""


def _evidence(ctx: Ctx, req: OnboardingRequest, claim: VerificationClaim) -> dict[str, Any]:
    supplier = ctx.session.get(Supplier, req.supplier_id)
    acct = ctx.session.get(SupplierBankAccount, req.bank_account_id) if req.bank_account_id else None
    assert supplier is not None
    reg = simulated.registry_lookup(supplier.registry_id, supplier.legal_name)
    if claim.method == "callback_on_file":
        on_file = supplier.contact_on_file is not None and supplier.contact_recorded_at is not None
        contact_source = "on_file" if on_file else "none"
        recorded_ms = to_ms(supplier.contact_recorded_at) if supplier.contact_recorded_at else None
        bank_confirmed = bool(claim.callback_confirmed) and on_file
    elif claim.method == "simulated_validation_service":
        contact_source, recorded_ms = "none", None
        bank_confirmed = False
        if acct is not None:
            from paylineage.db.models import VaultValue

            raw = ctx.session.get(VaultValue, acct.account_token)
            bank_confirmed = raw is not None and simulated.validation_service(raw.value, supplier.legal_name)
    else:
        raise ConflictError("INPUT_INVALID", "unknown verification method")
    return {
        "method": claim.method,
        "contact_source": contact_source,
        "contact_recorded_at_ms": recorded_ms,
        "request_created_at_ms": to_ms(req.created_at),
        "registry_match": reg.found and reg.name_matches,
        "bank_confirmed": bank_confirmed,
    }


def record_verification(
    ctx: Ctx, actor: Actor, request_id: str, claim: VerificationClaim
) -> OnboardingRequest:
    req = get_request(ctx, request_id)
    kind = RequestKind(req.kind)
    to = _transition(req, kind, OnbAction.RECORD_VERIFICATION)
    evidence = _evidence(ctx, req, claim)
    _authorize(
        ctx,
        _onboarding_input(
            ctx,
            req,
            OnbAction.RECORD_VERIFICATION,
            actor,
            supplier_id=req.supplier_id,
            kind=kind,
            verification=evidence,
        ),
        actor,
        req.supplier_id,
        OnbAction.RECORD_VERIFICATION,
    )
    req.verification = {
        **(req.verification or {}),
        **evidence,
        "note": claim.note[:500],
        "verified_by": actor.id,
    }
    req.state = to.value
    req.updated_at = ctx.now()
    if kind is RequestKind.NEW_SUPPLIER:
        supplier = ctx.session.get(Supplier, req.supplier_id)
        assert supplier is not None
        supplier.status = SupplierStatus.STEWARD_REVIEW.value
    if req.bank_account_id:
        acct = ctx.session.get(SupplierBankAccount, req.bank_account_id)
        assert acct is not None
        acct.verified_by = actor.id
        acct.verified_method = claim.method
    _audit(ctx, actor, "supplier.verification_recorded", req.supplier_id, {"request_id": req.id, **evidence})
    ctx.session.flush()
    return req


def steward_approve(ctx: Ctx, actor: Actor, request_id: str) -> OnboardingRequest:
    req = get_request(ctx, request_id)
    kind = RequestKind(req.kind)
    to = _transition(req, kind, OnbAction.STEWARD_APPROVE)
    evidence = (
        {
            k: req.verification[k]
            for k in (
                "method",
                "contact_source",
                "contact_recorded_at_ms",
                "request_created_at_ms",
                "registry_match",
                "bank_confirmed",
            )
        }
        if req.verification and "method" in req.verification
        else None
    )
    _authorize(
        ctx,
        _onboarding_input(
            ctx,
            req,
            OnbAction.STEWARD_APPROVE,
            actor,
            supplier_id=req.supplier_id,
            kind=kind,
            verification=evidence,
        ),
        actor,
        req.supplier_id,
        OnbAction.STEWARD_APPROVE,
    )
    now = ctx.now()
    req.steward_id = actor.id
    req.state = to.value
    req.updated_at = now
    req.closed_at = now
    supplier = ctx.session.get(Supplier, req.supplier_id)
    assert supplier is not None
    if req.bank_account_id:
        acct = ctx.session.get(SupplierBankAccount, req.bank_account_id)
        assert acct is not None
        acct.status = AccountStatus.VERIFIED.value
        acct.steward_by = actor.id
        acct.verified_at = now
        if kind is RequestKind.BANK_CHANGE:
            # A timer never replaces verification; it is an extra wait after it.
            acct.cooling_off_until = now + timedelta(milliseconds=COOLING_OFF_MS[req.risk_tier])
    if kind is RequestKind.NEW_SUPPLIER:
        supplier.status = SupplierStatus.VERIFIED.value
        claimed = (req.verification or {}).get("claimed_domains", [])
        supplier.verified_domains = [str(d).lower() for d in claimed][:10]
    supplier.updated_at = now
    _audit(
        ctx,
        actor,
        "supplier.verified",
        req.supplier_id,
        {
            "request_id": req.id,
            "kind": kind.value,
            "requester_id": req.requester_id,
            "verifier_id": req.verifier_id,
            "steward_id": actor.id,
            "account_id": req.bank_account_id,
        },
    )
    ctx.session.flush()
    return req


def reject(ctx: Ctx, actor: Actor, request_id: str, reason: str) -> OnboardingRequest:
    req = get_request(ctx, request_id)
    kind = RequestKind(req.kind)
    to = _transition(req, kind, OnbAction.REJECT)
    _authorize(
        ctx,
        _onboarding_input(ctx, req, OnbAction.REJECT, actor, supplier_id=req.supplier_id, kind=kind),
        actor,
        req.supplier_id,
        OnbAction.REJECT,
    )
    now = ctx.now()
    req.state = to.value
    req.resolution = reason[:500]
    req.updated_at = now
    req.closed_at = now
    if req.bank_account_id:
        acct = ctx.session.get(SupplierBankAccount, req.bank_account_id)
        assert acct is not None
        acct.status = AccountStatus.REVOKED.value
    if kind is RequestKind.NEW_SUPPLIER:
        supplier = ctx.session.get(Supplier, req.supplier_id)
        assert supplier is not None
        supplier.status = SupplierStatus.REJECTED.value
    _audit(ctx, actor, "supplier.rejected", req.supplier_id, {"request_id": req.id, "reason": reason[:500]})
    ctx.session.flush()
    return req


def supplier_changes_for(ctx: Ctx, supplier_id: str) -> list[dict[str, Any]]:
    """People who touched this supplier's bank details, with timestamps (policy SoD input)."""
    out: list[dict[str, Any]] = []
    rows = ctx.session.execute(
        select(OnboardingRequest).where(OnboardingRequest.supplier_id == supplier_id)
    ).scalars()
    for r in rows:
        out.append(
            {
                "actor_id": r.requester_id,
                "role": "bank_change_recorder" if r.kind == "bank_change" else "requester",
                "at_ms": to_ms(r.created_at),
            }
        )
        if r.verifier_id:
            out.append({"actor_id": r.verifier_id, "role": "verifier", "at_ms": to_ms(r.updated_at)})
        if r.steward_id:
            out.append(
                {"actor_id": r.steward_id, "role": "steward", "at_ms": to_ms(r.closed_at or r.updated_at)}
            )
    return out[:64]


__all__ = [
    "NewSupplier",
    "VerificationClaim",
    "account_token",
    "assign_verifier",
    "record_bank_change",
    "record_verification",
    "reject",
    "request_new_supplier",
    "steward_approve",
    "supplier_changes_for",
]
