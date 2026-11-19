"""Payment transaction service: valid transitions, versions, idempotency (rule 3).

Every state change: lock the row, check the machine, run the policy on input
rebuilt from the store, apply, audit. A material change bumps `version`, draws
a new nonce and digest, and voids every approval of the old version (I3, I4).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from paylineage.audit.chain import append
from paylineage.db.models import HoldClearance, Invoice, Payment, Signal, Supplier, SupplierBankAccount
from paylineage.db.vault import account_token, mask_account
from paylineage.domain.context import Actor, ConflictError, Ctx, ForbiddenError, NotFoundError
from paylineage.domain.enums import PaymentState
from paylineage.domain.ids import new_id
from paylineage.domain.reason_codes import code_class
from paylineage.onboarding.service import supplier_changes_for
from paylineage.payments.machine import IllegalPaymentTransitionError, PayEvent, next_state
from paylineage.payments.record import compute_digest
from paylineage.policy.engine import PolicyDecision, configured_policy_version
from paylineage.policy.input_builder import FieldFacts, build_payment_input, current_mandate
from paylineage.policy.record import decide
from paylineage.signals.detect import tool_poisoning_signal

PROPOSAL_TTL = timedelta(days=7)


@dataclass(frozen=True)
class Proposal:
    """What an agent asks for. Everything here is untrusted (agents may be fully manipulated)."""

    invoice_id: str
    supplier_id: str | None
    amount_minor: int
    currency: str
    beneficiary_account: str
    idempotency_key: str
    operation: str = "propose_payment"
    # Descriptions of the tools the agent used. Untrusted: scanned for steering, never obeyed.
    tool_descriptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationResult:
    payment: Payment
    decision: PolicyDecision
    fields: list[FieldFacts]


def _move(p: Payment, event: PayEvent) -> None:
    try:
        p.state = next_state(PaymentState(p.state), event).value
    except IllegalPaymentTransitionError as exc:
        raise ConflictError("ILLEGAL_TRANSITION", str(exc)) from exc


def lock_payment(ctx: Ctx, payment_id: str) -> Payment:
    p = ctx.session.execute(
        select(Payment).where(Payment.id == payment_id).with_for_update()
    ).scalar_one_or_none()
    if p is None:
        raise NotFoundError("NOT_FOUND", "payment not found")
    return p


def _resolve_beneficiary(ctx: Ctx, supplier_id: str | None, token: str) -> str | None:
    """Map the proposed account to a master account id. Never creates one (I1)."""
    if supplier_id is None:
        return None
    acct = ctx.session.execute(
        select(SupplierBankAccount).where(
            SupplierBankAccount.supplier_id == supplier_id, SupplierBankAccount.account_token == token
        )
    ).scalar_one_or_none()
    return acct.id if acct else None


def _refresh_record(ctx: Ctx, p: Payment) -> None:
    p.policy_version = _policy_version(ctx)
    p.policy_sha256 = ctx.engine.sha256
    p.digest = compute_digest(p)


def _policy_version(_ctx: Ctx) -> str:
    return configured_policy_version()


def _exposure(decision: PolicyDecision, amount: int) -> int:
    return amount if decision.decision != "allow" else 0


def _snapshot(
    decision: PolicyDecision, fields: list[FieldFacts], stage: str, operation: str = "propose_payment"
) -> dict[str, Any]:
    # The operation the agent requested is part of the evidence: replaying the
    # decision needs it (found by the demo replay check for S8).
    return {
        **decision.as_dict(),
        "stage": stage,
        "requested_operation": operation,
        "fields": [f.as_view() for f in fields],
    }


def propose(ctx: Ctx, agent: Actor, prop: Proposal, *, signature_valid: bool) -> EvaluationResult:
    """Create (or idempotently return) a proposal, then evaluate it."""
    existing = ctx.session.execute(
        select(Payment).where(Payment.agent_id == agent.id, Payment.idempotency_key == prop.idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        return EvaluationResult(existing, _decision_from_snapshot(existing), [])
    inv = ctx.session.get(Invoice, prop.invoice_id)
    if inv is None:
        raise NotFoundError("NOT_FOUND", "invoice not found")
    now = ctx.now()
    token = account_token(prop.beneficiary_account)
    m = current_mandate(ctx.session, agent.id)
    p = Payment(
        # Every hashed field is set here, not by a flush-time column default (regression I3).
        id=new_id(),
        version=1,
        operation="pay_invoice",
        state=PaymentState.PROPOSED.value,
        amount_minor=prop.amount_minor,
        currency=prop.currency,
        supplier_id=prop.supplier_id,
        beneficiary_account_id=_resolve_beneficiary(ctx, prop.supplier_id, token),
        proposed_account_token=token,
        invoice_id=inv.id,
        invoice_digest=inv.invoice_digest,
        agent_id=agent.id,
        mandate_version=m.version if m else 1,
        policy_version="",
        policy_sha256="",
        nonce=secrets.token_hex(16),
        expires_at=now + PROPOSAL_TTL,
        digest="",
        requested_by=agent.id,
        idempotency_key=prop.idempotency_key,
        overrides={},
        created_at=now,
        updated_at=now,
    )
    _refresh_record(ctx, p)
    ctx.session.add(p)
    ctx.session.flush()
    for hit in tool_poisoning_signal(list(prop.tool_descriptions)):
        ctx.session.add(Signal(invoice_id=inv.id, code=hit.code, severity=hit.severity, detail=hit.detail))
    append(
        ctx.session,
        actor=agent.id,
        kind="payment.proposed",
        subject_id=p.id,
        payload={
            "invoice_id": inv.id,
            "amount_minor": p.amount_minor,
            "currency": p.currency,
            "supplier_id": p.supplier_id,
            "account": mask_account(prop.beneficiary_account),
            "account_token": token,
            "operation": prop.operation,
        },
        now=now,
    )
    return evaluate(ctx, p, agent, operation=prop.operation, signature_valid=signature_valid)


def _decision_from_snapshot(p: Payment) -> PolicyDecision:
    snap = p.last_decision or {}
    return PolicyDecision(
        snap.get("decision", "deny"),
        tuple(snap.get("reasons", ["POLICY_UNDEFINED"])),
        snap.get("policy_version", "unknown"),
        snap.get("policy_sha256", ""),
        snap.get("runtime", "unavailable"),
    )


def evaluate(
    ctx: Ctx,
    p: Payment,
    actor: Actor,
    *,
    operation: str = "propose_payment",
    signature_valid: bool | None = None,
) -> EvaluationResult:
    """Proposed or Evaluated -> Denied | Held | AwaitingApproval."""
    if p.state == PaymentState.PROPOSED.value:
        _move(p, PayEvent.EVALUATE)
    if p.state != PaymentState.EVALUATED.value:
        raise ConflictError("ILLEGAL_TRANSITION", f"cannot evaluate from {p.state}")
    changes = supplier_changes_for(ctx, p.supplier_id) if p.supplier_id else []
    pin, fields = build_payment_input(
        ctx.session,
        p,
        stage="evaluate",
        now=ctx.now(),
        operation=operation,
        signature_valid=signature_valid,
        supplier_changes=changes,
    )
    d = decide(ctx, pin, actor=actor, stage="evaluate", payment_id=p.id, payment_version=p.version)
    _move(p, {"allow": PayEvent.READY, "hold": PayEvent.HOLD, "deny": PayEvent.DENY}[d.decision])
    p.last_decision = _snapshot(d, fields, "evaluate", operation)
    p.exposure_minor = _exposure(d, p.amount_minor)
    p.updated_at = ctx.now()
    append(
        ctx.session,
        actor=actor.id,
        kind=f"payment.{p.state}",
        subject_id=p.id,
        payload={"version": p.version, "reasons": list(d.reasons)},
        now=ctx.now(),
    )
    ctx.session.flush()
    return EvaluationResult(p, d, fields)


def recheck(ctx: Ctx, payment_id: str, actor: Actor) -> EvaluationResult:
    """Held -> AwaitingApproval once out of band verification has happened (or stays Held)."""
    p = lock_payment(ctx, payment_id)
    if p.state != PaymentState.HELD.value:
        raise ConflictError("ILLEGAL_TRANSITION", "only held payments are rechecked")
    changes = supplier_changes_for(ctx, p.supplier_id) if p.supplier_id else []
    pin, fields = build_payment_input(
        ctx.session, p, stage="evaluate", now=ctx.now(), supplier_changes=changes
    )
    d = decide(ctx, pin, actor=actor, stage="recheck", payment_id=p.id, payment_version=p.version)
    if d.decision == "allow":
        _move(p, PayEvent.READY)
    elif d.decision == "deny":
        _move(p, PayEvent.DENY)
    p.last_decision = _snapshot(d, fields, "recheck")
    p.exposure_minor = _exposure(d, p.amount_minor)
    p.updated_at = ctx.now()
    append(
        ctx.session,
        actor=actor.id,
        kind="payment.rechecked",
        subject_id=p.id,
        payload={"state": p.state, "reasons": list(d.reasons)},
        now=ctx.now(),
    )
    ctx.session.flush()
    return EvaluationResult(p, d, fields)


def clear_hold(ctx: Ctx, payment_id: str, analyst: Actor, code: str, note: str) -> EvaluationResult:
    """An analyst clears a clearable hold after out of band review. They then cannot approve (I7)."""
    if not (analyst.has("analyst") or analyst.has("steward")):
        raise ForbiddenError("ROLE_REQUIRED", "only analysts or stewards clear holds")
    if code_class(code) != "hold":
        raise ConflictError("INPUT_INVALID", "only hold codes can be cleared")
    p = lock_payment(ctx, payment_id)
    if analyst.id == p.requested_by:
        raise ForbiddenError("SOD_VIOLATION", "the requester cannot clear their own hold")
    ctx.session.add(
        HoldClearance(
            payment_id=p.id, code=code, cleared_by=analyst.id, note=note[:1000], created_at=ctx.now()
        )
    )
    append(
        ctx.session,
        actor=analyst.id,
        kind="payment.hold_cleared",
        subject_id=p.id,
        payload={"code": code, "note_len": len(note)},
        now=ctx.now(),
    )
    ctx.session.flush()
    return recheck(ctx, payment_id, analyst)


def deny_held(ctx: Ctx, payment_id: str, actor: Actor, reason: str) -> Payment:
    """Held -> Denied: verification failed or case closed as fraud."""
    if not (actor.has("analyst") or actor.has("steward")):
        raise ForbiddenError("ROLE_REQUIRED", "only analysts or stewards close a held payment")
    p = lock_payment(ctx, payment_id)
    _move(p, PayEvent.DENY)
    p.exposure_minor = 0
    p.updated_at = ctx.now()
    append(
        ctx.session,
        actor=actor.id,
        kind="payment.denied",
        subject_id=p.id,
        payload={"reason": reason[:300]},
        now=ctx.now(),
    )
    return p


@dataclass(frozen=True)
class MaterialChange:
    amount_minor: int | None = None
    beneficiary_account: str | None = None
    supplier_id: str | None = None
    currency: str | None = None


def material_change(ctx: Ctx, payment_id: str, actor: Actor, change: MaterialChange) -> EvaluationResult:
    """AwaitingApproval or Approved -> Evaluated, version += 1, every old approval void (S10)."""
    if not actor.has("ap_specialist"):
        raise ForbiddenError("ROLE_REQUIRED", "only AP specialists edit payments")
    p = lock_payment(ctx, payment_id)
    _move(p, PayEvent.MATERIAL_CHANGE)
    now = ctx.now()
    changed: dict[str, Any] = {}
    overrides = dict(p.overrides or {})
    if change.amount_minor is not None and change.amount_minor != p.amount_minor:
        p.amount_minor = change.amount_minor
        overrides["amount"] = {"by": actor.id, "at": now.isoformat()}
        changed["amount_minor"] = change.amount_minor
    if change.currency is not None and change.currency != p.currency:
        p.currency = change.currency
        overrides["currency"] = {"by": actor.id, "at": now.isoformat()}
        changed["currency"] = change.currency
    if change.supplier_id is not None and change.supplier_id != p.supplier_id:
        if ctx.session.get(Supplier, change.supplier_id) is None:
            raise NotFoundError("NOT_FOUND", "supplier not found")
        p.supplier_id = change.supplier_id
        changed["supplier_id"] = change.supplier_id
    if change.beneficiary_account is not None:
        token = account_token(change.beneficiary_account)
        if token != p.proposed_account_token:
            p.proposed_account_token = token
            changed["account"] = mask_account(change.beneficiary_account)
    # Beneficiary always re-resolved against the master; never typed in as trusted.
    p.beneficiary_account_id = _resolve_beneficiary(ctx, p.supplier_id, p.proposed_account_token)
    p.overrides = overrides
    p.version += 1
    p.nonce = secrets.token_hex(16)
    _refresh_record(ctx, p)
    p.updated_at = now
    append(
        ctx.session,
        actor=actor.id,
        kind="payment.material_change",
        subject_id=p.id,
        payload={"new_version": p.version, "changed": changed, "approvals_voided": True},
        now=now,
    )
    ctx.session.flush()
    return evaluate(ctx, p, actor)


def expire_if_stale(ctx: Ctx, p: Payment) -> bool:
    """Approved -> Expired when every approval of the current version is past expiry."""
    from paylineage.db.models import Approval

    if p.state != PaymentState.APPROVED.value:
        return False
    rows = (
        ctx.session.execute(
            select(Approval).where(
                Approval.payment_id == p.id,
                Approval.payment_version == p.version,
                Approval.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    if rows and all(a.expires_at <= ctx.now() for a in rows):
        _move(p, PayEvent.EXPIRE)
        p.exposure_minor = 0
        p.updated_at = ctx.now()
        append(
            ctx.session,
            actor="system",
            kind="payment.expired",
            subject_id=p.id,
            payload={"version": p.version},
            now=ctx.now(),
        )
        return True
    return False


def ensure_digest_matches(p: Payment) -> str:
    """Return the recomputed digest; the stored one is a cache, never trusted."""
    return compute_digest(p)
