"""Permit service: a fresh policy run, then a single use, short lived permit (I3, I4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select

from paylineage.audit.chain import append
from paylineage.db.models import Approval, Permit
from paylineage.domain.context import Actor, ConflictError, Ctx
from paylineage.domain.enums import PaymentState
from paylineage.onboarding.service import supplier_changes_for
from paylineage.payments.machine import PayEvent, next_state
from paylineage.payments.record import compute_digest
from paylineage.payments.service import expire_if_stale, lock_payment
from paylineage.policy.engine import PolicyDecision
from paylineage.policy.input_builder import build_payment_input
from paylineage.policy.record import decide

PERMIT_TTL = timedelta(minutes=2)


@dataclass(frozen=True)
class PermitOutcome:
    """permit is None when the policy refused. The refusal is recorded; commit it."""

    permit: Permit | None
    decision: PolicyDecision


def issue_permit(ctx: Ctx, payment_id: str, actor: Actor) -> PermitOutcome:
    """Approved -> PermitIssued, only if the policy allows *now* (R1 revalidation)."""
    p = lock_payment(ctx, payment_id)
    if p.state != PaymentState.APPROVED.value:
        raise ConflictError("ILLEGAL_TRANSITION", f"payment is {p.state}, not approved")
    now = ctx.now()
    changes = supplier_changes_for(ctx, p.supplier_id) if p.supplier_id else []
    pin, _ = build_payment_input(ctx.session, p, stage="permit", now=now, supplier_changes=changes)
    d = decide(ctx, pin, actor=actor, stage="permit", payment_id=p.id, payment_version=p.version)
    if not d.allowed:
        if "APPROVAL_EXPIRED" in d.reasons:
            expire_if_stale(ctx, p)  # Approved -> Expired, committed with the refusal
        append(
            ctx.session,
            actor=actor.id,
            kind="permit.refused",
            subject_id=p.id,
            payload={"reasons": list(d.reasons), "version": p.version},
            now=now,
        )
        return PermitOutcome(None, d)
    approval = (
        ctx.session.execute(
            select(Approval)
            .where(
                Approval.payment_id == p.id,
                Approval.payment_version == p.version,
                Approval.revoked_at.is_(None),
            )
            .order_by(Approval.signed_at.desc())
        )
        .scalars()
        .first()
    )
    if approval is None:  # The policy already required one; this is defence in depth.
        raise ConflictError("APPROVAL_MISSING", "no approval")
    permit = Permit(
        payment_id=p.id,
        approval_id=approval.id,
        digest=compute_digest(p),
        issued_at=now,
        expires_at=now + PERMIT_TTL,
    )
    ctx.session.add(permit)
    p.state = next_state(PaymentState(p.state), PayEvent.ISSUE_PERMIT).value
    p.updated_at = now
    ctx.session.flush()
    append(
        ctx.session,
        actor=actor.id,
        kind="permit.issued",
        subject_id=p.id,
        payload={
            "permit_id": permit.id,
            "digest": permit.digest,
            "expires_at": permit.expires_at.isoformat(),
        },
        now=now,
    )
    return PermitOutcome(permit, d)
