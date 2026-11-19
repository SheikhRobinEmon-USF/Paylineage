"""Approval service: passkey assertion over a server challenge bound to the digest (I3, I7).

The approver's identity comes from the credential that signed, never from the
client. The digest comes from the server's own recomputation, never from the
client. Before an approval is stored, the permit-stage policy runs with the
prospective approval included, so SoD and role failures refuse the approval.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from paylineage.approvals.webauthn import (
    IssuedChallenge,
    approval_challenge_bytes,
    begin_assertion,
    finish_assertion,
)
from paylineage.audit.chain import append
from paylineage.db.models import Approval, Payment, User
from paylineage.domain.clock import to_ms
from paylineage.domain.context import Actor, ConflictError, Ctx, ForbiddenError, NotFoundError
from paylineage.domain.enums import PaymentState
from paylineage.domain.ids import new_id
from paylineage.onboarding.service import supplier_changes_for
from paylineage.payments.machine import PayEvent, next_state
from paylineage.payments.record import compute_digest
from paylineage.payments.service import lock_payment
from paylineage.policy.engine import PolicyDecision
from paylineage.policy.input_builder import build_payment_input
from paylineage.policy.record import decide
from paylineage.settings import Settings

APPROVAL_TTL = timedelta(minutes=15)


def actor_for(user: User) -> Actor:
    return Actor(user.id, "user", frozenset(user.roles), user.active)


def begin_approval(
    ctx: Ctx, payment_id: str, approver: User, settings: Settings | None = None
) -> IssuedChallenge:
    p = ctx.session.get(Payment, payment_id)
    if p is None:
        raise NotFoundError("NOT_FOUND", "payment not found")
    if p.state != PaymentState.AWAITING_APPROVAL.value:
        raise ConflictError("ILLEGAL_TRANSITION", f"payment is {p.state}, not awaiting approval")
    digest = compute_digest(p)
    challenge_id = new_id()
    nonce = secrets.token_hex(16)
    challenge = approval_challenge_bytes(
        payment_id=p.id, version=p.version, digest=digest, challenge_id=challenge_id, nonce=nonce
    )
    return begin_assertion(
        ctx,
        purpose="approve",
        challenge=challenge,
        user_id=approver.id,
        nonce=nonce,
        payment=(p.id, p.version, digest),
        settings=settings,
        challenge_id=challenge_id,
    )


@dataclass(frozen=True)
class ApprovalOutcome:
    """approval is None when the policy refused. The refusal and spent challenge are recorded."""

    approval: Approval | None
    payment: Payment
    decision: PolicyDecision


def finish_approval(
    ctx: Ctx, challenge_id: str, credential: dict[str, Any] | str, settings: Settings | None = None
) -> ApprovalOutcome:
    verified = finish_assertion(ctx, challenge_id, "approve", credential, settings)
    ch = verified.challenge
    if ch.payment_id is None or ch.payment_version is None or ch.digest is None:
        raise ForbiddenError("CHALLENGE_INVALID", "not an approval challenge")
    # The challenge commits to these values; recompute to prove nothing was swapped.
    expected = approval_challenge_bytes(
        payment_id=ch.payment_id,
        version=ch.payment_version,
        digest=ch.digest,
        challenge_id=ch.id,
        nonce=ch.nonce,
    )
    if expected != ch.challenge:
        raise ForbiddenError("APPROVAL_DIGEST_MISMATCH", "challenge commitment broken")
    p = lock_payment(ctx, ch.payment_id)
    if p.state != PaymentState.AWAITING_APPROVAL.value:
        raise ConflictError("ILLEGAL_TRANSITION", f"payment is {p.state}")
    if p.version != ch.payment_version or compute_digest(p) != ch.digest:
        raise ConflictError("APPROVAL_DIGEST_MISMATCH", "record changed after the challenge was issued")
    approver = verified.user
    now = ctx.now()
    prospective = {
        "approval_id": "prospective",
        "approver_id": approver.id,
        "digest": ch.digest,
        "payment_version": ch.payment_version,
        "expires_at_ms": to_ms(now + APPROVAL_TTL),
        "revoked": False,
        "approver_active": approver.active,
        "approver_roles": sorted(approver.roles),
    }
    changes = supplier_changes_for(ctx, p.supplier_id) if p.supplier_id else []
    pin, _ = build_payment_input(
        ctx.session, p, stage="permit", now=now, extra_approval=prospective, supplier_changes=changes
    )
    actor = actor_for(approver)
    d = decide(ctx, pin, actor=actor, stage="approve", payment_id=p.id, payment_version=p.version)
    if d.decision == "deny" or (d.decision == "hold" and set(d.reasons) != {"SECOND_APPROVAL_REQUIRED"}):
        append(
            ctx.session,
            actor=approver.id,
            kind="payment.approval_refused",
            subject_id=p.id,
            payload={"reasons": list(d.reasons), "version": p.version},
            now=now,
        )
        return ApprovalOutcome(None, p, d)
    a = Approval(
        payment_id=p.id,
        payment_version=p.version,
        digest=ch.digest,
        approver_id=approver.id,
        webauthn_credential_id=verified.credential_id,
        challenge_id=ch.id,
        signed_at=now,
        expires_at=now + APPROVAL_TTL,
    )
    ctx.session.add(a)
    ctx.session.flush()
    if d.decision == "allow":
        p.state = next_state(PaymentState(p.state), PayEvent.APPROVE).value
    p.updated_at = now
    append(
        ctx.session,
        actor=approver.id,
        kind="payment.approved" if d.decision == "allow" else "payment.approval_added",
        subject_id=p.id,
        payload={
            "approval_id": a.id,
            "version": p.version,
            "digest": ch.digest,
            "credential": verified.credential_id[:16],
        },
        now=now,
    )
    return ApprovalOutcome(a, p, d)


def revoke_approval(ctx: Ctx, approval_id: str, actor: Actor, reason: str) -> Approval:
    a = ctx.session.get(Approval, approval_id)
    if a is None:
        raise NotFoundError("NOT_FOUND", "approval not found")
    if actor.id != a.approver_id and not actor.has("admin"):
        raise ForbiddenError("ROLE_REQUIRED", "only the approver or an admin revokes an approval")
    if a.revoked_at is None:
        a.revoked_at = ctx.now()
        append(
            ctx.session,
            actor=actor.id,
            kind="payment.approval_revoked",
            subject_id=a.payment_id,
            payload={"approval_id": a.id, "reason": reason[:300]},
            now=ctx.now(),
        )
    return a
