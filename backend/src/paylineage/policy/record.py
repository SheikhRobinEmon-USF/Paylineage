"""Evaluate the policy and persist the decision with an audit event, in one call."""

from __future__ import annotations

from typing import Any

from paylineage.audit.chain import append
from paylineage.canonical import digest
from paylineage.db.models import PolicyDecisionRow
from paylineage.domain.context import Actor, Ctx
from paylineage.policy.engine import PolicyDecision


def decide(
    ctx: Ctx,
    policy_input: dict[str, Any],
    *,
    actor: Actor,
    stage: str,
    payment_id: str | None = None,
    payment_version: int | None = None,
    subject_id: str | None = None,
) -> PolicyDecision:
    d = ctx.engine.evaluate(policy_input)
    try:
        input_digest = digest(policy_input)
    except ValueError:
        input_digest = "0" * 64
    now = ctx.now()
    ctx.session.add(
        PolicyDecisionRow(
            payment_id=payment_id,
            subject_id=subject_id,
            payment_version=payment_version,
            stage=stage,
            decision=d.decision,
            reasons=list(d.reasons),
            policy_version=d.policy_version,
            policy_sha256=d.policy_sha256,
            runtime=d.runtime,
            input_digest=input_digest,
            latency_us=d.latency_us,
            created_at=now,
        )
    )
    append(
        ctx.session,
        actor=actor.id,
        kind=f"policy.{stage}",
        subject_id=payment_id or subject_id,
        payload={**d.as_dict(), "input_digest": input_digest, "payment_version": payment_version},
        now=now,
    )
    return d
