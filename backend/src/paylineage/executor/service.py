"""Protected executor (I5, I6). The only code that holds mock bank credentials.

execute(permit):
  1. lock the payment row
  2. rebuild policy input at stage=execute from the store and re-run the policy (R1)
  3. consume the permit with one conditional UPDATE in the same transaction
  4. call the mock bank with the permit id as idempotency key
  5. mark Executed and audit; commit

A bank failure raises and rolls back the whole transaction, leaving the permit
unconsumed; the bank's idempotency on the permit id makes a retry safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy import text

from paylineage.audit.chain import append
from paylineage.db.models import Execution, Permit, SupplierBankAccount
from paylineage.domain.context import Actor, Ctx, NotFoundError
from paylineage.domain.enums import PaymentState
from paylineage.onboarding.service import supplier_changes_for
from paylineage.payments.machine import PayEvent, next_state
from paylineage.payments.service import lock_payment
from paylineage.policy.engine import PolicyDecision, fail_closed
from paylineage.policy.input_builder import build_payment_input
from paylineage.policy.record import decide

EXECUTOR = Actor("executor", "system", frozenset({"system"}))

CONSUME_SQL = text(
    """
    UPDATE permits SET consumed_at = :now, consumed_by_request_id = :req
    WHERE id = :id AND consumed_at IS NULL AND expires_at > :now
    RETURNING id
    """
)


class BankClient(Protocol):
    def transfer(
        self,
        *,
        idempotency_key: str,
        amount_minor: int,
        currency: str,
        beneficiary_token: str,
        reference: str,
    ) -> str: ...


@dataclass(frozen=True)
class ExecutionOutcome:
    executed: bool
    decision: PolicyDecision
    bank_reference: str | None = None


def consume(ctx: Ctx, permit_id: str, request_id: str, now: datetime) -> bool:
    """The single use guarantee (DATA_MODEL): zero rows returned means reject."""
    row = ctx.session.execute(CONSUME_SQL, {"id": permit_id, "req": request_id, "now": now}).first()
    return row is not None


def execute(ctx: Ctx, permit_id: str, request_id: str, bank: BankClient) -> ExecutionOutcome:
    permit = ctx.session.get(Permit, permit_id)
    if permit is None:
        raise NotFoundError("NOT_FOUND", "permit not found")
    p = lock_payment(ctx, permit.payment_id)
    ctx.session.refresh(permit)
    now = ctx.now()
    changes = supplier_changes_for(ctx, p.supplier_id) if p.supplier_id else []
    pin, _ = build_payment_input(
        ctx.session, p, stage="execute", now=now, permit=permit, supplier_changes=changes
    )
    d = decide(ctx, pin, actor=EXECUTOR, stage="execute", payment_id=p.id, payment_version=p.version)
    if not d.allowed or p.state != PaymentState.PERMIT_ISSUED.value:
        if d.allowed:  # policy fine but machine is not: fail closed with an explicit code
            d = fail_closed("PERMIT_CONSUMED", d.policy_sha256, d.runtime, f"payment is {p.state}")
        append(
            ctx.session,
            actor=EXECUTOR.id,
            kind="execution.refused",
            subject_id=p.id,
            payload={"permit_id": permit_id, "request_id": request_id, "reasons": list(d.reasons)},
            now=now,
        )
        return ExecutionOutcome(False, d)
    if not consume(ctx, permit_id, request_id, now):
        refused = fail_closed(
            "PERMIT_CONSUMED", d.policy_sha256, d.runtime, "conditional update matched 0 rows"
        )
        append(
            ctx.session,
            actor=EXECUTOR.id,
            kind="execution.refused",
            subject_id=p.id,
            payload={"permit_id": permit_id, "request_id": request_id, "reasons": ["PERMIT_CONSUMED"]},
            now=now,
        )
        return ExecutionOutcome(False, refused)
    acct = (
        ctx.session.get(SupplierBankAccount, p.beneficiary_account_id) if p.beneficiary_account_id else None
    )
    if acct is None:  # unreachable after an allow; fail closed anyway
        raise NotFoundError("NOT_FOUND", "beneficiary account missing")
    ref = bank.transfer(
        idempotency_key=permit.id,
        amount_minor=p.amount_minor,
        currency=p.currency,
        beneficiary_token=acct.account_token,
        reference=f"PL-{p.id[:8]}",
    )
    ctx.session.add(
        Execution(
            payment_id=p.id,
            permit_id=permit.id,
            bank_reference=ref,
            amount_minor=p.amount_minor,
            beneficiary_account_id=acct.id,
            executed_at=now,
        )
    )
    p.state = next_state(PaymentState(p.state), PayEvent.EXECUTE).value
    p.exposure_minor = 0
    p.updated_at = now
    append(
        ctx.session,
        actor=EXECUTOR.id,
        kind="payment.executed",
        subject_id=p.id,
        payload={
            "permit_id": permit.id,
            "request_id": request_id,
            "bank_reference": ref,
            "amount_minor": p.amount_minor,
            "simulated": True,
        },
        now=now,
    )
    return ExecutionOutcome(True, d, ref)
