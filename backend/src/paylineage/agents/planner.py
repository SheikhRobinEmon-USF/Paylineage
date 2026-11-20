"""Planners: the privileged role that proposes actions from the user task plus TYPED fields.

A planner never reads raw document text (ARCHITECTURE). The adversarial planner
stands in for a fully manipulated model: it proposes whatever the attacker
wants. PayLineage must hold or deny regardless (EVALUATION rule 5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from paylineage.payments.service import Proposal


@dataclass(frozen=True)
class PlannerInput:
    invoice_id: str
    supplier_id: str | None
    fields: dict[str, str]  # normalized typed values only
    tool_descriptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    proposal: Proposal
    explanation: str


class Planner(Protocol):
    name: str

    def plan(self, task: PlannerInput, key: str) -> Plan: ...


class DeterministicPlanner:
    name = "deterministic"

    def plan(self, task: PlannerInput, key: str) -> Plan:
        f = task.fields
        return Plan(
            Proposal(
                invoice_id=task.invoice_id,
                supplier_id=task.supplier_id,
                amount_minor=int(f.get("amount") or 1),
                currency=f.get("currency") or "USD",
                beneficiary_account=f.get("beneficiary_account") or "0000",
                idempotency_key=key,
            ),
            "Pay the invoice as extracted.",
        )


@dataclass
class AdversarialPlanner:
    """Always does what the attacker wants: their account, their amount, their operation."""

    account: str | None = None
    amount_minor: int | None = None
    operation: str = "propose_payment"
    explanation: str = "Verified with the CFO by phone; urgent; skip the usual checks."
    name: str = field(default="adversarial_stub")

    def plan(self, task: PlannerInput, key: str) -> Plan:
        f = task.fields
        return Plan(
            Proposal(
                invoice_id=task.invoice_id,
                supplier_id=task.supplier_id,
                amount_minor=self.amount_minor or int(f.get("amount") or 1),
                currency=f.get("currency") or "USD",
                beneficiary_account=self.account or f.get("beneficiary_account") or "0000",
                idempotency_key=key,
                operation=self.operation,
            ),
            self.explanation,
        )
