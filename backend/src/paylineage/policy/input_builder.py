"""Build policy input for a payment from the authoritative store only (rule 4, I9).

Nothing here is taken from a request body. Trust class is recomputed from the
source kind, master matches are recomputed against the current supplier master,
approvals and permits are read back from PostgreSQL. Every stage (evaluate,
permit, execute) rebuilds from scratch, which is what makes revalidation (I4) work.

Field provenance for a payment compares what the agent proposed with what was
extracted from the invoice. A proposed value that matches an extracted value
inherits that field's source. A value with no document or master source is
`agent_asserted` (ADR-011).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from paylineage.db.models import (
    Agent,
    Approval,
    ExtractedField,
    HoldClearance,
    Invoice,
    Mandate,
    Payment,
    Permit,
    PurchaseOrder,
    Signal,
    Supplier,
    SupplierBankAccount,
    User,
)
from paylineage.db.vault import value_token
from paylineage.domain.clock import to_ms
from paylineage.domain.enums import (
    AccountStatus,
    Consistency,
    FieldName,
    PaymentState,
    SourceKind,
    SupplierStatus,
    trust_for,
)
from paylineage.payments.record import compute_digest

Stage = Literal["evaluate", "permit", "execute"]


def current_mandate(session: Session, agent_id: str) -> Mandate | None:
    return session.execute(
        select(Mandate).where(Mandate.agent_id == agent_id).order_by(Mandate.version.desc()).limit(1)
    ).scalar_one_or_none()


def mandate_input(m: Mandate | None, now: datetime) -> dict[str, Any] | None:
    if m is None:
        return None
    return {
        "mandate_id": m.id,
        "version": m.version,
        "agent_id": m.agent_id,
        "permitted_operations": list(m.permitted_operations),
        "forbidden_operations": list(m.forbidden_operations),
        "supplier_scope": list(m.supplier_scope),
        "per_proposal_ceiling_minor": m.per_proposal_ceiling_minor,
        "daily_ceiling_minor": m.daily_ceiling_minor,
        "approver_role": m.approver_role,
        "second_approver_above_minor": m.second_approver_above_minor,
        "not_before_ms": to_ms(m.not_before),
        "expires_at_ms": to_ms(m.expires_at),
        "revoked": m.revoked_at is not None and m.revoked_at <= now,
    }


def amount_token(amount_minor: int) -> str:
    return value_token("amount", str(amount_minor))


def text_token(kind: str, raw: str) -> str:
    return value_token(kind, " ".join(raw.split()).casefold())


@dataclass(frozen=True)
class FieldFacts:
    name: FieldName
    source_kind: SourceKind
    consistency: Consistency
    master_matched: bool
    note: str

    def as_input(self) -> dict[str, Any]:
        return {
            "field_name": self.name.value,
            "source_kind": self.source_kind.value,
            "trust_class": trust_for(self.source_kind).value,  # recomputed, never stored trust
            "consistency": self.consistency.value,
            "master_matched": self.master_matched,
        }

    def as_view(self) -> dict[str, Any]:
        return {**self.as_input(), "note": self.note}


def _extracted(session: Session, invoice_id: str) -> dict[str, ExtractedField]:
    rows = session.execute(select(ExtractedField).where(ExtractedField.invoice_id == invoice_id)).scalars()
    return {r.field_name: r for r in rows}


def payment_fields(session: Session, p: Payment, inv: Invoice) -> list[FieldFacts]:
    ex = _extracted(session, inv.id)
    overrides: dict[str, Any] = p.overrides or {}
    supplier = session.get(Supplier, p.supplier_id) if p.supplier_id else None
    po = None
    if inv.po_number and p.supplier_id:
        po = session.execute(
            select(PurchaseOrder).where(
                PurchaseOrder.po_number == inv.po_number, PurchaseOrder.supplier_id == p.supplier_id
            )
        ).scalar_one_or_none()
    out: list[FieldFacts] = []

    def from_doc(name: FieldName, proposed_token: str) -> tuple[SourceKind, Consistency, str]:
        row = ex.get(name.value)
        if name.value in overrides:
            return (
                SourceKind.USER_ENTERED,
                Consistency.CONSISTENT,
                f"entered by {overrides[name.value]['by']}",
            )
        if row is None:
            return SourceKind.AGENT_ASSERTED, Consistency.UNCHECKED, "not found in any document"
        if row.value_token != proposed_token:
            return (
                SourceKind.AGENT_ASSERTED,
                Consistency.UNCHECKED,
                "proposed value differs from the document",
            )
        return SourceKind(row.source_kind), Consistency(row.consistency), "matches the document"

    # amount: trusted only when it matches the purchase order (a user_entered record)
    src, cons, note = from_doc(FieldName.AMOUNT, amount_token(p.amount_minor))
    matched = po is not None and po.amount_minor == p.amount_minor and po.currency == p.currency
    out.append(
        FieldFacts(
            FieldName.AMOUNT, src, cons, matched, note + ("; matches PO" if matched else "; no matching PO")
        )
    )

    src, cons, note = from_doc(FieldName.CURRENCY, text_token("currency", p.currency))
    matched = po is not None and po.currency == p.currency
    out.append(FieldFacts(FieldName.CURRENCY, src, cons, matched, note))

    src, cons, note = from_doc(FieldName.BENEFICIARY_ACCOUNT, p.proposed_account_token)
    verified_tokens = set()
    if p.supplier_id:
        verified_tokens = set(
            session.execute(
                select(SupplierBankAccount.account_token).where(
                    SupplierBankAccount.supplier_id == p.supplier_id,
                    SupplierBankAccount.status == AccountStatus.VERIFIED.value,
                )
            ).scalars()
        )
    matched = p.proposed_account_token in verified_tokens
    out.append(
        FieldFacts(
            FieldName.BENEFICIARY_ACCOUNT,
            src,
            cons,
            matched,
            note + ("; matches verified master account" if matched else "; not a verified account"),
        )
    )

    name_row = ex.get(FieldName.SUPPLIER_NAME.value)
    if name_row is None:
        src, cons, note = SourceKind.AGENT_ASSERTED, Consistency.UNCHECKED, "no supplier name in documents"
    else:
        src, cons, note = (
            SourceKind(name_row.source_kind),
            Consistency(name_row.consistency),
            "from the document",
        )
    matched = (
        supplier is not None
        and supplier.status == SupplierStatus.VERIFIED.value
        and inv.supplier_id == p.supplier_id
        and name_row is not None
        and name_row.value_token == text_token("supplier_name", supplier.legal_name)
    )
    if p.supplier_id is not None and inv.supplier_id != p.supplier_id:
        src, cons, note = SourceKind.AGENT_ASSERTED, Consistency.UNCHECKED, "agent named a different supplier"
        matched = False
    out.append(FieldFacts(FieldName.SUPPLIER_NAME, src, cons, matched, note))

    # The material invoice reference is the invoice record id the system assigned at ingestion.
    out.append(
        FieldFacts(
            FieldName.INVOICE_NUMBER, SourceKind.SYSTEM, Consistency.CONSISTENT, True, "system invoice record"
        )
    )
    return out


def daily_total(session: Session, p: Payment, now: datetime) -> int:
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total = session.execute(
        select(func.coalesce(func.sum(Payment.amount_minor), 0)).where(
            Payment.agent_id == p.agent_id,
            Payment.id != p.id,
            Payment.created_at >= start,
            Payment.created_at < start + timedelta(days=1),
            Payment.state.notin_([PaymentState.DENIED.value, PaymentState.EXPIRED.value]),
        )
    ).scalar_one()
    return int(total)


def build_payment_input(
    session: Session,
    p: Payment,
    *,
    stage: Stage,
    now: datetime,
    operation: str = "propose_payment",
    signature_valid: bool | None = None,
    permit: Permit | None = None,
    extra_approval: dict[str, Any] | None = None,
    supplier_changes: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[FieldFacts]]:
    inv = session.get(Invoice, p.invoice_id)
    if inv is None:
        raise LookupError("invoice missing")
    agent = session.get(Agent, p.agent_id)
    if signature_valid is None:
        # After proposal, the agent must still exist and be active for the request to stand.
        signature_valid = agent is not None and agent.active
    m = current_mandate(session, p.agent_id)
    supplier = session.get(Supplier, p.supplier_id) if p.supplier_id else None
    acct = session.get(SupplierBankAccount, p.beneficiary_account_id) if p.beneficiary_account_id else None
    has_verified = False
    if supplier is not None:
        has_verified = (
            session.execute(
                select(func.count())
                .select_from(SupplierBankAccount)
                .where(
                    SupplierBankAccount.supplier_id == supplier.id,
                    SupplierBankAccount.status == AccountStatus.VERIFIED.value,
                )
            ).scalar_one()
            > 0
        )
    fields = payment_fields(session, p, inv)
    signals = session.execute(select(Signal).where(Signal.invoice_id == inv.id)).scalars().all()
    clearances = (
        session.execute(select(HoldClearance).where(HoldClearance.payment_id == p.id)).scalars().all()
    )

    approvals: list[dict[str, Any]] = []
    if stage in ("permit", "execute") or extra_approval is not None:
        rows = (
            session.execute(
                select(Approval).where(Approval.payment_id == p.id, Approval.payment_version == p.version)
            )
            .scalars()
            .all()
        )
        for a in rows:
            u = session.get(User, a.approver_id)
            approvals.append(
                {
                    "approval_id": a.id,
                    "approver_id": a.approver_id,
                    "digest": a.digest,
                    "payment_version": a.payment_version,
                    "expires_at_ms": to_ms(a.expires_at),
                    "revoked": a.revoked_at is not None,
                    "approver_active": bool(u and u.active),
                    "approver_roles": sorted(u.roles) if u else [],
                }
            )
        if extra_approval is not None:
            approvals.append(extra_approval)

    digest_now = compute_digest(p)
    policy_input: dict[str, Any] = {
        "schema_version": "1",
        "request_kind": "payment",
        "now_ms": to_ms(now),
        "payment": {
            "stage": stage,
            "operation": operation,
            "agent": {"agent_id": p.agent_id, "signature_valid": bool(signature_valid)},
            "mandate": mandate_input(m, now),
            "record": {
                "payment_id": p.id,
                "version": p.version,
                "amount_minor": p.amount_minor,
                "currency": p.currency,
                "supplier_id": p.supplier_id,
                "beneficiary_account_id": p.beneficiary_account_id,
                "invoice_id": p.invoice_id,
                "mandate_version": p.mandate_version,
                "policy_version": p.policy_version,
                "digest": digest_now,
            },
            "requested_by": p.requested_by if p.requested_by != p.agent_id else None,
            "daily_total_minor": daily_total(session, p, now),
            "fields": [f.as_input() for f in fields],
            "supplier": None
            if supplier is None
            else {
                "supplier_id": supplier.id,
                "status": supplier.status,
                "has_verified_account": has_verified,
            },
            "beneficiary": None
            if acct is None
            else {
                "account_id": acct.id,
                "supplier_id": acct.supplier_id,
                "status": acct.status,
                "cooling_off_until_ms": to_ms(acct.cooling_off_until) if acct.cooling_off_until else None,
            },
            "duplicate_invoice": inv.duplicate_of is not None,
            "signals": [{"code": s.code, "severity": s.severity} for s in signals][:64],
            "hold_clearances": [
                {"code": c.code, "cleared_by": c.cleared_by, "at_ms": to_ms(c.created_at)} for c in clearances
            ][:32],
            "supplier_changes": supplier_changes or [],
            "approvals": approvals[:8],
            "permit": None
            if permit is None
            else {
                "permit_id": permit.id,
                "digest": permit.digest,
                "expires_at_ms": to_ms(permit.expires_at),
                "consumed": permit.consumed_at is not None,
            },
        },
    }
    return policy_input, fields
