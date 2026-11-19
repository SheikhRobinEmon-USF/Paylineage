"""Read models for the UI. Account numbers appear masked; document text is returned as data."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from paylineage.db.models import (
    Agent,
    Approval,
    AuditEvent,
    Document,
    Execution,
    ExtractedField,
    Invoice,
    Mandate,
    OnboardingRequest,
    Payment,
    Permit,
    PolicyDecisionRow,
    Signal,
    Supplier,
    SupplierBankAccount,
    User,
)
from paylineage.domain.reason_codes import meanings
from paylineage.payments.record import canonical_record, compute_digest


def _iso(dt: Any) -> str | None:
    return dt.isoformat() if dt is not None else None


def user_name(s: Session, uid: str | None) -> str | None:
    if uid is None:
        return None
    u = s.get(User, uid)
    return u.display_name if u else uid


def account_view(a: SupplierBankAccount, s: Session) -> dict[str, Any]:
    return {
        "id": a.id,
        "masked": f"•••• {a.last4}",
        "bank_name": a.bank_name,
        "status": a.status,
        "verified_by": user_name(s, a.verified_by),
        "verified_method": a.verified_method,
        "steward_by": user_name(s, a.steward_by),
        "verified_at": _iso(a.verified_at),
        "cooling_off_until": _iso(a.cooling_off_until),
        "reported_compromised_at": _iso(a.reported_compromised_at),
        "token_prefix": a.account_token[:12],
    }


def payment_summary(s: Session, p: Payment) -> dict[str, Any]:
    sup = s.get(Supplier, p.supplier_id) if p.supplier_id else None
    inv = s.get(Invoice, p.invoice_id)
    snap = p.last_decision or {}
    return {
        "id": p.id,
        "state": p.state,
        "version": p.version,
        "amount_minor": p.amount_minor,
        "currency": p.currency,
        "supplier": sup.legal_name if sup else None,
        "supplier_id": p.supplier_id,
        "invoice_number": inv.invoice_number if inv else None,
        "decision": snap.get("decision"),
        "reasons": snap.get("reasons", []),
        "exposure_minor": p.exposure_minor,
        "agent_id": p.agent_id,
        "created_at": _iso(p.created_at),
        "updated_at": _iso(p.updated_at),
        "scenario": inv.scenario_id if inv else None,
    }


def queue(s: Session, state: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    q = select(Payment).order_by(Payment.created_at.desc()).limit(limit)
    if state:
        q = q.where(Payment.state == state)
    return [payment_summary(s, p) for p in s.execute(q).scalars()]


def payment_detail(s: Session, p: Payment) -> dict[str, Any]:
    inv = s.get(Invoice, p.invoice_id)
    assert inv is not None
    doc = s.get(Document, inv.document_id)
    email_doc = s.get(Document, inv.email_document_id) if inv.email_document_id else None
    fields = s.execute(select(ExtractedField).where(ExtractedField.invoice_id == inv.id)).scalars().all()
    signals = s.execute(select(Signal).where(Signal.invoice_id == inv.id)).scalars().all()
    sup = s.get(Supplier, p.supplier_id) if p.supplier_id else None
    accounts = []
    if sup:
        accounts = [
            account_view(a, s)
            for a in s.execute(
                select(SupplierBankAccount).where(SupplierBankAccount.supplier_id == sup.id)
            ).scalars()
        ]
    proposed_acct = s.get(SupplierBankAccount, p.beneficiary_account_id) if p.beneficiary_account_id else None
    decisions = (
        s.execute(
            select(PolicyDecisionRow)
            .where(PolicyDecisionRow.payment_id == p.id)
            .order_by(PolicyDecisionRow.created_at, PolicyDecisionRow.id)
        )
        .scalars()
        .all()
    )
    events = (
        s.execute(
            select(AuditEvent).where(AuditEvent.subject_id.in_([p.id, inv.id])).order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )
    approvals = s.execute(select(Approval).where(Approval.payment_id == p.id)).scalars().all()
    permits = s.execute(select(Permit).where(Permit.payment_id == p.id)).scalars().all()
    execution = s.execute(select(Execution).where(Execution.payment_id == p.id)).scalar_one_or_none()
    m = meanings()
    snap = p.last_decision or {}
    return {
        **payment_summary(s, p),
        "record": canonical_record(p),
        "digest": compute_digest(p),
        "policy_sha256": p.policy_sha256,
        "reason_details": [{"code": r, "meaning": m.get(r, r)} for r in snap.get("reasons", [])],
        "fields": snap.get("fields", []),
        "extracted": [
            {
                "field": f.field_name,
                "display": f.display_value,
                "source_kind": f.source_kind,
                "trust_class": f.trust_class,
                "consistency": f.consistency,
                "page": f.source_ref.get("page"),
                "quote": f.source_ref.get("quote"),
                "span_check": f.source_ref.get("span_check"),
                "extractor": f.extractor,
            }
            for f in fields
        ],
        "signals": [{"code": g.code, "severity": g.severity, "detail": g.detail} for g in signals],
        "document": {
            "filename": doc.filename if doc else None,
            "digest": doc.file_digest if doc else None,
            "pages": doc.pages if doc else [],
            "trust_class": doc.trust_class if doc else None,
        },
        "email": None
        if email_doc is None
        else {
            "transport": email_doc.transport,
            "body": email_doc.text_content[:5000],
            "digest": email_doc.file_digest,
        },
        "supplier": None
        if sup is None
        else {
            "id": sup.id,
            "legal_name": sup.legal_name,
            "status": sup.status,
            "verified_domains": sup.verified_domains,
            "accounts": accounts,
        },
        "proposed_account": account_view(proposed_acct, s)
        if proposed_acct
        else {
            "masked": next(
                (f.display_value for f in fields if f.field_name == "beneficiary_account"), "unknown"
            ),
            "status": "not in supplier master",
        },
        "decisions": [
            {
                "stage": d.stage,
                "decision": d.decision,
                "reasons": d.reasons,
                "runtime": d.runtime,
                "policy_sha256": d.policy_sha256,
                "latency_us": d.latency_us,
                "version": d.payment_version,
                "at": _iso(d.created_at),
            }
            for d in decisions
        ],
        "timeline": [
            {
                "seq": e.seq,
                "kind": e.kind,
                "actor": user_name(s, e.actor) or e.actor,
                "at": _iso(e.created_at),
                "hash": e.hash[:12],
                "payload": e.payload,
            }
            for e in events
        ],
        "approvals": [
            {
                "id": a.id,
                "approver": user_name(s, a.approver_id),
                "version": a.payment_version,
                "digest": a.digest,
                "signed_at": _iso(a.signed_at),
                "expires_at": _iso(a.expires_at),
                "revoked_at": _iso(a.revoked_at),
            }
            for a in approvals
        ],
        "permits": [
            {
                "id": x.id,
                "digest": x.digest,
                "issued_at": _iso(x.issued_at),
                "expires_at": _iso(x.expires_at),
                "consumed_at": _iso(x.consumed_at),
            }
            for x in permits
        ],
        "execution": None
        if execution is None
        else {
            "bank_reference": execution.bank_reference,
            "executed_at": _iso(execution.executed_at),
            "simulated": True,
        },
    }


def supplier_detail(s: Session, sup: Supplier) -> dict[str, Any]:
    reqs = (
        s.execute(
            select(OnboardingRequest)
            .where(OnboardingRequest.supplier_id == sup.id)
            .order_by(OnboardingRequest.created_at.desc())
        )
        .scalars()
        .all()
    )
    events = (
        s.execute(
            select(AuditEvent)
            .where(AuditEvent.subject_id == sup.id, AuditEvent.kind.like("supplier.%"))
            .order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )
    return {
        "id": sup.id,
        "legal_name": sup.legal_name,
        "status": sup.status,
        "verified_domains": sup.verified_domains,
        "registry_id": sup.registry_id,
        "contact_on_file": sup.contact_on_file,
        "contact_recorded_at": _iso(sup.contact_recorded_at),
        "accounts": [
            account_view(a, s)
            for a in s.execute(
                select(SupplierBankAccount).where(SupplierBankAccount.supplier_id == sup.id)
            ).scalars()
        ],
        "requests": [
            {
                "id": r.id,
                "kind": r.kind,
                "state": r.state,
                "channel": r.channel,
                "requester": user_name(s, r.requester_id),
                "verifier": user_name(s, r.verifier_id),
                "steward": user_name(s, r.steward_id),
                "risk_tier": r.risk_tier,
                "verification": r.verification,
                "created_at": _iso(r.created_at),
                "closed_at": _iso(r.closed_at),
            }
            for r in reqs
        ],
        "events": [
            {
                "seq": e.seq,
                "kind": e.kind,
                "actor": user_name(s, e.actor) or e.actor,
                "at": _iso(e.created_at),
                "hash": e.hash[:12],
            }
            for e in events
        ],
    }


def agents_view(s: Session) -> list[dict[str, Any]]:
    out = []
    for a in s.execute(select(Agent)).scalars():
        ms = (
            s.execute(select(Mandate).where(Mandate.agent_id == a.id).order_by(Mandate.version.desc()))
            .scalars()
            .all()
        )
        out.append(
            {
                "id": a.id,
                "display_name": a.display_name,
                "key_id": a.key_id,
                "active": a.active,
                "public_key_hex": a.public_key.hex(),
                "mandates": [
                    {
                        "id": m.id,
                        "version": m.version,
                        "permitted_operations": m.permitted_operations,
                        "forbidden_operations": m.forbidden_operations,
                        "supplier_scope": m.supplier_scope,
                        "per_proposal_ceiling_minor": m.per_proposal_ceiling_minor,
                        "daily_ceiling_minor": m.daily_ceiling_minor,
                        "approver_role": m.approver_role,
                        "second_approver_above_minor": m.second_approver_above_minor,
                        "not_before": _iso(m.not_before),
                        "expires_at": _iso(m.expires_at),
                        "revoked_at": _iso(m.revoked_at),
                        "created_by": user_name(s, m.created_by),
                    }
                    for m in ms
                ],
            }
        )
    return out
