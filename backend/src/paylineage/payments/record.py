"""The canonical payment record and its digest. Approvals and permits bind to this digest."""

from __future__ import annotations

from typing import Any

from paylineage.canonical import PAYMENT_RECORD_SCHEMA, payment_record_digest
from paylineage.db.models import Payment
from paylineage.domain.clock import to_ms

MATERIAL_FIELDS = (
    "amount_minor",
    "currency",
    "supplier_id",
    "beneficiary_account_id",
    "invoice_id",
    "operation",
)


def canonical_record(p: Payment) -> dict[str, Any]:
    return {
        "schema": PAYMENT_RECORD_SCHEMA,
        "payment_id": p.id,
        "version": p.version,
        "amount_minor": p.amount_minor,
        "currency": p.currency,
        "supplier_id": p.supplier_id or "",
        "beneficiary_account_id": p.beneficiary_account_id or "",
        "invoice_id": p.invoice_id,
        "invoice_digest": p.invoice_digest,
        "agent_id": p.agent_id,
        "mandate_version": p.mandate_version,
        "policy_version": p.policy_version,
        "policy_sha256": p.policy_sha256,
        "operation": p.operation,
        "nonce": p.nonce,
        "expires_at_ms": to_ms(p.expires_at),
    }


def compute_digest(p: Payment) -> str:
    """Always recomputed by the server from the stored record. Client digests are never accepted."""
    return payment_record_digest(canonical_record(p))
