"""Authoritative store (ARCHITECTURE: PostgreSQL owns suppliers, payments, approvals, mandates, permits).

Conventions: UUIDv7 text ids, integer minor units for money, timezone-aware UTC
timestamps, closed vocabularies enforced by CHECK constraints so an unknown enum
value can never be written (fail closed at the storage layer too).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from paylineage.db.base import Base
from paylineage.domain.enums import (
    AccountStatus,
    Consistency,
    FieldName,
    PaymentState,
    RequestKind,
    Role,
    SourceKind,
    SupplierStatus,
    TrustClass,
)
from paylineage.domain.ids import new_id

TS = DateTime(timezone=True)


def _in(col: str, values: Any) -> str:
    return f"{col} IN ({', '.join(repr(str(v.value)) for v in values)})"


def _ts_now() -> Any:
    return text("now()")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    roles: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    __table_args__ = (
        CheckConstraint(
            "roles <@ ARRAY[" + ", ".join(repr(r.value) for r in Role) + "]::varchar[]", name="roles_known"
        ),
    )


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"
    id: Mapped[str] = mapped_column(String(512), primary_key=True)  # base64url credential id
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    transports: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    revoked_at: Mapped[datetime | None] = mapped_column(TS)


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    purpose: Mapped[str] = mapped_column(String(16))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    payment_id: Mapped[str | None] = mapped_column(ForeignKey("payments.id"))
    payment_version: Mapped[int | None] = mapped_column(Integer)
    digest: Mapped[str | None] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(TS)
    used_at: Mapped[datetime | None] = mapped_column(TS)
    __table_args__ = (CheckConstraint("purpose IN ('register', 'login', 'approve')", name="purpose_known"),)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. AP-Agent-001
    display_name: Mapped[str] = mapped_column(String(120))
    key_id: Mapped[str] = mapped_column(String(128), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)  # raw Ed25519, 32 bytes
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())


class AgentNonce(Base):
    """Replay protection for signed agent requests."""

    __tablename__ = "agent_nonces"
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(TS)


class Mandate(Base):
    """Versioned delegation of authority. Loaded only from here, never from a request body."""

    __tablename__ = "mandates"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    version: Mapped[int] = mapped_column(Integer)
    principal_org: Mapped[str] = mapped_column(String(200))
    permitted_operations: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    forbidden_operations: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    supplier_scope: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    per_proposal_ceiling_minor: Mapped[int] = mapped_column(BigInteger)
    daily_ceiling_minor: Mapped[int] = mapped_column(BigInteger)
    approver_role: Mapped[str] = mapped_column(String(32))
    second_approver_above_minor: Mapped[int] = mapped_column(BigInteger)
    not_before: Mapped[datetime] = mapped_column(TS)
    expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    __table_args__ = (
        UniqueConstraint("agent_id", "version"),
        CheckConstraint("per_proposal_ceiling_minor >= 0 AND daily_ceiling_minor >= 0", name="ceilings"),
        CheckConstraint("version >= 1", name="version_positive"),
    )


class VaultValue(Base):
    """Raw sensitive values (fictional account numbers). Everything else holds tokens."""

    __tablename__ = "vault_values"
    token: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())


class Supplier(Base):
    __tablename__ = "suppliers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    legal_name: Mapped[str] = mapped_column(String(200))
    verified_domains: Mapped[list[str]] = mapped_column(ARRAY(String(253)), default=list)
    status: Mapped[str] = mapped_column(String(20))
    contact_on_file: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    contact_recorded_at: Mapped[datetime | None] = mapped_column(TS)
    registry_id: Mapped[str | None] = mapped_column(String(64))
    risk_tier: Mapped[str] = mapped_column(String(8), default="medium")
    created_from: Mapped[str] = mapped_column(String(32), default="user_entered")
    requested_by: Mapped[str | None] = mapped_column(String(64))
    row_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    __mapper_args__ = {"version_id_col": row_version}  # noqa: RUF012
    __table_args__ = (
        CheckConstraint(_in("status", SupplierStatus), name="status_known"),
        CheckConstraint("risk_tier IN ('low', 'medium', 'high')", name="risk_known"),
    )


class SupplierBankAccount(Base):
    __tablename__ = "supplier_bank_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"))
    account_token: Mapped[str] = mapped_column(String(80))
    last4: Mapped[str] = mapped_column(String(4))
    bank_name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(12))
    verified_by: Mapped[str | None] = mapped_column(String(36))
    verified_method: Mapped[str | None] = mapped_column(String(40))
    steward_by: Mapped[str | None] = mapped_column(String(36))
    verified_at: Mapped[datetime | None] = mapped_column(TS)
    cooling_off_until: Mapped[datetime | None] = mapped_column(TS)
    reported_compromised_at: Mapped[datetime | None] = mapped_column(TS)
    row_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())
    __mapper_args__ = {"version_id_col": row_version}  # noqa: RUF012
    __table_args__ = (
        CheckConstraint(_in("status", AccountStatus), name="status_known"),
        CheckConstraint(
            "verified_method IS NULL OR "
            "verified_method IN ('callback_on_file', 'simulated_validation_service')",
            name="method_known",
        ),
        UniqueConstraint("supplier_id", "account_token"),
    )


class OnboardingRequest(Base):
    """One case on the onboarding state machine: a new supplier or a bank change."""

    __tablename__ = "onboarding_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"))
    kind: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(20))
    bank_account_id: Mapped[str | None] = mapped_column(ForeignKey("supplier_bank_accounts.id"))
    old_account_id: Mapped[str | None] = mapped_column(ForeignKey("supplier_bank_accounts.id"))
    old_account_outcome: Mapped[str | None] = mapped_column(String(16))
    channel: Mapped[str] = mapped_column(
        String(32)
    )  # how the claim arrived: email, portal, phone, user_entered
    requester_id: Mapped[str] = mapped_column(String(64))
    verifier_id: Mapped[str | None] = mapped_column(String(36))
    steward_id: Mapped[str | None] = mapped_column(String(36))
    assigned_by: Mapped[str | None] = mapped_column(String(36))
    verification: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    risk_tier: Mapped[str] = mapped_column(String(8), default="high")
    resolution: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS)
    updated_at: Mapped[datetime] = mapped_column(TS)
    closed_at: Mapped[datetime | None] = mapped_column(TS)
    row_version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": row_version}  # noqa: RUF012
    __table_args__ = (
        CheckConstraint(_in("kind", RequestKind), name="kind_known"),
        CheckConstraint(
            "state IN ('requested', 'unverified', 'verifying', 'steward_review', 'verified', 'rejected')",
            name="state_known",
        ),
        Index("ix_onboarding_supplier", "supplier_id"),
    )


class PurchaseOrder(Base):
    __tablename__ = "purchase_orders"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"))
    po_number: Mapped[str] = mapped_column(String(64), unique=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=_ts_now())


class Document(Base):
    """An ingested artifact. Trust class assigned by the server from source only, before any LLM."""

    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("documents.id"))
    source_kind: Mapped[str] = mapped_column(String(24))
    trust_class: Mapped[str] = mapped_column(String(24))
    file_digest: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str | None] = mapped_column(String(255))
    media_type: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int] = mapped_column(Integer)
    transport: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    text_content: Mapped[str] = mapped_column(Text, default="")
    pages: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    received_at: Mapped[datetime] = mapped_column(TS)
    __table_args__ = (
        CheckConstraint(_in("source_kind", SourceKind), name="source_known"),
        CheckConstraint(_in("trust_class", TrustClass), name="trust_known"),
    )


class Invoice(Base):
    __tablename__ = "invoices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"))
    email_document_id: Mapped[str | None] = mapped_column(ForeignKey("documents.id"))
    supplier_id: Mapped[str | None] = mapped_column(ForeignKey("suppliers.id"))
    invoice_number: Mapped[str | None] = mapped_column(String(64))
    invoice_digest: Mapped[str] = mapped_column(String(64))
    amount_minor: Mapped[int | None] = mapped_column(BigInteger)
    currency: Mapped[str | None] = mapped_column(String(3))
    po_number: Mapped[str | None] = mapped_column(String(64))
    duplicate_of: Mapped[str | None] = mapped_column(String(36))
    scenario_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(TS)


class ExtractedField(Base):
    __tablename__ = "extracted_fields"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    invoice_id: Mapped[str] = mapped_column(ForeignKey("invoices.id"))
    field_name: Mapped[str] = mapped_column(String(32))
    value_token: Mapped[str] = mapped_column(String(80))
    display_value: Mapped[str] = mapped_column(String(200))  # masked for account numbers
    source_kind: Mapped[str] = mapped_column(String(24))
    trust_class: Mapped[str] = mapped_column(String(24))
    source_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    consistency: Mapped[str] = mapped_column(String(16))
    extractor: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    master_match: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    __table_args__ = (
        CheckConstraint(_in("field_name", FieldName), name="field_known"),
        CheckConstraint(_in("source_kind", SourceKind), name="source_known"),
        CheckConstraint(_in("trust_class", TrustClass), name="trust_known"),
        CheckConstraint(_in("consistency", Consistency), name="consistency_known"),
        Index("ix_fields_invoice", "invoice_id"),
    )


class Signal(Base):
    __tablename__ = "signals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    invoice_id: Mapped[str] = mapped_column(ForeignKey("invoices.id"))
    code: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(8))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    __table_args__ = (
        CheckConstraint("code LIKE 'SIGNAL_%'", name="code_signal"),
        CheckConstraint("severity IN ('low', 'medium', 'high')", name="severity_known"),
    )


class Payment(Base):
    """Canonical payment record. `version` increments on material change; approvals bind to it."""

    __tablename__ = "payments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    version: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(20))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    supplier_id: Mapped[str | None] = mapped_column(ForeignKey("suppliers.id"))
    beneficiary_account_id: Mapped[str | None] = mapped_column(ForeignKey("supplier_bank_accounts.id"))
    proposed_account_token: Mapped[str] = mapped_column(String(80))
    invoice_id: Mapped[str] = mapped_column(ForeignKey("invoices.id"))
    invoice_digest: Mapped[str] = mapped_column(String(64))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    mandate_version: Mapped[int] = mapped_column(Integer)
    policy_version: Mapped[str] = mapped_column(String(32))
    policy_sha256: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(32), default="pay_invoice")
    nonce: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(TS)
    digest: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    last_decision: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Material values a person corrected (field -> {by, at}); provenance becomes user_entered.
    overrides: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    exposure_minor: Mapped[int] = mapped_column(BigInteger, default=0)
    row_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(TS)
    updated_at: Mapped[datetime] = mapped_column(TS)
    __mapper_args__ = {"version_id_col": row_version}  # noqa: RUF012
    __table_args__ = (
        CheckConstraint(_in("state", PaymentState), name="state_known"),
        CheckConstraint("amount_minor > 0", name="amount_positive"),
        CheckConstraint("operation = 'pay_invoice'", name="operation_known"),
        UniqueConstraint("agent_id", "idempotency_key"),
        Index("ix_payments_state", "state"),
    )


class PolicyDecisionRow(Base):
    """Every policy evaluation, for audit and the investigation timeline."""

    __tablename__ = "policy_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str | None] = mapped_column(ForeignKey("payments.id"))
    subject_id: Mapped[str | None] = mapped_column(String(36))
    payment_version: Mapped[int | None] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(48))
    decision: Mapped[str] = mapped_column(String(8))
    reasons: Mapped[list[str]] = mapped_column(ARRAY(String(40)))
    policy_version: Mapped[str] = mapped_column(String(32))
    policy_sha256: Mapped[str] = mapped_column(String(64))
    runtime: Mapped[str] = mapped_column(String(16))
    input_digest: Mapped[str] = mapped_column(String(64))
    latency_us: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(TS)
    __table_args__ = (CheckConstraint("decision IN ('allow', 'hold', 'deny')", name="decision_known"),)


class HoldClearance(Base):
    __tablename__ = "hold_clearances"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str] = mapped_column(ForeignKey("payments.id"))
    code: Mapped[str] = mapped_column(String(40))
    cleared_by: Mapped[str] = mapped_column(String(36))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str] = mapped_column(ForeignKey("payments.id"))
    payment_version: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str] = mapped_column(String(64))
    approver_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    webauthn_credential_id: Mapped[str] = mapped_column(String(512))
    challenge_id: Mapped[str] = mapped_column(ForeignKey("webauthn_challenges.id"), unique=True)
    signed_at: Mapped[datetime] = mapped_column(TS)
    expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    __table_args__ = (UniqueConstraint("payment_id", "payment_version", "approver_id"),)


class Permit(Base):
    __tablename__ = "permits"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str] = mapped_column(ForeignKey("payments.id"))
    approval_id: Mapped[str] = mapped_column(ForeignKey("approvals.id"))
    digest: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(TS)
    expires_at: Mapped[datetime] = mapped_column(TS)
    consumed_at: Mapped[datetime | None] = mapped_column(TS)
    consumed_by_request_id: Mapped[str | None] = mapped_column(String(64))
    __table_args__ = (
        CheckConstraint("(consumed_at IS NULL) = (consumed_by_request_id IS NULL)", name="consumed_pair"),
    )


class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str] = mapped_column(ForeignKey("payments.id"), unique=True)
    permit_id: Mapped[str] = mapped_column(ForeignKey("permits.id"), unique=True)
    bank_reference: Mapped[str] = mapped_column(String(64))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    beneficiary_account_id: Mapped[str] = mapped_column(String(36))
    executed_at: Mapped[datetime] = mapped_column(TS)


class AuditEvent(Base):
    """Append-only hash chain. Supplier master changes are the `supplier.*` kinds (I11)."""

    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(BigInteger, unique=True)
    actor: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(64))
    subject_id: Mapped[str | None] = mapped_column(String(36))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_digest: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(TS)
    __table_args__ = (Index("ix_audit_subject", "subject_id"),)


class AuditHead(Base):
    """Single row locked FOR UPDATE to serialize appends."""

    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    hash: Mapped[str] = mapped_column(String(64))
    __table_args__ = (CheckConstraint("id = 1", name="singleton"),)


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_digest: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(TS)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    payment_id: Mapped[str | None] = mapped_column(ForeignKey("payments.id"))
    onboarding_request_id: Mapped[str | None] = mapped_column(ForeignKey("onboarding_requests.id"))
    status: Mapped[str] = mapped_column(String(16), default="open")
    title: Mapped[str] = mapped_column(String(200))
    assigned_to: Mapped[str | None] = mapped_column(String(36))
    notes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    outcome: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(TS)
    updated_at: Mapped[datetime] = mapped_column(TS)


class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    topic: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(TS)
    processed_at: Mapped[datetime | None] = mapped_column(TS)
