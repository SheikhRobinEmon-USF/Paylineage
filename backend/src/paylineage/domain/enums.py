"""Closed vocabularies. Unknown values are rejected at every boundary (fail closed)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    AP_SPECIALIST = "ap_specialist"
    FINANCE_APPROVER = "finance_approver"
    STEWARD = "steward"
    VERIFIER = "verifier"
    ANALYST = "analyst"
    PLATFORM_ENGINEER = "platform_engineer"
    ADMIN = "admin"


class SourceKind(StrEnum):
    EMAIL_BODY = "email_body"
    EMAIL_ATTACHMENT = "email_attachment"
    PORTAL_UPLOAD = "portal_upload"
    AGENT_ASSERTED = "agent_asserted"
    SUPPLIER_MASTER = "supplier_master"
    USER_ENTERED = "user_entered"
    SYSTEM = "system"


class TrustClass(StrEnum):
    UNTRUSTED_EXTERNAL = "untrusted_external"
    VERIFIED_MASTER = "verified_master"
    USER_ENTERED = "user_entered"
    SYSTEM_GENERATED = "system_generated"


# The server assigns trust from the source kind alone (I9). Nothing else may set it.
TRUST_BY_SOURCE: dict[SourceKind, TrustClass] = {
    SourceKind.EMAIL_BODY: TrustClass.UNTRUSTED_EXTERNAL,
    SourceKind.EMAIL_ATTACHMENT: TrustClass.UNTRUSTED_EXTERNAL,
    SourceKind.PORTAL_UPLOAD: TrustClass.UNTRUSTED_EXTERNAL,
    SourceKind.AGENT_ASSERTED: TrustClass.UNTRUSTED_EXTERNAL,
    SourceKind.SUPPLIER_MASTER: TrustClass.VERIFIED_MASTER,
    SourceKind.USER_ENTERED: TrustClass.USER_ENTERED,
    SourceKind.SYSTEM: TrustClass.SYSTEM_GENERATED,
}


def trust_for(source: SourceKind | str) -> TrustClass:
    return TRUST_BY_SOURCE[SourceKind(source)]


class Consistency(StrEnum):
    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    UNCHECKED = "unchecked"


class FieldName(StrEnum):
    AMOUNT = "amount"
    BENEFICIARY_ACCOUNT = "beneficiary_account"
    CURRENCY = "currency"
    INVOICE_NUMBER = "invoice_number"
    SUPPLIER_NAME = "supplier_name"
    DUE_DATE = "due_date"
    REMIT_EMAIL = "remit_email"
    PO_NUMBER = "po_number"


MATERIAL_FIELDS: tuple[FieldName, ...] = (
    FieldName.AMOUNT,
    FieldName.BENEFICIARY_ACCOUNT,
    FieldName.CURRENCY,
    FieldName.INVOICE_NUMBER,
    FieldName.SUPPLIER_NAME,
)


class SupplierStatus(StrEnum):
    REQUESTED = "requested"
    UNVERIFIED = "unverified"
    VERIFYING = "verifying"
    STEWARD_REVIEW = "steward_review"
    VERIFIED = "verified"
    REJECTED = "rejected"
    SUSPENDED = "suspended"


class AccountStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class RequestKind(StrEnum):
    NEW_SUPPLIER = "new_supplier"
    BANK_CHANGE = "bank_change"


class OldAccountOutcome(StrEnum):
    """Three outcome rule for the old account during a bank change (ADR-006)."""

    STILL_VALID = "still_valid"
    COMPROMISED = "compromised"
    CLOSED = "closed"


class PaymentState(StrEnum):
    PROPOSED = "proposed"
    EVALUATED = "evaluated"
    HELD = "held"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    PERMIT_ISSUED = "permit_issued"
    EXECUTED = "executed"
    EXPIRED = "expired"


class Operation(StrEnum):
    READ_INVOICE = "read_invoice"
    EXTRACT_FIELDS = "extract_fields"
    PROPOSE_PAYMENT = "propose_payment"
    CHANGE_BANK_DETAILS = "change_bank_details"
    APPROVE = "approve"
    EXECUTE = "execute"
    EDIT_MANDATE = "edit_mandate"
    CREATE_SUPPLIER = "create_supplier"
    VERIFY_SUPPLIER = "verify_supplier"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
