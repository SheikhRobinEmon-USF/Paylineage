# Data model

All money is `amount_minor: int` plus `currency: str` (ISO 4217, MVP: USD only). All times UTC. IDs are UUIDv7.

## Provenance-tagged field

| Field | Type | Notes |
| --- | --- | --- |
| field_name | enum | beneficiary_account, amount, invoice_number, supplier_name, due_date, remit_email, ... |
| value_token | str | Tokenized; raw value only in `vault_values` table |
| source_kind | enum | email_body, email_attachment, portal_upload, agent_asserted, supplier_master, user_entered, system (agent_asserted: the agent supplied the value with no document or master source; ADR-011) |
| source_ref | object | file digest, page, bounding box, span hash |
| trust_class | enum | untrusted_external, verified_master, user_entered, system_generated (assigned by server from source only) |
| consistency | enum | consistent, inconsistent, unchecked (span verifier) |
| extractor | object | model id, model digest, prompt version |
| master_match | object or null | master record id, matched: bool |

## Agent mandate (versioned)

| Field | Example |
| --- | --- |
| mandate_id, version | uuid, 3 |
| principal_org | Example Manufacturing LLC (fictional) |
| agent_id, public_key | AP-Agent-001, Ed25519 |
| permitted_operations | read_invoice, extract_fields, propose_payment |
| forbidden_operations | change_bank_details, approve, execute, edit_mandate |
| supplier_scope | allowlist of supplier ids or categories |
| per_proposal_ceiling_minor, daily_ceiling_minor | 5000000, 15000000 |
| approval_policy | approver role; second approver above threshold |
| not_before, expires_at, revoked_at | |

Loaded only from the trusted store by `agent_id` + `version`. A mandate in a request body is ignored.

## Supplier and bank accounts

`suppliers`: id, legal_name, verified_domains[], contact_on_file (with `recorded_at`), status (requested, unverified, verifying, steward_review, verified, rejected, suspended), version.

`supplier_bank_accounts`: id, supplier_id, account_token, status (pending, verified, suspended, revoked), verified_by, verified_method (callback_on_file, simulated_validation_service), steward_by, cooling_off_until, reported_compromised_at, version.

`supplier_events`: append-only, id, supplier_id, actor, event_type, payload_digest, prev_hash, hash, created_at.

## Canonical payment record

| Field | Notes |
| --- | --- |
| payment_id, version | version increments on material change |
| amount_minor, currency | |
| supplier_id, beneficiary_account_id | id of a master account, never raw invoice digits |
| invoice_id, invoice_digest | |
| agent_id, mandate_version, policy_version, policy_sha256 | |
| operation | pay_invoice |
| nonce, expires_at | |
| digest | SHA-256 over RFC 8785 canonical JSON of all fields above |

Material fields: amount_minor, currency, supplier_id, beneficiary_account_id, invoice_id, operation.

## Approvals and permits

`approvals`: id, payment_id, payment_version, digest, approver_id, webauthn_credential_id, challenge_id, signed_at, expires_at, revoked_at.

`permits`: id, payment_id, approval_id, digest, issued_at, expires_at, consumed_at (nullable), consumed_by_request_id.

Consume (inside one transaction, after revalidation):
```sql
UPDATE permits SET consumed_at = now(), consumed_by_request_id = :req
WHERE id = :id AND consumed_at IS NULL AND expires_at > now()
RETURNING id;
```
Zero rows returned means reject.

## Audit

`audit_events`: id, seq, actor, kind, subject_id, payload_digest, prev_hash, hash, created_at.
Checkpoints: every N events or M minutes, sign (Ed25519) `{seq, hash, created_at}` with a key held outside the DB; write to `var/checkpoints/*.json` (MVP) so the store can later move off-host.

## Reason codes (initial set)

| Code | Meaning |
| --- | --- |
| BENEFICIARY_NOT_VERIFIED | Account not in master with status verified |
| BENEFICIARY_MISMATCH | Proposed account differs from verified account |
| FIELD_UNTRUSTED_MATERIAL | A material field has trust_class untrusted_external |
| FIELD_INCONSISTENT | Span verifier failed |
| COOLING_OFF_ACTIVE | New account inside cooling-off |
| ACCOUNT_SUSPENDED | Account reported compromised, closed or disputed |
| MANDATE_MISSING, MANDATE_EXPIRED, MANDATE_REVOKED | |
| OP_FORBIDDEN | Operation not permitted by mandate |
| OVER_CEILING | Amount above mandate ceiling |
| SOD_VIOLATION | Same person in conflicting roles |
| APPROVAL_DIGEST_MISMATCH, APPROVAL_EXPIRED, APPROVAL_REVOKED | |
| PERMIT_CONSUMED, PERMIT_EXPIRED | |
| DUPLICATE_INVOICE | |
| SIGNAL_LOOKALIKE_DOMAIN, SIGNAL_DMARC_FAIL, SIGNAL_REPLY_TO_MISMATCH, SIGNAL_HIDDEN_TEXT, SIGNAL_PROMPT_INJECTION | Signals raise holds, never allow |
| POLICY_UNDEFINED, POLICY_ERROR, INPUT_INVALID, PARITY_MISMATCH | Fail-closed codes |

### Reason codes added in v1.0.0 of the policy (ADR-011)

The registry of record is `policy/schema/reason_codes.v1.json`. Each code has one class: `deny` forces deny, `hold` forces hold.

| Code | Class | Meaning |
| --- | --- | --- |
| AGENT_SIGNATURE_INVALID | deny | Agent request signature missing or invalid |
| MANDATE_VERSION_STALE | deny | Payment was proposed under an older mandate version |
| SUPPLIER_OUT_OF_SCOPE | deny | Supplier not in the mandate supplier scope |
| TRUST_CLASS_INVALID | deny | Trust class does not match the source kind (someone tried to set their own trust) |
| EVIDENCE_MISSING | deny | A required material field or verification record is missing or ambiguous |
| FIELD_NO_PROVENANCE | deny | A material value was asserted by the agent with no document or master source |
| APPROVAL_MISSING | deny | No approval recorded for this payment version |
| APPROVER_NOT_AUTHORIZED | deny | Approver inactive or lacks the role the mandate requires |
| POLICY_VERSION_STALE | deny | Record was evaluated under a different policy version |
| PERMIT_MISSING | deny | No permit presented for execution |
| PERMIT_DIGEST_MISMATCH | deny | Permit digest differs from the current canonical record |
| ROLE_REQUIRED | deny | Actor lacks the role this onboarding action needs |
| VERIFIER_NOT_ASSIGNED | deny | Actor is not the verifier assigned to this request |
| VERIFICATION_CONTACT_INVALID | deny | Verification used a contact that is not on file or postdates the request |
| VERIFICATION_FAILED | deny | Registry or bank confirmation failed |
| FIELD_UNCHECKED | hold | Span verifier has not checked an untrusted material field |
| SUPPLIER_UNKNOWN | hold | No supplier master record for this invoice |
| SUPPLIER_NOT_VERIFIED | hold | Supplier exists but is not verified |
| SECOND_APPROVAL_REQUIRED | hold | Amount needs a second distinct approver |
| SIGNAL_TOOL_POISONING | hold | A tool description tried to steer payment details |

Existing codes keep their meaning. Their classes: BENEFICIARY_NOT_VERIFIED, BENEFICIARY_MISMATCH, FIELD_UNTRUSTED_MATERIAL, FIELD_INCONSISTENT, COOLING_OFF_ACTIVE, DUPLICATE_INVOICE and all SIGNAL_* codes are `hold`. All other codes are `deny`.

### Time and number conventions in the policy input

Times are UTC epoch milliseconds (`*_ms`). Integers are bounded to the IEEE 754 safe range so Python and JavaScript agree (ADR-012).
