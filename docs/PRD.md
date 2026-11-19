# PRD: PayLineage

Status: draft for owner review (T0.10). Source documents: PRODUCT, SECURITY, STATE_MACHINES, DATA_MODEL, UI, EVALUATION.

## Problem

AI agents now read invoices and propose supplier payments. Attackers already change supplier bank details through email and invoices (business email compromise: about $3.05 billion in reported US losses in 2025, FBI IC3). An agent that reads attacker content can be steered by it. Existing tools cover one step each: supplier verification, agent tool gating, or approval binding. Nothing connects them, so untrusted content can still become payment authority somewhere along the way.

## Goal

No payment leaves until the record matches. Untrusted invoice and email content can never become payment authority, even when the model is fully manipulated and a human clicks approve.

## Users

AP specialist, finance approver, vendor data steward, verifier, fraud or security analyst, AP platform engineer (see PRODUCT).

## Functional requirements

| ID | Requirement | Invariants | Where |
| --- | --- | --- | --- |
| FR1 | Ingest email and attachments; record transport metadata and file digest; assign trust class from source only, before any model sees content | I1, I9 | ingestion |
| FR2 | Extract typed invoice fields with a claimed location, using a quarantined model that never sees tools or instructions | I1 | extraction |
| FR3 | Verify each extracted value appears at its claimed span; mark consistent, inconsistent or unchecked; never treat this as authenticity | I1 | extraction/span verifier |
| FR4 | Compute signals: lookalike domain, DMARC failure from our own server's header, Reply-To mismatch, hidden text, prompt injection, tool poisoning. Signals only hold, never allow | I1 | signals |
| FR5 | Keep a supplier master with verified domains, contact on file with its record date, and bank accounts with status | I2, I11 | onboarding |
| FR6 | Onboard new suppliers through Requested, Unverified, Verifying, StewardReview, Verified or Rejected, with requester, verifier and steward as three people | I7 | onboarding |
| FR7 | Record claimed bank changes as pending accounts; apply the three outcome rule to the old account; verify by contact on file that predates the request or by the simulated validation service | I1, I2, I7 | onboarding |
| FR8 | Apply a risk based cooling-off after a bank change is verified; a timer never replaces verification | I2 | policy |
| FR9 | Register agents with Ed25519 keys; verify every agent request signature (HTTP Message Signatures, RFC 9421) with replay protection | I6, I9, I10 | agents |
| FR10 | Load versioned mandates only from the trusted store; enforce operations, supplier scope, per proposal and daily ceilings, approver role and second approver threshold | I10 | policy |
| FR11 | Evaluate every proposal with the shared policy; return allow, hold or deny with reason codes | I1, I2, I8 | policy |
| FR12 | Run the same policy.wasm in browser and backend, identified by SHA-256; any parity mismatch fails CI; the OPA server fallback needs an explicit opt in | I8 | policy-runtime |
| FR13 | Fail closed on undefined result, unsupported built-in, exception, timeout, invalid input or unknown enum value | I8 | policy |
| FR14 | Compute a canonical payment record (RFC 8785) and its SHA-256 digest on the server only | I3 | canonical |
| FR15 | Approve with a passkey over a server issued challenge that commits to the digest; one payment at a time | I3, I7 | approvals |
| FR16 | Void approvals on material change, expiry, revocation, or change of mandate, account, approver permission or policy version | I4 | payments, policy |
| FR17 | Issue a short lived permit only after a fresh policy run | I3, I4 | permits |
| FR18 | Execute only through the protected executor: revalidate, consume the permit with one conditional update, call the simulated bank idempotently | I5, I6 | executor |
| FR19 | Append every decision and supplier change to a hash chain with signed checkpoints outside the database; verify detects modified, deleted, reordered and truncated history | I11 | audit |
| FR20 | Investigation workspace: each field linked to its source span, diff against the master, reason codes, timeline, AI explanation rendered as text | I1 | web |
| FR21 | Attack Lab: run scenarios with and without protection on the same seed; build your own attack in the browser with the real policy.wasm | I2, I9 | demo |
| FR22 | Evaluation: Tracks B and C on frozen holdout scenarios, adversarial stub in place of the model, layer ablation, latency percentiles, limits stated | all | eval |

## Non-functional requirements

- Model-free decision path p95 under 250 ms. Measured: about 0.2 ms per policy evaluation in Python.
- Works with no model running (deterministic extractor, recorded traces).
- WCAG 2.2 AA; keyboard first triage.
- No real payment rails, banks, credentials, PII or money. Verification is simulated and labeled.

## Out of scope

As frozen in v3.1 (ADR-008): batch approval, counter-sign compatibility, advanced graph views, extra models, synthetic-label fraud ML, graph ML, malware detonation, real money, consumer banking, runtime LLM judge, multi-tenancy, SSO.

## Success metrics

Zero unauthorized simulated payments on holdout with the adversarial stub. False holds on legitimate payments under 5%. Zero approval bypasses and zero double executions in Track C. Analyst minutes per case reported, not claimed.
