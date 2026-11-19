# Architecture decision records

Format: ID, title, status (Proposed, Accepted, Superseded), context, decision, consequences. Claude Code may add "Proposed" ADRs; only the owner marks them Accepted.

## ADR-001 B2B accounts payable focus (Accepted)
Clear buyer and largest relevant loss pool (BEC). Consumer banking assistant out of scope.

## ADR-002 LLM outside the authorization boundary (Accepted)
The model extracts and explains only. Policy, state and execution never depend on model output being correct.

## ADR-003 OPA Rego compiled to Wasm, shared by browser and backend (Accepted)
Backend runtime: opa-py-wasm (Wasmtime, in process). Browser: @open-policy-agent/opa-wasm. OPA server only as explicit, parity-tested fallback.

## ADR-004 Policy decides, Postgres enforces state (Accepted)
Single-use permits consumed with a conditional update inside a transaction; executor revalidates at execution time.

## ADR-005 Approval bound to RFC 8785 canonical digest via server-issued WebAuthn challenge (Accepted)
Described as server-bound approval, not trusted display. Secure Payment Confirmation is future work.

## ADR-006 Supplier onboarding and bank changes are first-class, dual-controlled workflows (Accepted)
Three-outcome rule for old accounts during bank changes; cooling-off never replaces verification.

## ADR-007 Tamper-evident audit with external signed checkpoints (Accepted)
Not tamper-proof; limits documented.

## ADR-008 Deferred and excluded scope (Accepted)
Deferred: batch approval, counter-sign compatibility, advanced graph views, extra models. Excluded: synthetic-trained fraud ML, graph ML, malware detonation, real-money execution, runtime LLM judge.

## ADR-009 Name: PayLineage (Accepted, pending USPTO and GitHub check)
Close to the existing "Payline" payments brand; acceptable for a portfolio project.

## ADR-010 Own OPA Wasm host on Wasmtime for Python (Proposed)
Context: ADR-003 names "opa-py-wasm (Wasmtime, in process)". The PyPI `opa-wasm` SDK runs on wasmer, which does not support Python above 3.10. The small `opa-wasmtime` package works but has no fuel metering and lets host built-ins through.
Decision: `backend/src/paylineage/policy/wasm_host.py` implements the OPA Wasm ABI 1.2 fastpath directly on `wasmtime` (about 200 lines). It meters fuel (a timeout denies), refuses modules that import host built-ins, and resets the heap between evaluations. The TypeScript runtime applies the same built-in refusal on top of `@open-policy-agent/opa-wasm`.
Consequences: in-process Wasmtime as ADR-003 intended, with a hard compute budget. We own a small amount of ABI code, covered by I8 tests and parity vectors.

## ADR-011 Policy input contract and reason code additions (Proposed)
Context: the spec lists an initial reason code set and expects S2 (account not in master) to hold but S9 (poisoned tool, backup account) to deny.
Decision:
- Add `source_kind = agent_asserted` for a value the agent supplied with no document or master source. A material field with this source denies (`FIELD_NO_PROVENANCE`). S2 holds (the account came from a supplier document and may be a real bank change). S9 denies (no provenance at all).
- Each reason code has exactly one class, `deny` or `hold`, in `policy/schema/reason_codes.v1.json`. Any deny code forces deny; otherwise any hold code forces hold; otherwise a positive allow gate must be proven or the result is deny with `POLICY_UNDEFINED`.
- New codes: AGENT_SIGNATURE_INVALID, MANDATE_VERSION_STALE, SUPPLIER_OUT_OF_SCOPE, TRUST_CLASS_INVALID, EVIDENCE_MISSING, FIELD_NO_PROVENANCE, FIELD_UNCHECKED, SUPPLIER_UNKNOWN, SUPPLIER_NOT_VERIFIED, APPROVAL_MISSING, APPROVER_NOT_AUTHORIZED, SECOND_APPROVAL_REQUIRED, POLICY_VERSION_STALE, PERMIT_MISSING, PERMIT_DIGEST_MISMATCH, ROLE_REQUIRED, VERIFIER_NOT_ASSIGNED, VERIFICATION_CONTACT_INVALID, VERIFICATION_FAILED, SIGNAL_TOOL_POISONING.
- Signal and duplicate holds can be cleared by an analyst who then cannot approve (I7). Beneficiary, supplier and field holds can never be cleared by a person; only a verified master record clears them (I2).
- Agents can never request change_bank_details, approve, execute, edit_mandate, create_supplier or verify_supplier, whatever a mandate says.
Consequences: the S2 and S9 expectations are both met by a rule, not by special cases.

## ADR-012 Canonical JSON number profile (Proposed)
Context: JavaScript cannot tell `1e30` from a 31 digit integer, so RFC 8785 alone does not give identical accept/reject behaviour across Python and TypeScript.
Decision: apply the I-JSON (RFC 7493) rule by value in both languages. Any integral number outside +/-(2^53 - 1) is rejected, as are non-finite numbers and lone surrogates. All money is integer minor units well inside that range. The payment record carries a schema tag `paylineage.payment.v1` for domain separation.
Consequences: the RFC 8785 section 3.2.2 example is kept as a known-answer vector without its `1E30` element, and `1E30` becomes an error vector.

## ADR-013 Policy data compiled into policy.wasm (Proposed)
Context: `opa build -t wasm` keeps bundle data outside the Wasm module, so one SHA-256 would not cover thresholds and role rules.
Decision: `policy/scripts/build.py` compiles `policy/data/config.v1.json` into a generated `config` Rego package before building. The module is evaluated with empty data. `policy.sha256` identifies policy and data together. Times are UTC epoch milliseconds in the input, so the policy needs no time built-ins.
Consequences: changing a threshold changes the hash, which (by I4) voids outstanding approvals made under the old policy.

## ADR-014 Bank changes run as a case; supplier stays verified (Proposed)
Context: STATE_MACHINES lists "Verified to Verifying: anyone recording a claimed bank change", and also says an old account confirmed still valid may stay payable. If the supplier record itself left `verified`, every payment to the still valid old account would hold.
Decision: a bank change is an onboarding case (`onboarding_requests.kind = bank_change`) that starts in `verifying` and follows the same transitions to `steward_review`, `verified` or `rejected`. The supplier record stays `verified`. The new account is `pending` until the steward approves, then `verified` with a cooling-off. A compromised or closed old account is suspended the moment the change is recorded. Assigning the verifier of a bank change case is an attribute update inside `verifying`, allowed once.
Consequences: the old account keeps working for ordinary updates; the new account cannot be paid until verified and cooled off (I2). Cross workflow SoD reads requester, verifier and steward from these cases.

## ADR-015 Agent request signing with HTTP Message Signatures (Proposed)
Context: ARCHITECTURE asks for Ed25519 request verification. Visa's Trusted Agent Protocol and Web Bot Auth both use HTTP Message Signatures (RFC 9421) with Ed25519.
Decision: agents sign `@method`, `@target-uri`, `content-digest` (RFC 9530), `created`, `nonce` and `keyid` with Ed25519 per RFC 9421. The server checks the key, a 5 minute window and a single use nonce.
Consequences: an industry standard wire format instead of a custom header; the same agent identity could later be presented to other relying parties.
