# Security: trust model, threat model, invariants

## Trust model: six independent checks

| Control | Question it answers | What it cannot prove |
| --- | --- | --- |
| Field provenance | Where did this value come from, how trusted is that source? | That the source is truthful |
| Supplier master verification | Do bank details match an independently verified record? | That the verified record was never compromised |
| Agent mandate | Is this agent allowed to request this action, supplier, amount? | That the request is wise |
| Payment policy | Do organizational rules allow it? | That inputs are genuine |
| Server-bound passkey approval | Did an authorized human approve this exact canonical record? | That the screen showed true details (no trusted display) |
| Execution integrity | Does execution match the approval, exactly once? | Anything before approval |

## Threat model

Attacker controls: inbound emails and attachments, invoice contents including hidden text, lookalike domains, payment reference text, one third-party tool description, unlimited submissions.

Attacker does not control: supplier master, mandates, policies, passkeys, executor credentials, checkpoint signing key.

Assumptions: approver device and browser not compromised; executor reachable only via the permit service; the LLM may be fully manipulated at any time.

Verification trust assumption: supplier verification is simulated in the MVP. A test administrator records that a fictional supplier's details were independently confirmed.

## Invariants (acceptance criteria)

Every invariant has tests named with its ID (for example `test_I5_concurrent_consume_executes_once`).

| ID | Invariant | Covers | Test types |
| --- | --- | --- | --- |
| I1 | Untrusted document content cannot grant authorization or modify trusted supplier records | Injection, invoice-driven bank changes | Stateful, adversarial stub |
| I2 | An unverified beneficiary cannot be paid, even if the agent proposes it and a human approves it | Unverified payee, deceived approver | Property, stateful |
| I3 | Approval is valid only for the exact canonical transaction, authorized actor and permitted operation | Tampering, wrong approver | Mutation between approval and execution |
| I4 | Any material change, expiry, revocation or policy failure removes execution eligibility | Edits, revoked mandates, stale approvals | Stateful |
| I5 | Each permit is consumed at most once, including under concurrency | Replay, double execution | Parallel submissions against Postgres |
| I6 | The agent cannot reach the executor or obtain credentials except through a permit | Bypass | Network and credential isolation |
| I7 | Supplier creation, bank verification and payment approval follow separation of duties | Insider self-approval | Role fuzzing |
| I8 | Missing evidence, unavailable policy, undefined result, unsupported built-in, runtime exception, parity mismatch or any authorization error fails closed | Outage and error abuse | Fault injection |
| I9 | No trust level accepted from client or LLM; browser results never authoritative | Client tampering | Tampered requests |
| I10 | No action outside the agent's current mandate version executes | Excess agency | Mandate fuzzing |
| I11 | Every supplier-master change is attributable and tamper-evident relative to signed checkpoints outside the database | Compromised master (detection only) | Modified, deleted, reordered, truncated events |

## Residual risks (state, do not hide)

- A well-prepared fake supplier can pass simulated onboarding (scenario S13).
- Collusion between verifier and approver.
- An attacker who also controls a contact already on file.
- Compromised approver device, administrator, or checkpoint signing key (I11 no longer holds).
- Tamper-evident is not tamper-proof: the log proves integrity of what was recorded, not that facts were true.

## Application security requirements

- Model output is always HTML-encoded; strict CSP with nonces; no `dangerouslySetInnerHTML` with model or document text.
- No URL fetching of attacker-supplied links (SSRF). Links are parsed and scored only.
- Bounded file parsers, file-type validation, size limits; known-bad hash list only, no detonation.
- Rate limits per agent and per user; idempotency keys on all state-changing endpoints.
- Secrets only from env; `.env.example` committed; Gitleaks in CI.
- Dependencies locked (uv.lock, pnpm-lock.yaml); Dependabot; Semgrep; Trivy; CycloneDX SBOM per release.
- Logs: no full account numbers, no document bodies; tokenized identifiers.
