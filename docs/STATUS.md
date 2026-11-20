# Status

Snapshot of what is built against `docs/ROADMAP.md`. Evidence is in tests and `eval/results/report.md`.

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 Feasibility | Done, gate G1 to G5 passed | `make parity` (58 decision and 25 digest vectors), OPA tests at 100% coverage, T0.8 and T0.9 tests |
| M1 Deterministic core | Done | Payment state machine with Hypothesis on PostgreSQL, RFC 9421 agent signing, executor and mock bank as separate processes, I6 isolation tests, I11 tamper tests, Tracks B and C pass with the adversarial stub |
| M2 Evidence layer | Done | Bounded email and PDF ingestion, hidden text detection, signals, quarantined extraction (deterministic, Ollama, adversarial stub), span verifier; all 16 templates behave as specified on the frozen holdout |
| M3 Approval and UI | Done | WebAuthn approvals proven in a real browser with a virtual authenticator; seven workspaces; Playwright and axe green on the demo |
| M4 Demo and evaluation | Done except the items below | Static demo with in-browser replay parity, GitHub Pages workflow, evaluation report, README |

## Numbers (frozen holdout)

- 0 unauthorized payments with the adversarial stub, 0 with the deterministic extractor.
- 0 of 18 false holds on legitimate payments.
- 17 of 17 Track C authorization checks refused.
- 24 of 24 hand planted Rego mutants killed.
- 21 of 21 hand planted Python mutants killed on the authorization path (`make mutation`). The first run left 7 alive; each became a direct guard test in `backend/tests/unit/test_guards_direct.py`.
- Policy decision p95 about 2 ms; proposal to decision including PDF parsing p95 about 110 ms.

## Open items

| Item | Why open | Next step |
| --- | --- | --- |
| Track A (AgentDojo) and baseline comparisons | P1 in the spec; needs model runs | Reproduce Interbolt's published banking result first, then run PayLineage beside it |
| Recorded model attack traces (Attack Lab mode A) | P1; needs local model runs | Record Qwen3.5 4B runs with model id, digest and date |
| Analyst minutes per case | Needs a user study | Time a small set of tasks with and without the investigation workspace |
| Semgrep not run locally | The build sandbox cannot reach the Semgrep rule registry | Runs in the CI security job; ruff's `S` (bandit) rules run locally |
| ADR-010 to ADR-016 | Proposed, owner decides. ADR-016 replaces mutmut with hand planted Python mutants | Review `docs/DECISIONS.md` |

## Hardening pass (bug fixes)

| Area | Fixed |
| --- | --- |
| Approvals | A passkey finish checks that the challenge was issued to the signed in user for this payment. A failed assertion still burns its challenge |
| Idempotency | Retries racing on one idempotency key returned a unique violation; a transaction scoped advisory lock now serializes them |
| Audit (I11) | Checkpoints are signed every minute and on `POST /v1/audit/checkpoint`; both audit views verify them. An unreadable key is a problem, never a pass |
| Secrets | Vault pepper is separate from the session secret; production refuses development defaults; inbound mail needs `INGEST_TOKEN` outside dev |
| Rate limit | Bucketed by client address and agent key id, never by headers alone |
| Agent | The simulated agent polls `GET /v1/agent/invoices`, uses one idempotency key per invoice and parses money with `Decimal` |
| Deployment | Working images for backend and web, `.dockerignore`, migrate and seed-if-empty, loopback bind by default, key files readable through `group_add`. Verified with `make stack` |
| CI | Playwright received a literal `--`; pip-audit choked on the workspace line; nightly mutants missed OPA on `PATH`. New job builds both images |
| UI | Deny and revoke dialogs no longer hang off an empty trigger; revoke errors are shown; the session check no longer logs a 401 |
