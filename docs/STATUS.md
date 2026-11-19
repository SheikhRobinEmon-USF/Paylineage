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
- Policy decision p95 about 2 ms; proposal to decision including PDF parsing p95 about 110 ms.

## Open items

| Item | Why open | Next step |
| --- | --- | --- |
| Python mutation testing (mutmut) on approvals, permits and executor | mutmut 3 names mutants by file path (`backend.src.paylineage...`) but the code is imported as `paylineage...`, so it never maps tests to mutants in this workspace layout. Policy mutation testing is done in Rego instead | Try `cosmic-ray` or a small purpose built mutator for the four modules; give each worker its own test database |
| Track A (AgentDojo) and baseline comparisons | P1 in the spec; needs model runs | Reproduce Interbolt's published banking result first, then run PayLineage beside it |
| Recorded model attack traces (Attack Lab mode A) | P1; needs local model runs | Record Qwen3.5 4B runs with model id, digest and date |
| Analyst minutes per case | Needs a user study | Time a small set of tasks with and without the investigation workspace |
| Docker images not built in this environment | No Docker daemon was available here | `docker compose up` locally; the compose file is checked by the I6 tests |
| ADR-010 to ADR-015 | Proposed, owner decides | Review `docs/DECISIONS.md` |
