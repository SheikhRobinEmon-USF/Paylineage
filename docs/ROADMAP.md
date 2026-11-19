# Roadmap

Estimate: 150 to 200 hours over 10 to 12 weeks. No UI work until the M0 gate passes.

## M0: Feasibility and spec pack (week 1 to 2)

Gate (all five must pass):

- [x] G1 One Rego policy compiled once and evaluated in the browser and in Python (own Wasmtime host, ADR-010). Evidence: `make parity`
- [x] G2 Identical decisions on shared vectors, including malformed, missing and unsupported-built-in inputs, all failing closed. Evidence: 58 vectors, `test_I8_*` in both runtimes
- [x] G3 Supplier onboarding and bank-change transitions defined as code with tests. Evidence: `onboarding/machine.py`, `tests/stateful/test_onboarding_machine.py`
- [x] G4 One valid approval accepted; altered, expired, revoked and replayed approvals rejected, including two concurrent executions. Evidence: `tests/unit/test_payment_flow.py`, `tests/concurrency/test_I5_permits.py`
- [x] G5 Threat model and five scenario templates (S1, S4, S7, S10, S11) written. Evidence: `docs/SECURITY.md`, `scenarios/templates/` (all 16)

Tickets:

| ID | Task | Acceptance | Links |
| --- | --- | --- | --- |
| T0.1 | Repo scaffold: Makefile, uv, pnpm workspace, docker compose (postgres), CI skeleton with lint and test-fast | `make setup && make lint && make test-fast` green on clean clone | ARCHITECTURE |
| T0.2 | Policy skeleton: input/output JSON Schemas, `decision.rego` with default deny and 6 reason codes, OPA unit tests | `make policy-test` green; undefined result impossible to read as allow | ARCHITECTURE, DATA_MODEL |
| T0.3 | Build pipeline: pinned OPA, `make policy-build` writes wasm + sha256 | Same sha256 on two clean builds | ARCHITECTURE |
| T0.4 | Python runtime adapter with opa-py-wasm, schema validation, fail-closed wrapper, fallback guard | Tests for I8: exception, timeout, undefined, invalid input all deny | SECURITY |
| T0.5 | TS policy-runtime package with @open-policy-agent/opa-wasm, same wrapper semantics | Vitest suite mirrors T0.4 | ARCHITECTURE |
| T0.6 | Parity harness: 30+ vectors incl. malformed and missing inputs; `make parity` | Zero mismatches; CI fails on mismatch | EVALUATION |
| T0.7 | Canonical digest in Python and TS with cross-language vectors | Identical digests on 20 vectors incl. unicode and large integers | DATA_MODEL |
| T0.8 | Onboarding state machine as transition table + Hypothesis RuleBasedStateMachine | Illegal transitions rejected; SoD enforced (I7) | STATE_MACHINES |
| T0.9 | Minimal approvals + permits on Postgres: issue, revalidate, atomic consume | Tests: altered (I3), expired, revoked (I4), replayed and concurrent (I5); R1 revalidation | DATA_MODEL, STATE_MACHINES |
| T0.10 | Docs: PRD, threat model refinement, scenario templates S1, S4, S7, S10, S11 | Reviewed by owner | PRODUCT, SCENARIOS |

If T0.4 fails (opa-py-wasm cannot evaluate the policy reliably), stop and open an ADR proposing the OPA server fallback with parity tests.

## M1: Deterministic core (weeks 3 to 4)

Full data model and migrations, payment state machine, mandates and agent request signing, executor and mock bank as separate processes with network isolation (I6), audit chain with signed checkpoints (I11), adversarial stub. Exit: Tracks B and C pass with the stub instead of an LLM.

## M2: Evidence layer (weeks 5 to 6)

Ingestion with trust class, Qwen extraction with claimed locations, span verifier, signals incl. Prompt Guard 2, onboarding and bank-change workflows end to end. Exit: S1 to S9, S13, L1 to L3 behave as specified on holdout.

## M3: Approval and UI (weeks 7 to 9)

WebAuthn approvals, five workspaces, Attack Lab mode B, failure states. Exit: every scenario replayable end to end; axe and Playwright green.

## M4: Public demo and evaluation (weeks 10 to 12)

GitHub Pages demo, Track A reproduction and baselines (P1), mutation testing report, evaluation report with limits, README, case study, 90-second video. Exit: demo works in a fresh browser with no install; report published.
