# CLAUDE.md: PayLineage

PayLineage stops AI accounts-payable agents from sending payments to unverified or unauthorized beneficiaries.
Tagline: no payment leaves until the record matches.

This file tells Claude Code how to work in this repository. Read it fully before every task.
The specification lives in `docs/`. When this file and a doc disagree, stop and ask.

## 1. Before you write any code

1. Read `docs/ROADMAP.md` and find the current milestone and ticket.
2. Read every doc the ticket links to. At minimum: `docs/SECURITY.md` (invariants I1 to I11). For product intent and requirement IDs (FR1 to FR22), read `docs/PRD.md`.
3. Check the ticket's acceptance criteria. Plan the tests first, then the code.
4. If the task would change scope, an invariant, a trust boundary or a state machine: do not implement it. Write a short proposal in `docs/DECISIONS.md` (new ADR, status "Proposed") and ask the owner.

## 2. Non-negotiable rules

These come from the frozen v3.1 spec. Breaking any of them is a bug, even if tests pass.

1. **The LLM is never in the authorization path.** It extracts and explains. It never decides, never sets a trust level, never writes to the supplier master, mandates, approvals or permits.
2. **Fail closed.** Undefined policy result, unsupported built-in, runtime exception, missing evidence, parity mismatch, timeout, unknown enum value: all mean `deny`. Never default to allow.
3. **Policy decides, the database enforces state.** OPA (Rego) answers "is this permitted?". PostgreSQL transactions, the transaction service and the executor enforce state changes, versions, idempotency and single use.
4. **Never trust the client or the browser.** The backend recomputes provenance, trust class and policy for every request. A browser "allowed" result is display only.
5. **Untrusted content stays untrusted.** Invoice and email values are `untrusted_external` until matched to a verified supplier-master record. A span match proves extraction consistency, never authenticity.
6. **Approval binds to the canonical digest.** Any material change, expiry, or revocation of supplier account, beneficiary status, mandate, approver permission or policy version voids execution eligibility, even if the signature is still valid.
7. **One permit, one execution.** Permit check and consumption happen in one database transaction with a conditional update.
8. **Separation of duties.** Requester, verifier, steward and payment approver are distinct people for the same supplier change.
9. **Simulation only.** No real payment rails, real bank APIs, real credentials, real PII or real money. Supplier verification is simulated and must be labeled so in UI, demo and README.
10. **Same policy everywhere.** Browser and backend load the same `policy.wasm`, identified by SHA-256. The OPA server fallback is never activated silently.

## 3. Scope guardrails (frozen in v3.1)

Do not build these, even if they seem helpful. Propose an ADR instead.

- Deferred: batch approval, counter-sign protocol compatibility, advanced graph views, extra AI models.
- Excluded: fraud ML trained on synthetic labels, graph ML, malware detonation, real-money execution, consumer banking, a runtime LLM judge, multi-tenancy, SSO.

Priorities: P0 = onboarding and bank changes, provenance, mandates, shared policy, approvals, protected execution, investigation UI, attack playground, invariants and Tracks B and C. P1 = recorded model attacks, AgentDojo reproduction, baseline comparisons.

## 4. Repository map

```
policy/        Rego source, policy tests, shared test vectors, build to dist/policy.wasm
backend/       Python 3.12, FastAPI, SQLAlchemy 2, Alembic; services, executor, tests
packages/      TypeScript shared code: policy-runtime, canonical (RFC 8785 + digest), ui
apps/web/      Next.js 16 full app (talks to backend)
apps/demo/     Next.js 16 static export for GitHub Pages (no backend)
scenarios/     Scenario templates, generator, frozen holdout manifest
eval/          Track A (AgentDojo), Track B (supplier integrity), Track C (authorization), baselines
docs/          Specification (source of truth)
```

Full layout and module responsibilities: `docs/ARCHITECTURE.md`.

## 5. Commands

Use these; add new ones to the root `Makefile` rather than documenting ad hoc commands.

```
make setup            # uv sync, pnpm install, pull pinned OPA binary, create .env from .env.example
make db-up            # docker compose up -d postgres
make policy-build     # opa build -t wasm, writes policy/dist/policy.wasm and policy.sha256
make policy-test      # opa test policy/ -v
make parity           # run shared vectors through Python (opa-py-wasm) and Node (opa-wasm); must match
make test-fast        # PR level: unit, policy, parity, regression, small Hypothesis budget
make test-deep        # nightly level: large Hypothesis budget, stateful, concurrency, adversarial stub
make mutation         # mutmut on backend/src/paylineage/{policy,approval,permit,executor}
make lint             # ruff, mypy --strict, eslint, tsc --noEmit
make dev              # backend + web locally
make demo             # build apps/demo static export with the current policy.wasm
```

Example: run one test file with `uv run pytest backend/tests/stateful/test_payment_machine.py -q`.

## 6. Definition of done for any change

- Tests written first or alongside; all of `make lint` and `make test-fast` pass.
- Any change to `policy/` rebuilds `policy.wasm`, updates `policy.sha256`, and passes `make parity`.
- Any change touching approval, permit, executor, onboarding or policy adds or updates tests mapped to the invariant IDs in `docs/SECURITY.md` (name tests `test_I5_...` style).
- Any bug found by Hypothesis is minimized and committed as an explicit test in `backend/tests/regression/`. The Hypothesis database alone does not count.
- New reason codes are added to `docs/DATA_MODEL.md` and to `policy/schema/`.
- No secrets, real account numbers or real company names in code, fixtures or logs. Account numbers are tokenized in logs.

## 7. Coding conventions

- Python: typed (`mypy --strict`), Pydantic v2 models at boundaries, money as integer minor units (`amount_minor: int`), never floats. UTC timestamps only.
- TypeScript: strict mode; no `any` in packages/.
- Canonical JSON: RFC 8785 in both languages (`rfc8785` in Python, `canonicalize` in TS). Cross-language digest vectors live in `policy/vectors/digest/`.
- Errors: domain errors map to explicit reason codes; never swallow exceptions in authorization code.
- IDs: UUIDv7 for records; never sequential IDs in URLs.
- Writing style for docs and UI copy: plain English, short sentences, no em dashes or en dashes.

## 8. Git and commits

- Author every commit as `Sheikh Robin Emon <semon@usf.edu>`.
- Do not add `Co-Authored-By` lines or any AI attribution to commits or PR descriptions.
- Conventional commits: `feat(policy): ...`, `fix(executor): ...`, `test(I5): ...`, `docs: ...`.
- Small commits per ticket. Reference the ticket ID, for example `feat(permit): atomic consume (T0.6)`.
- Never commit `.env`, keys, `policy/dist/` artifacts other than `policy.wasm` and `policy.sha256`, or model weights.

## 9. Local environment notes

- Target machine: 16 GB Apple Silicon Mac. Keep one LLM loaded at a time (Qwen3.5 4B via Ollama). Prompt Guard 2 (86M) runs on CPU.
- Llama Prompt Guard 2 is gated on Hugging Face; the owner must accept the license and set `HF_TOKEN`.
- The app and the public demo must work with no model running (recorded traces plus deterministic paths).
- WebAuthn works on `localhost` without TLS; do not disable origin checks.

## 10. When unsure

Ask a specific question with options. Do not guess on anything that touches money movement, trust, or the invariants.
