# Architecture

## Request path

```
Inbound email + invoices (untrusted) -> Evidence layer (ingestion, extraction, provenance, signals)
AP agent (signed requests)           -> Agent authority (identity, mandates)
Finance staff                        -> Supplier master (verified accounts, dual-control changes)

Evidence + Authority + Supplier master -> Policy engine (OPA, fail closed): allow | hold | deny + reason codes
allow/hold -> Approval service (canonical digest, passkey) -> Permit service (single use)
           -> Protected executor (revalidate + atomic consume) -> Mock bank (simulated funds)
every decision -> Audit service (hash chain + signed external checkpoints)
```

## Component responsibilities

| Component | Owns | Never does |
| --- | --- | --- |
| Ingestion | Source, transport metadata, file digest, trust class | Call an LLM before trust class is assigned |
| Extractor (LLM, quarantined role) | Typed field values + claimed location | See tool definitions or user instructions; set trust |
| Span verifier | Check value appears at claimed location; mark `consistent` or `inconsistent` | Treat consistency as authenticity |
| Planner (LLM, privileged role) | Propose actions from user task + typed fields | Read raw document text |
| Policy engine (policy.wasm) | Decide permitted or not, with reason codes | Hold state; default to allow |
| PostgreSQL | Authoritative suppliers, payments, approvals, mandates, permits | |
| Transaction service | Valid state transitions, optimistic locking, idempotency | Skip version checks |
| Approval service | Server-issued WebAuthn challenge over digest; verify assertion | Accept client-computed digests |
| Permit service | Issue single-use, expiring permit after re-running policy | Issue without fresh policy run |
| Protected executor | Revalidate everything, consume permit atomically, call mock bank | Accept anything except a valid unconsumed permit |
| Audit service | Append events, hash chain, signed checkpoints to external file | Rewrite history |

The executor process is the only holder of mock-bank credentials. The agent process has no network route to the mock bank (enforced in docker compose networks; tested for I6).

## Shared policy engine

1. Rego in `policy/paylineage/`, unit tests in `policy/tests/`.
2. Pinned OPA version in `policy/OPA_VERSION`. `make policy-build` runs `opa build -t wasm -e paylineage/decision` and writes `policy/dist/policy.wasm` and `policy.sha256`.
3. Backend loads it in process with `opa-py-wasm` (Wasmtime). Browser loads it with `@open-policy-agent/opa-wasm`.
4. Input contract: `policy/schema/input.v1.json` (JSON Schema). Both runtimes validate input against it before evaluation; invalid input means deny.
5. Policy data (thresholds, cooling-off settings, role rules) in `policy/data/` versioned with the policy; hash recorded alongside.
6. Shared vectors in `policy/vectors/` (input, expected decision, expected reason codes). `make parity` runs them in both runtimes; any mismatch fails CI.
7. Use only Rego built-ins supported in Wasm. CI greps the compiled capabilities list.
8. OPA server fallback: only via explicit `POLICY_RUNTIME=opa-server` plus matching `policy.sha256` plus passing parity. Otherwise a Wasm failure means deny.
9. Output contract: `{ "decision": "allow" | "hold" | "deny", "reasons": [codes], "policy_version": "...", "policy_sha256": "..." }`. Undefined or malformed output means deny.

## Repository layout

```
policy/
  OPA_VERSION
  paylineage/decision.rego, onboarding.rego, mandate.rego, provenance.rego
  data/config.v1.json
  schema/input.v1.json, output.v1.json
  tests/*_test.rego
  vectors/decision/*.json, vectors/digest/*.json
  dist/policy.wasm, policy.sha256
backend/
  pyproject.toml, uv.lock, alembic/
  src/paylineage/
    api/            FastAPI routers (agents, invoices, payments, approvals, suppliers, cases, audit)
    domain/         Pydantic models, enums, reason codes
    policy/         runtime adapter (opa-py-wasm), input builder, fallback guard
    canonical/      RFC 8785 + SHA-256 digest
    ingestion/      email and PDF parsing, transport metadata, trust class
    extraction/     LLM extractor client, span verifier
    signals/        lookalike domain, auth results, reply-to, hidden text, Prompt Guard
    onboarding/     supplier state machine, verification tasks, cooling-off
    payments/       payment state machine, transaction service
    approvals/      WebAuthn challenge and verification
    permits/        issue and consume
    executor/       protected executor (separate process entrypoint)
    mockbank/       simulated rails (separate process)
    audit/          event log, hash chain, checkpoint signer and verifier
    agents/         agent registry, Ed25519 request verification, mandates
  tests/ unit/ property/ stateful/ concurrency/ regression/ adversarial/ isolation/
packages/
  canonical/        RFC 8785 + digest (TS), shares vectors with Python
  policy-runtime/   loads policy.wasm, validates input, fail-closed wrapper
  ui/               design tokens, components (React Aria based)
apps/
  web/              Next.js 16 full app
  demo/             Next.js 16 static export (GitHub Pages)
scenarios/          templates/, generator/, holdout.lock.json
eval/               track_a_agentdojo/, track_b_supplier/, track_c_authz/, baselines/
```

## Stack

| Layer | Choice |
| --- | --- |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, psycopg 3 |
| DB | PostgreSQL 16+ (docker), outbox table for async events |
| Policy | OPA Rego to Wasm; opa-py-wasm; @open-policy-agent/opa-wasm |
| Crypto | rfc8785 / canonicalize; SHA-256; Ed25519 (cryptography / Web Crypto); py_webauthn + @simplewebauthn/browser |
| AI | Ollama Qwen3.5 4B (extraction, explanations); Llama Prompt Guard 2 86M (CPU) |
| Frontend | Next.js 16 (patched), React 19, TypeScript strict, Tailwind v4, React Aria Components, TanStack Table, React Flow, ECharts |
| Testing | pytest, Hypothesis (incl. stateful), mutmut, Vitest, Playwright, axe-core |
| Quality | ruff, mypy, eslint, Semgrep, Trivy, Gitleaks, Dependabot, CycloneDX |
| Delivery | Docker Compose, GitHub Actions, GitHub Pages (demo) |

Verify each package's current version and license at install time; pin exact versions in lockfiles.
