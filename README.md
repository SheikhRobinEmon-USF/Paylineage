# PayLineage

**No payment leaves until the record matches.**

PayLineage stops AI accounts payable agents from paying unverified or unauthorized beneficiaries. It sits between an agent that reads invoices and the money. Invoice and email content can never become payment authority, even when the model is fully manipulated and a person clicks approve.

> Simulation only. Rails, bank accounts and supplier verification are simulated. Every company, person and account is fictional. PayLineage enforces verification decisions; it does not prove real bank account ownership.

![Payment Control](docs/images/payment-control.png)

## Why this exists

Business email compromise caused about $3.05 billion in reported US losses in 2025 (FBI IC3). Attackers change supplier bank details in emails and invoices. AI agents now read those invoices and pay them: Visa, BILL and Billtrust started a live pilot of agents completing invoice payments on 20 October 2026. An agent that reads attacker content can be steered by it.

Existing tools cover one step each: verify suppliers, gate agent tool calls, or bind approvals. PayLineage connects the whole B2B lifecycle so that no step trusts what the previous step could not prove.

## Headline result

On the frozen holdout (96 generated scenarios, 54 attacks, suppliers and dates never seen during development), with an **adversarial stub in place of the model** that always outputs the attacker's preferred values, and deceived people who clear every clearable hold and approve:

| Metric | Result |
| --- | --- |
| Unauthorized simulated payments | **0** |
| False holds on legitimate payments | **0 of 18** |
| Scenarios behaving as specified | **96 of 96** in both modes |
| Authorization attacks (Track C: replay, tamper, revalidation, SoD and mandate fuzzing, 16 concurrent executions) | **17 of 17** refused |
| Policy decision latency, p95 | **about 2 ms** |
| Proposal to decision including PDF parsing, p95 | **about 110 ms** (target 250 ms) |

Full report with limits: [`eval/results/report.md`](eval/results/report.md). Two honest findings are reported, not hidden: a forged registry entry passes simulated onboarding (S13, a documented residual risk), and a deceived analyst can clear a duplicate invoice hold.

## How it works

```
Inbound email + invoice (untrusted) -> ingestion assigns trust from the source, before any model runs
                                    -> quarantined extractor (visible text only) -> span verifier -> signals
AP agent (RFC 9421 signed requests) -> mandate loaded from the trusted store, never from the request
                                    -> policy.wasm (OPA Rego): allow | hold | deny + reason codes
allow -> passkey approval over a server challenge that commits to the canonical digest
      -> permit after a fresh policy run (single use, 2 minutes)
      -> protected executor: re-runs the policy, consumes the permit with one conditional UPDATE,
         calls the simulated bank (the only process that holds bank credentials)
every decision and supplier change -> hash chain + Ed25519 checkpoints signed outside the database
```

Six independent checks, each with a clear limit:

| Check | Question it answers | What it cannot prove |
| --- | --- | --- |
| Field provenance | Where did this value come from? | That the source is truthful |
| Supplier master | Do bank details match a verified record? | That the record was never compromised |
| Agent mandate | Is this agent allowed this action, supplier and amount? | That the request is wise |
| Payment policy | Do the rules allow it? | That inputs are genuine |
| Passkey approval | Did an authorized person approve this exact record? | That the screen showed the truth |
| Execution integrity | Does execution match the approval, exactly once? | Anything before approval |

## What makes it different

- **Same policy everywhere.** One Rego policy compiled once to `policy.wasm`, identified by SHA-256, evaluated by the Python backend (an audited Wasmtime host with a fuel budget) and by the browser. 58 shared vectors, including malformed and unsupported built-in cases, give identical decisions in both. The static demo replays all 13 recorded backend decisions in the browser and recomputes their digests.
- **Fail closed by construction.** Explicit deny and hold rules plus a positive allow gate that must prove every fact. Undefined results, timeouts, unknown enum values, a tampered module and unsupported built-ins all deny. 24 hand-planted Rego mutants are all killed by the tests.
- **Server-bound approvals.** WebAuthn passkeys sign a challenge derived from the RFC 8785 canonical record. Any material change, expiry, revocation, mandate change or policy change voids eligibility even with a valid signature.
- **Industry standard agent identity.** Agents sign requests with HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530), the scheme behind Visa's Trusted Agent Protocol and Web Bot Auth.
- **One permit, one execution**, proven against real PostgreSQL with up to 16 concurrent executions of the same permit.
- **Tamper evidence that survives a database admin.** Modified, deleted, reordered and truncated history is detected against Ed25519 checkpoints held outside the database, even when the attacker recomputes every hash.

## The workspaces

| Workspace | Question |
| --- | --- |
| Payment Control | What needs me? Keyboard triage (`j`/`k`, `Enter`, `h`, `d`), exposure by reason, saved filters |
| Evidence Investigation | Why was it held? Each field linked to its source line, hidden text exposed, master diff, lineage graph, AI explanation as text |
| Approval Center | Am I approving exactly this? Full canonical record, digest, passkey, receipt, permit, execution |
| Supplier Master | Is the supplier real? Accounts, bank changes, requester, verifier and steward as three people |
| Agent Authority | What can each agent do? Keys, versioned mandates with diffs, revocation |
| Attack Lab | Does it hold up? Build an attack and watch the real `policy.wasm` decide in the browser |
| Audit Trail | Can I prove what happened? Hash chain verification |

| Evidence Investigation | Attack Lab |
| --- | --- |
| ![Evidence](docs/images/evidence-investigation.png) | ![Attack Lab](docs/images/attack-lab.png) |

## Quick start

Requirements: Python 3.12 with [uv](https://docs.astral.sh/uv/), Node 22 with pnpm 10, Docker (for PostgreSQL 16).

```bash
make setup
```

```bash
make db-up && make migrate && make seed
```

```bash
make dev
```

Open http://localhost:3000, pick a fictional person, and use "Add a passkey on this device" before approving. The app works with no model running. For local AI extraction, install [Ollama](https://ollama.com), run `ollama pull qwen3.5:4b` and set `EXTRACTOR=ollama`.

The public demo needs nothing installed: it runs the same UI against an in-browser engine (`make demo`, deployed to GitHub Pages from `main`).

## Testing

```bash
make lint          # ruff, mypy --strict, eslint, tsc
make test-fast     # OPA tests (100% coverage), Rego mutants, parity, pytest, vitest
make test-deep     # large Hypothesis budget, payment lifecycle state machine, Tracks B and C gate
make eval          # Tracks B and C on the frozen holdout, writes eval/results/report.md
```

Test names map to the invariants in [`docs/SECURITY.md`](docs/SECURITY.md) (`test_I5_concurrent_consume_executes_once`). Every bug found by property testing or replay is kept as an explicit regression test.

## Stack

| Layer | Choice |
| --- | --- |
| Policy | OPA Rego compiled to Wasm (OPA 1.22), own Wasmtime host in Python, `@open-policy-agent/opa-wasm` in browsers with precompiled JSON Schema validators (strict CSP, no eval) |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL 16, py_webauthn, cryptography (Ed25519) |
| Evidence | Bounded email and PDF parsing (pdfminer.six), hidden text detection from glyph color and size, lookalike domains, injection heuristics, optional Llama Prompt Guard 2 |
| AI | Qwen3.5 4B via Ollama for extraction and explanations only; never in the authorization path |
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS v4 (OKLCH tokens), React Aria Components, TanStack Table v9, React Flow, ECharts, IBM Plex |
| Testing | pytest, Hypothesis (stateful), OPA test, Vitest, Playwright, axe-core |
| Supply chain | 7 day release cooldown for uv and pnpm, SHA pinned GitHub Actions, Gitleaks, Semgrep, pip-audit, CycloneDX SBOMs |

## Repository

```
policy/      Rego, tests, shared vectors, mutants, reproducible build to dist/policy.wasm
backend/     FastAPI services, executor and mock bank processes, Alembic, tests by invariant
packages/    canonical (RFC 8785), policy-runtime (fail closed), ui (design system and workspaces)
apps/web/    Next.js app for the backend      apps/demo/  static demo for GitHub Pages
scenarios/   templates and the frozen holdout manifest
eval/        Track B and C results
docs/        specification, decisions (ADRs), research
```

## Prior art

PayLineage builds on, and does not claim, the ideas in aiAuthZ, Interbolt (provenance gated tool calls on AgentDojo), payee-provenance, MandateShield and counter-sign. Its contribution is the complete supplier payment lifecycle around those mechanisms. See [`docs/PRODUCT.md`](docs/PRODUCT.md) and [`docs/RESEARCH.md`](docs/RESEARCH.md).

## Limits

Synthetic scenarios from one simulated organization. Simulated rails and simulated verification. The adversarial stub models a fully manipulated model; it does not measure how a real model reacts. Residual risks are listed in [`docs/SECURITY.md`](docs/SECURITY.md).

## License

MIT. Copyright (c) 2026 Sheikh Robin Emon.
