# Research notes

Research done on 19 November 2026 to check the spec's claims, choose current technology, and find what the plan missed. Sources are listed per claim. Secondary sources are marked; confirm against the primary text before citing externally.

## 1. The problem is real and timely

| Claim | Status | Source |
| --- | --- | --- |
| BEC caused about $3.05 billion in reported US losses in 2025 | Confirmed ($3,046,598,558 from 24,768 complaints; second only to investment fraud) | FBI IC3 2025 report (reproduced PDF), JD Supra, SecurityWeek |
| Visa, BILL and Billtrust launched a live agent invoice payment pilot on 20 October 2026 | Confirmed. BILL's Payment Agent uses Visa's Trusted Agent Protocol; the buyer approves, the agent executes | Visa newsroom, Electronic Payments International, CFOtech |
| Nacha 2026 rules require risk based monitoring for "false pretenses" (BEC, vendor impersonation) | Confirmed. Phase 1 for ODFIs from 20 March 2026; phase 2 for other originators from 19 June 2026; R17 return code covers false pretenses | Nacha, American Banker, Eftsure (secondary) |
| EU Verification of Payee is live | Confirmed since 9 October 2025 (Instant Payments Regulation 2024/886): match, close match, no match, not possible | EPC, KPMG, PwC Legal (secondary) |
| OWASP Top 10 for Agentic Applications | Published 9 December 2025. ASI01 agent goal hijack, ASI02 tool misuse | Cycode, SecureW2 (secondary) |
| Tool description poisoning | Microsoft warned on 30 June 2026 (demonstration included an invoice workflow); no confirmed in the wild payment case found | TechRepublic, CSA research note |
| Deepfake voice against callbacks | Vendors report cloned executive voices used to push bank changes; numbers vary and are hard to trace | Corpay (vendor content) |
| Baseline projects exist | Confirmed on GitHub: `Sports-Vision-Inc/aiAuthZ`, `deconvolute-labs/interbolt-agentdojo`, `Alkur123/payee-provenance`, several `mandateshield` repositories | GitHub search |

## 2. Is PayLineage the best project for this goal?

Goal: impactful, technical, secure, AI oriented with free models, solves a current business problem in AI security and fraud, and strengthens a CV.

Alternatives considered:

| Idea | Strength | Why it ranks below PayLineage |
| --- | --- | --- |
| MCP gateway firewall for agent tool calls | Hot topic, broad | Crowded; hard to show measurable outcomes; no money flow to anchor invariants |
| Deepfake resistant vendor verification | Real pain | Detection of synthetic voice is an arms race; claims are hard to evaluate honestly with free models |
| Agent payment mandate verifier (AP2 style) for consumer checkout | Timely | Consumer focus; card networks are building this themselves |
| LLM phishing email classifier | Easy to demo | Excluded by the spec (synthetic label ML); weak novelty |

PayLineage wins on four points. It has a precise threat (untrusted content becoming payment authority), measurable invariants that can be proven with tests, a regulatory tailwind (Nacha 2026, EU VoP), and market timing (agents paying invoices went live in October 2026). It also shows breadth across policy as code, cryptography, databases, AI safety and product design.

## 3. Technology choices (checked against current releases)

- Next.js 16.4 and React 19.3 (the same base as Hospital Ops Copilot) with a different design language: light first, ledger style, IBM Plex, OKLCH tokens, React Aria Components for accessibility, TanStack Table v9, React Flow, ECharts.
- OPA 1.22 pinned by checksum. The PyPI `opa-wasm` SDK needs wasmer and Python 3.10 or older, so the backend uses its own Wasmtime host with a fuel budget (ADR-010).
- TypeScript is pinned to 6.0.3: typescript-eslint does not support TypeScript 7 yet.
- Supply chain: uv `exclude-newer` and pnpm `minimumReleaseAge` enforce a 7 day cooldown; GitHub Actions are pinned to commit SHAs.

## 4. What the plan missed, and what was done about it

| Gap | Action |
| --- | --- |
| `CLAUDE.md` pointed at `docs/PRD.md`, which did not exist | Written with FR1 to FR22 (T0.10) |
| Spec asked S2 to hold but S9 to deny for the same "account not in master" | Resolved by provenance: `agent_asserted` values deny (ADR-011) |
| RFC 8785 alone does not give identical accept or reject in Python and JS for large numbers | I-JSON number profile in both languages (ADR-012) |
| OPA bundle data sits outside `policy.wasm`, so one hash would not cover thresholds | Config compiled into the module (ADR-013) |
| A bank change that moves the supplier out of `verified` would freeze the still valid old account | Bank changes run as a case; supplier stays verified (ADR-014) |
| "Ed25519 request verification" had no wire format | HTTP Message Signatures, RFC 9421 (ADR-015), aligned with Visa TAP and Web Bot Auth |
| Strict CSP blocks the JSON Schema validator in browsers (it uses `new Function`) | Validators precompiled at build time, tested for equivalence and drift |
| The requested agent operation was not recorded with its decision | Found by the demo's replay check; fixed with a regression test |
| A stored digest was computed before the row id existed | Found by the Hypothesis state machine; fixed with a regression test |
| A wildcard mandate scope failed the input schema | Found by an integration test; fixed with a regression test and vectors |

Not built, worth considering (each needs an ADR because it changes scope):

1. **Verification of Payee as a verification method.** A simulated VoP check (match, close match, no match) fits the onboarding workflow and maps directly to EU practice.
2. **Nacha 2026 mapping.** A short document showing how PayLineage evidence supports "false pretenses" monitoring would help buyers.
3. **Callback hardening against voice cloning.** Require the callback to be placed by us to a number on file, plus a second channel, before a bank change verifies. The current model already rejects contacts from invoices and emails.
4. **OWASP Agentic Top 10 mapping.** ASI01 goal hijack maps to I1, ASI02 tool misuse to I10, identity and privilege abuse to RFC 9421 plus mandates.

## 5. Decisions only the owner can make

- Accept or change ADR-010 to ADR-015 (all "Proposed").
- Enable GitHub Pages for the repository (Settings, Pages, Source: GitHub Actions).
- Accept the Llama Prompt Guard 2 licence and set `HF_TOKEN` if the optional model detector is wanted.
- Make sure `semon@usf.edu` is a verified email on your GitHub account so commits are attributed to you.
- Name check: ADR-009 notes closeness to the "Payline" brand.
