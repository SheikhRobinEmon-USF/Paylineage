# UI and UX

Evidence first, not chat first. The home screen answers: what is risky, how much money is exposed, why it was held, what action is needed.

## Workspaces

| Workspace | Question | Key interactions | Failure states to design |
| --- | --- | --- | --- |
| Payment Control (home) | What needs me? | Queue (allow, hold, deny), exposure total, keyboard triage (j/k, h hold, d deny, enter open), saved filters | Policy unavailable banner (all deny), empty queue |
| Evidence Investigation | Why held, is the supplier real? | Invoice viewer with each field linked to its source span; side-by-side diff vs supplier master; reason codes; timeline; supplier change queue showing changer and verifier; AI panel (explain case, draft note) | Extraction inconsistent, verification timeout |
| Approval Center | Am I approving exactly this? | Full canonical record and digest; passkey prompt; decision receipt; one payment at a time | Expired approval, revoked mandate, digest changed |
| Agent Authority | What can each agent do? | Registry, keys, mandate editor with version diff, revoke, policy versions with test results | Revocation confirmation |
| Attack Lab | Does it hold up? | Scenario picker, run with and without protection on the same seed, state machine stepper, build-your-own invoice editor | Mode labels always visible |

## Design rules

- IBM Plex Sans; Plex Mono for ids, amounts, digests. Tabular figures; amounts right aligned with currency code.
- Status = word + icon + color. Colors: allowed (green), hold (amber), denied (red), untrusted origin (violet dotted underline wherever such a value appears).
- One token set (OKLCH) for light and dark.
- Model and document text always rendered as text, never HTML.
- WCAG 2.2 AA: keyboard reachable, visible focus, accessible authentication, no color-only meaning. axe-core in Playwright.

## Public demo (apps/demo, GitHub Pages)

| Runs live in browser | Replayed, labeled | Full app only |
| --- | --- | --- |
| policy.wasm (same SHA-256 as backend) | LLM extraction outputs with model id and date | Ollama extraction, AI panel |
| RFC 8785 + SHA-256 (Web Crypto) | Unprotected agent behavior from real runs | Server-side WebAuthn, real passkeys |
| Provenance tagging, master comparison, state machine, permits (in memory), hash chain (IndexedDB) | AgentDojo results | Postgres, multi-user roles |
| Build-your-own attack editor | | |

Every artifact shows a badge: "valid" (math checks out) or "trusted" (verified by an independent authority). Nothing in the browser is ever "trusted". A banner states which parts are live, replayed or simulated.
