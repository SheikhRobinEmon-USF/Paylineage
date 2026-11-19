# Product

## One line

PayLineage stops AI accounts-payable agents from sending payments to unverified or unauthorized beneficiaries.

## Problem

Business email compromise caused about $3.05 billion in reported US losses in 2025 (FBI IC3). Attackers change supplier bank details in emails and invoices. AI agents now read those invoices and propose payments (Visa, BILL and Billtrust started a live agent invoice-payment pilot on 20 Oct 2026). Prompt injection in banking assistants is documented (Bunq via a EUR 0.02 transfer reference; a bank chatbot XSS via a PDF and two 1-cent transfers).

The gap: existing tools either verify suppliers, or gate agent tool calls, or bind approvals. PayLineage connects the whole lifecycle so untrusted invoice content can never become payment authority.

## What already exists (do not claim these as novel)

| Project | What it covers |
| --- | --- |
| aiAuthZ | Off-host authorization; blocks attacker calls on AgentDojo banking, at the cost of one legitimate first-time payment |
| Interbolt (AgentDojo harness) | Provenance-gated tool calls; 0 of 144 attacks on AgentDojo banking (two repeats) |
| payee-provenance | Deterministic payee-source gate for consumer payments, single-use tokens, hold periods |
| MandateShield | Binds signed approval to the exact Stripe PaymentIntent; single-use permit |
| counter-sign | Open protocol: agent signs intent, human countersigns |

## PayLineage's contribution

The complete B2B supplier-payment lifecycle around those mechanisms:

1. New-supplier onboarding and bank-change verification with separation of duties.
2. Field-level provenance from financial documents.
3. Agent mandates (versioned delegations of authority).
4. Human approval bound to a canonical payment digest.
5. Protected, single-use execution with revalidation.
6. An evidence-first investigation workspace and an interactive attack playground.
7. Evaluation against the projects above as baselines.

## Personas

| Persona | Job | Main workspace |
| --- | --- | --- |
| AP specialist | Process agent-proposed invoices | Payment Control |
| Finance approver | Approve payments | Approval Center |
| Vendor data steward | Own supplier master, approve bank changes | Evidence Investigation (suppliers) |
| Fraud or security analyst | Investigate holds and denials | Evidence Investigation |
| AP platform engineer | Put an existing agent behind PayLineage | Agent Authority, API docs |

## Outcome metrics

Unauthorized simulated payments, false holds on legitimate payments, approval bypasses, analyst minutes per case, model-free decision latency. Simulated dollars blocked are reported as scenario exposure, never savings.

## Honesty rules for all copy

- Supplier verification is simulated. PayLineage enforces verification decisions; it does not prove real bank-account ownership.
- Browser demo artifacts are "valid" (math checks out), never "trusted".
- Recorded model traces are labeled with model id, digest and date.
