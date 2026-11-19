# Evaluation

## Tracks

| Track | Priority | Tests | Metrics | Gate (proposed) |
| --- | --- | --- | --- | --- |
| A. AgentDojo banking | P1 | Pinned v1.2.x banking suite, fixed attack and model settings | Attack success, benign utility, utility under attack, 95% intervals | Reproduce Interbolt's published result as baseline; report ours beside it |
| B. Supplier payment integrity | P0 | S1 to S9, S13, L1 to L3 and generated variants | Unauthorized payments, missed substitutions, false holds, loss-weighted misses, analyst minutes per case | Zero unauthorized on holdout; false holds under 5% |
| C. Authorization security | P0 | S10 to S12, R1 revalidation, tamper, replay, concurrency, escalation fuzzing | Bypasses, double executions, mismatches | Zero; deterministic in CI |

Baselines (P1, only where comparable): Interbolt, payee-provenance (MIT, runnable), aiAuthZ. State where problem definitions differ.

## Rules for honest numbers

1. Pin benchmark versions, attack sets and model settings before comparing.
2. Freeze holdout before tuning; split by template, supplier and time.
3. Layer ablation: none, provenance only, + supplier master, + mandate, full.
4. Latency p50, p95, p99 for the model-free path (target p95 under 250 ms) separately from LLM extraction.
5. Adversarial stub: replace the LLM with a stub that always outputs attacker-preferred values. Tracks B and C must still pass. This is the headline claim.
6. Limits section: synthetic data, single organization, simulated rails, simulated verification.

## Testing levels

| Level | When | Runs |
| --- | --- | --- |
| Fast | Every PR | unit, OPA tests, parity, regression, about 200 Hypothesis examples per property |
| Deep | Nightly, pre-release | thousands of examples, `RuleBasedStateMachine` sequences, concurrency, adversarial stub, fault injection |
| Mutation | Weekly, pre-release | mutmut on policy adapter, approvals, permits, executor; hand-planted Rego mutants; every critical mutant killed |

Example stateful sequence: create supplier, request bank change, approve payment, revoke approval, restore old details, execute twice concurrently.

Regression rule: every failure is minimized and committed to `backend/tests/regression/` with the invariant ID in the name.

## Attack Lab modes (public demo)

| Mode | Shows | Must not claim |
| --- | --- | --- |
| A. Recorded model attacks (P1) | Real captured tool call from a local run; unprotected vs live policy on the same proposal | Attacker success the model never produced |
| B. Build your own attack (P0) | Edits to invoice text, hidden instructions, beneficiary, proposed action; I2 holds live | How a model would react to new text |
