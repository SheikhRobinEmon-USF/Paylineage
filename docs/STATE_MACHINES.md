# State machines

Both machines are implemented as explicit transition tables in code (`payments/machine.py`, `onboarding/machine.py`) and tested with Hypothesis `RuleBasedStateMachine`. Any transition not listed is rejected.

## Payment

States: Proposed, Evaluated, Held, Denied, AwaitingApproval, Approved, PermitIssued, Executed, Expired.
Terminal: Denied, Expired, Executed.

| From | To | Guard |
| --- | --- | --- |
| Proposed | Evaluated | Agent Ed25519 signature valid; mandate loaded from trusted store |
| Evaluated | Denied | Mandate or policy violation |
| Evaluated | Held | Unverified or changed beneficiary, untrusted material field, duplicate, signal threshold |
| Evaluated | AwaitingApproval | No holds; all material fields trace to verified sources |
| Held | AwaitingApproval | Out-of-band verification completed by someone other than requester and approver |
| Held | Denied | Verification fails or case closed as fraud |
| AwaitingApproval | Approved | Passkey assertion over server-issued challenge for this digest; approver not the bank-detail changer |
| Approved | PermitIssued | Policy re-run now; approval unexpired; digest unchanged; supplier account, mandate and approver permissions still valid |
| PermitIssued | Executed | Executor revalidates and consumes permit atomically |
| AwaitingApproval, Approved | Evaluated | Material change; version += 1; approval void |
| Approved | Expired | Approval past expiry |

Execution-time revalidation example (test R1 in Track C): approved 10:00, mandate revoked 10:01, execution attempt 10:02 must be rejected although the signature is valid. Repeat for supplier record, beneficiary status, approver permission, policy version.

## Supplier onboarding and bank change

States: Requested, Unverified, Verifying, StewardReview, Verified, Rejected (plus account-level: pending, verified, suspended, revoked).

| Transition | Who | Evidence |
| --- | --- | --- |
| Requested to Unverified | AP specialist, or created from an invoice | Record exists, not payable; invoice data untrusted |
| Unverified to Verifying | Steward assigns verifier | Verifier is not requester |
| Verifying to StewardReview | Verifier | Identity vs simulated business registry; bank confirmation via contact on file that predates the request, or simulated validation service. Never contacts from invoice or email |
| StewardReview to Verified | Steward | Steward is not verifier; for bank changes, risk-based cooling-off must also pass |
| Verifying or StewardReview to Rejected | Verifier or steward | Failed or inconsistent verification; case opened |
| Verified to Verifying | Anyone recording a claimed bank change | New account pending |

Old and new accounts during a bank change:

| Situation | Treatment |
| --- | --- |
| Ordinary update, old account confirmed still valid | Old account may stay payable per policy data |
| Old account reported compromised, closed or disputed | Old account suspended immediately |
| New account verified, cooling-off incomplete | New account ineligible |

Cooling-off is configurable in `policy/data/config.v1.json`. A timer never replaces verification.

Cross-workflow rule: for a configurable window after verifying a supplier's account, the verifier and steward cannot approve payments to that supplier (I7).
