# PayLineage decision entrypoint.
#
# Contract (see policy/schema/output.v1.json):
#   {"decision": "allow" | "hold" | "deny", "reasons": [codes], "policy_version": "..."}
#
# Fail closed by construction:
#   * the default decision is deny with POLICY_UNDEFINED;
#   * "allow" needs zero deny reasons, zero hold reasons AND a positive allow gate
#     that proves every required fact. A missing fact can never become allow.
#   * every rule only uses Wasm native built-ins (count, sort, set and array ops,
#     comparisons). CI checks the compiled module needs no host built-ins.
package paylineage

import rego.v1

cfg := data.config

default decision := {"decision": "deny", "reasons": ["POLICY_UNDEFINED"], "policy_version": "unknown"}

decision := _result(payment_deny, payment_hold, payment_allow_gate) if {
	input.request_kind == "payment"
}

decision := _result(onboarding_deny, onboarding_hold, onboarding_allow_gate) if {
	input.request_kind == "onboarding"
}

_result(deny, hold, gate) := {
	"decision": _outcome(deny, hold, gate),
	"reasons": sort(((deny | hold) | _gate_missing(deny, hold, gate))),
	"policy_version": cfg.policy_version,
}

_outcome(deny, hold, gate) := "deny" if {
	count(deny) > 0
} else := "hold" if {
	count(hold) > 0
} else := "allow" if {
	gate == true
} else := "deny"

# When nothing explains a failed allow gate, say so explicitly.
_gate_missing(deny, hold, gate) := {"POLICY_UNDEFINED"} if {
	count(deny) == 0
	count(hold) == 0
	gate != true
} else := set()

# ---------- shared helpers ----------

now := input.now_ms

severity_rank(s) := cfg.signal_severity_rank[s]

hold_min_rank := cfg.signal_severity_rank[cfg.signal_hold_min_severity]
