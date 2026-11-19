# Supplier onboarding and bank change: roles and separation of duties (I7).
# The state machine (backend/src/paylineage/onboarding/machine.py) owns which
# transitions exist. This module answers whether this actor may perform this
# action now, with this evidence.
package paylineage

import rego.v1

o := input.onboarding

required_role := cfg.onboarding_roles[o.action]

actor_has_role if {
	required_role in o.actor_roles
}

onboarding_deny contains "ROLE_REQUIRED" if {
	not actor_has_role
}

# The requester can never verify, assign, approve or reject their own request.
onboarding_deny contains "SOD_VIOLATION" if {
	o.action in {"assign_verifier", "record_verification", "steward_approve", "reject"}
	o.requester_id != null
	o.actor_id == o.requester_id
}

onboarding_deny contains "SOD_VIOLATION" if {
	o.action == "assign_verifier"
	o.assignee_id == o.requester_id
}

onboarding_deny contains "SOD_VIOLATION" if {
	o.action == "assign_verifier"
	o.assignee_id == o.actor_id
}

onboarding_deny contains "SOD_VIOLATION" if {
	o.action == "steward_approve"
	o.actor_id == o.verifier_id
}

onboarding_deny contains "VERIFIER_NOT_ASSIGNED" if {
	o.action == "record_verification"
	o.actor_id != o.verifier_id
}

onboarding_deny contains "INPUT_INVALID" if {
	o.action == "assign_verifier"
	o.assignee_id == null
}

# ---------- verification evidence ----------

v := o.verification

verification_present if {
	v != null
}

onboarding_deny contains "EVIDENCE_MISSING" if {
	o.action in {"record_verification", "steward_approve"}
	not verification_present
}

# Callback must use a contact that was on file before the request existed.
# Contacts from the invoice or email are attacker controlled.
contact_valid if {
	v.method == "callback_on_file"
	v.contact_source == "on_file"
	v.contact_recorded_at_ms != null
	v.contact_recorded_at_ms < v.request_created_at_ms
}

contact_valid if {
	v.method == "simulated_validation_service"
}

onboarding_deny contains "VERIFICATION_CONTACT_INVALID" if {
	o.action in {"record_verification", "steward_approve"}
	verification_present
	not contact_valid
}

onboarding_deny contains "VERIFICATION_FAILED" if {
	o.action in {"record_verification", "steward_approve"}
	verification_present
	v.registry_match != true
}

onboarding_deny contains "VERIFICATION_FAILED" if {
	o.action in {"record_verification", "steward_approve"}
	verification_present
	v.bank_confirmed != true
}

verification_gate if {
	not o.action in {"record_verification", "steward_approve"}
}

verification_gate if {
	o.action in {"record_verification", "steward_approve"}
	verification_present
	contact_valid
	v.registry_match == true
	v.bank_confirmed == true
}

default onboarding_allow_gate := false

onboarding_allow_gate if {
	actor_has_role
	verification_gate
}

# Onboarding never produces holds; it is permitted or not.
onboarding_hold := set()
