package paylineage_test

import rego.v1

verification := {
	"method": "callback_on_file",
	"contact_source": "on_file",
	"contact_recorded_at_ms": now_ms - (90 * day_ms),
	"request_created_at_ms": now_ms - day_ms,
	"registry_match": true,
	"bank_confirmed": true,
}

onb(overrides) := {
	"schema_version": "1",
	"request_kind": "onboarding",
	"now_ms": now_ms,
	"onboarding": object.union(
		{
			"action": "record_verification",
			"kind": "bank_change",
			"actor_id": "u-ver-1",
			"actor_roles": ["verifier"],
			"supplier_id": "sup-acme",
			"requester_id": "u-ap-1",
			"verifier_id": "u-ver-1",
			"assignee_id": null,
			"verification": verification,
		},
		overrides,
	),
}

test_I7_assigned_verifier_records_verification if {
	decided(onb({}), "allow")
}

test_I7_unassigned_verifier_denied if {
	has(onb({"actor_id": "u-ver-2"}), "VERIFIER_NOT_ASSIGNED")
}

test_I7_requester_cannot_verify_own_request if {
	inp := onb({"actor_id": "u-ap-1", "verifier_id": "u-ap-1", "actor_roles": ["verifier", "ap_specialist"]})
	has(inp, "SOD_VIOLATION")
	decided(inp, "deny")
}

test_I7_wrong_role_denied if {
	has(onb({"actor_roles": ["ap_specialist"]}), "ROLE_REQUIRED")
}

test_I7_steward_cannot_assign_requester if {
	inp := onb({"action": "assign_verifier", "actor_id": "u-stw-1", "actor_roles": ["steward"], "assignee_id": "u-ap-1", "verifier_id": null})
	has(inp, "SOD_VIOLATION")
}

test_I7_steward_cannot_assign_self if {
	inp := onb({"action": "assign_verifier", "actor_id": "u-stw-1", "actor_roles": ["steward"], "assignee_id": "u-stw-1", "verifier_id": null})
	has(inp, "SOD_VIOLATION")
}

test_steward_assigns_other_verifier if {
	inp := onb({"action": "assign_verifier", "actor_id": "u-stw-1", "actor_roles": ["steward"], "assignee_id": "u-ver-1", "verifier_id": null})
	decided(inp, "allow")
}

test_I7_steward_cannot_be_verifier if {
	inp := onb({"action": "steward_approve", "actor_id": "u-ver-1", "actor_roles": ["steward", "verifier"]})
	has(inp, "SOD_VIOLATION")
}

test_steward_approves_after_verification if {
	decided(onb({"action": "steward_approve", "actor_id": "u-stw-1", "actor_roles": ["steward"]}), "allow")
}

test_S1_callback_to_invoice_contact_rejected if {
	v := object.union(verification, {"contact_source": "invoice"})
	has(onb({"verification": v}), "VERIFICATION_CONTACT_INVALID")
}

test_contact_recorded_after_request_rejected if {
	v := object.union(verification, {"contact_recorded_at_ms": now_ms})
	has(onb({"verification": v}), "VERIFICATION_CONTACT_INVALID")
}

test_simulated_validation_service_accepted if {
	v := object.union(verification, {"method": "simulated_validation_service", "contact_source": "none", "contact_recorded_at_ms": null})
	decided(onb({"verification": v}), "allow")
}

test_failed_bank_confirmation_denied if {
	v := object.union(verification, {"bank_confirmed": false})
	has(onb({"verification": v}), "VERIFICATION_FAILED")
}

test_missing_verification_evidence_denied if {
	has(onb({"verification": null}), "EVIDENCE_MISSING")
}

test_request_supplier_by_ap_specialist if {
	decided(onb({"action": "request_supplier", "actor_id": "u-ap-1", "actor_roles": ["ap_specialist"], "verification": null}), "allow")
}

test_assign_without_assignee_denied if {
	inp := onb({"action": "assign_verifier", "actor_id": "u-stw-1", "actor_roles": ["steward"], "assignee_id": null, "verifier_id": null})
	has(inp, "INPUT_INVALID")
}

test_failed_registry_match_denied if {
	v := object.union(verification, {"registry_match": false})
	has(onb({"verification": v}), "VERIFICATION_FAILED")
}
