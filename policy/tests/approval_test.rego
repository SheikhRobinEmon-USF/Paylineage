package paylineage_test

import rego.v1

test_I3_valid_approval_allows_permit if {
	decided(permit_stage({}), "allow")
}

test_I3_no_approval_denies_permit if {
	has(permit_stage({"approvals": []}), "APPROVAL_MISSING")
	decided(permit_stage({"approvals": []}), "deny")
}

test_S10_I3_digest_changed_after_approval_denies if {
	inp := object.union(permit_stage({}), {"payment": {"record": object.union(payment.record, {"digest": digest_b})}})
	has(inp, "APPROVAL_DIGEST_MISMATCH")
	decided(inp, "deny")
}

test_I3_version_changed_after_approval_denies if {
	a := object.union(approval("apr-1", "u-fin-1"), {"payment_version": 2})
	has(permit_stage({"approvals": [a]}), "APPROVAL_DIGEST_MISMATCH")
}

test_S12_I4_expired_approval_denies if {
	a := object.union(approval("apr-1", "u-fin-1"), {"expires_at_ms": now_ms})
	has(permit_stage({"approvals": [a]}), "APPROVAL_EXPIRED")
	decided(permit_stage({"approvals": [a]}), "deny")
}

test_I4_revoked_approval_denies if {
	a := object.union(approval("apr-1", "u-fin-1"), {"revoked": true})
	has(permit_stage({"approvals": [a]}), "APPROVAL_REVOKED")
}

test_I4_approver_permission_revoked_denies if {
	a := object.union(approval("apr-1", "u-fin-1"), {"approver_active": false})
	has(permit_stage({"approvals": [a]}), "APPROVER_NOT_AUTHORIZED")
}

test_I3_approver_without_role_denies if {
	a := object.union(approval("apr-1", "u-fin-1"), {"approver_roles": ["ap_specialist"]})
	has(permit_stage({"approvals": [a]}), "APPROVER_NOT_AUTHORIZED")
}

test_S12_I7_approver_who_changed_bank_details_denies if {
	ch := [{"actor_id": "u-fin-1", "role": "bank_change_recorder", "at_ms": now_ms - 1000}]
	has(permit_stage({"supplier_changes": ch}), "SOD_VIOLATION")
	decided(permit_stage({"supplier_changes": ch}), "deny")
}

test_I7_verifier_cannot_approve_inside_window if {
	ch := [{"actor_id": "u-fin-1", "role": "verifier", "at_ms": now_ms - 1000}]
	has(permit_stage({"supplier_changes": ch}), "SOD_VIOLATION")
}

test_I7_verifier_may_approve_after_window if {
	ch := [{"actor_id": "u-fin-1", "role": "verifier", "at_ms": now_ms - 604800000}]
	decided(permit_stage({"supplier_changes": ch}), "allow")
}

test_I7_requester_cannot_approve if {
	has(permit_stage({"requested_by": "u-fin-1"}), "SOD_VIOLATION")
}

test_I7_hold_clearer_cannot_approve if {
	inp := permit_stage({
		"signals": [{"code": "SIGNAL_DMARC_FAIL", "severity": "high"}],
		"hold_clearances": [{"code": "SIGNAL_DMARC_FAIL", "cleared_by": "u-fin-1", "at_ms": now_ms}],
	})
	has(inp, "SOD_VIOLATION")
}

test_second_approver_required_above_threshold if {
	inp := object.union(permit_stage({}), {"payment": {"record": object.union(payment.record, {"amount_minor": 3000000})}})
	d := eval(inp)
	d.decision == "hold"
	"SECOND_APPROVAL_REQUIRED" in d.reasons
}

test_two_distinct_approvers_allow_above_threshold if {
	apps := [approval("apr-1", "u-fin-1"), approval("apr-2", "u-fin-2")]
	inp := object.union(permit_stage({"approvals": apps}), {"payment": {"record": object.union(payment.record, {"amount_minor": 3000000})}})
	decided(inp, "allow")
}

test_same_approver_twice_is_not_two if {
	apps := [approval("apr-1", "u-fin-1"), approval("apr-2", "u-fin-1")]
	inp := object.union(permit_stage({"approvals": apps}), {"payment": {"record": object.union(payment.record, {"amount_minor": 3000000})}})
	not decided(inp, "allow")
}

test_I4_policy_version_stale_denies if {
	inp := object.union(permit_stage({}), {"payment": {"record": object.union(payment.record, {"policy_version": "0.9.0"})}})
	has(inp, "POLICY_VERSION_STALE")
}

test_R1_mandate_revoked_after_approval_denies_permit if {
	m := object.union(mandate, {"revoked": true})
	has(permit_stage({"mandate": m}), "MANDATE_REVOKED")
}

test_R1_beneficiary_suspended_after_approval_denies_execute if {
	b := object.union(payment.beneficiary, {"status": "suspended"})
	has(execute_stage({"beneficiary": b}), "ACCOUNT_SUSPENDED")
}

test_R1_supplier_suspended_after_approval_blocks_execute if {
	s := object.union(payment.supplier, {"status": "suspended"})
	not decided(execute_stage({"supplier": s}), "allow")
}

# ---------- execute stage ----------

test_I5_valid_permit_allows_execute if {
	decided(execute_stage({}), "allow")
}

test_I5_missing_permit_denies if {
	has(execute_stage({"permit": null}), "PERMIT_MISSING")
}

test_I5_consumed_permit_denies if {
	pm := {"permit_id": "pmt-1", "digest": digest_a, "expires_at_ms": now_ms + 60000, "consumed": true}
	has(execute_stage({"permit": pm}), "PERMIT_CONSUMED")
}

test_I5_expired_permit_denies if {
	pm := {"permit_id": "pmt-1", "digest": digest_a, "expires_at_ms": now_ms, "consumed": false}
	has(execute_stage({"permit": pm}), "PERMIT_EXPIRED")
}

test_I3_permit_digest_mismatch_denies if {
	pm := {"permit_id": "pmt-1", "digest": digest_b, "expires_at_ms": now_ms + 60000, "consumed": false}
	has(execute_stage({"permit": pm}), "PERMIT_DIGEST_MISMATCH")
}
