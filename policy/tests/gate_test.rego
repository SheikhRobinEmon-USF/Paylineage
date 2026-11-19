package paylineage_test

import rego.v1

# The policy has two independent layers: explicit deny/hold rules, and a positive
# allow gate that must prove every fact. These tests check the gate on its own,
# so each layer is verified independently (found by hand-planted Rego mutants).

gate(inp) if {
	data.paylineage.payment_allow_gate with input as inp
}

test_gate_open_for_L1 if {
	gate(base)
}

test_I10_over_ceiling_by_one_minor_unit_denied if {
	m := object.union(mandate, {"second_approver_above_minor": 9000000})
	inp := pay({"mandate": m, "record": object.union(payment.record, {"amount_minor": 5000001})})
	has(inp, "OVER_CEILING")
	not gate(inp)
}

test_gate_closed_mandate_revoked if {
	not gate(pay({"mandate": object.union(mandate, {"revoked": true})}))
}

test_gate_closed_at_expiry_instant if {
	not gate(pay({"mandate": object.union(mandate, {"expires_at_ms": now_ms})}))
}

test_gate_closed_for_never_operations_even_if_permitted if {
	m := object.union(mandate, {"permitted_operations": ["propose_payment", "approve"], "forbidden_operations": []})
	not gate(pay({"mandate": m, "operation": "approve"}))
}

test_gate_closed_untrusted_unmatched_field if {
	f := object.union(good_fields[1], {"master_matched": false})
	fs := array.concat([good_fields[0], f], array.slice(good_fields, 2, 5))
	not gate(pay({"fields": fs}))
}

test_gate_closed_pending_account if {
	not gate(pay({"beneficiary": object.union(payment.beneficiary, {"status": "pending"})}))
}

test_gate_closed_during_cooling_off if {
	not gate(pay({"beneficiary": object.union(payment.beneficiary, {"cooling_off_until_ms": now_ms + 1})}))
}

test_gate_closed_approval_digest_differs if {
	inp := object.union(permit_stage({}), {"payment": {"record": object.union(payment.record, {"digest": digest_b})}})
	not gate(inp)
}

test_gate_closed_expired_approval if {
	a := object.union(approval("apr-1", "u-fin-1"), {"expires_at_ms": now_ms})
	not gate(permit_stage({"approvals": [a]}))
}

test_gate_closed_sod_conflict if {
	ch := [{"actor_id": "u-fin-1", "role": "verifier", "at_ms": now_ms - 1}]
	not gate(permit_stage({"supplier_changes": ch}))
}

test_gate_closed_without_approvals if {
	not gate(permit_stage({"approvals": []}))
}

test_gate_closed_consumed_permit if {
	pm := {"permit_id": "pmt-1", "digest": digest_a, "expires_at_ms": now_ms + 60000, "consumed": true}
	not gate(execute_stage({"permit": pm}))
}

test_gate_closed_expired_permit if {
	pm := {"permit_id": "pmt-1", "digest": digest_a, "expires_at_ms": now_ms, "consumed": false}
	not gate(execute_stage({"permit": pm}))
}
