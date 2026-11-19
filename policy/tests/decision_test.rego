package paylineage_test

import rego.v1

# ---------- fail closed (I8) ----------

test_I8_empty_input_denies_policy_undefined if {
	d := data.paylineage.decision with input as {}
	d.decision == "deny"
	d.reasons == ["POLICY_UNDEFINED"]
}

test_I8_unknown_request_kind_denies if {
	d := data.paylineage.decision with input as {"request_kind": "anything", "now_ms": now_ms}
	d.decision == "deny"
}

test_I8_missing_payment_object_denies if {
	decided({"schema_version": "1", "request_kind": "payment", "now_ms": now_ms}, "deny")
}

test_I8_missing_now_denies if {
	inp := object.remove(base, ["now_ms"])
	decided(inp, "deny")
}

test_I8_gate_unproven_without_reason_is_deny if {
	# Mandate field missing entirely: no deny rule fires on it, the gate cannot be proven.
	# Build the input by hand: object.union deep merges and would restore the key.
	m := object.remove(mandate, ["daily_ceiling_minor"])
	pm := object.union(object.remove(payment, ["mandate"]), {"mandate": m})
	inp := {"schema_version": "1", "request_kind": "payment", "now_ms": now_ms, "payment": pm}
	not inp.payment.mandate.daily_ceiling_minor
	d := eval(inp)
	d.decision == "deny"
}

# ---------- legitimate path ----------

test_L1_recurring_verified_supplier_allows if {
	d := eval(base)
	d.decision == "allow"
	d.reasons == []
	d.policy_version == "1.0.0"
}

test_reasons_are_sorted if {
	d := eval(pay({"beneficiary": null, "duplicate_invoice": true}))
	d.reasons == sort(d.reasons)
}

test_deny_wins_over_hold if {
	d := eval(pay({"beneficiary": null, "operation": "change_bank_details"}))
	d.decision == "deny"
	"OP_FORBIDDEN" in d.reasons
	"BENEFICIARY_NOT_VERIFIED" in d.reasons
}

# ---------- signature and mandate (I10) ----------

test_I10_signature_invalid_denies if {
	has(pay({"agent": {"agent_id": "AP-Agent-001", "signature_valid": false}}), "AGENT_SIGNATURE_INVALID")
}

test_I10_mandate_missing_denies if {
	d := eval(pay({"mandate": null}))
	d.decision == "deny"
	"MANDATE_MISSING" in d.reasons
	not "OP_FORBIDDEN" in d.reasons
}

test_I10_mandate_for_other_agent_denies if {
	has(pay({"mandate": object.union(mandate, {"agent_id": "AP-Agent-999"})}), "MANDATE_MISSING")
}

test_I10_mandate_revoked_denies if {
	has(pay({"mandate": object.union(mandate, {"revoked": true})}), "MANDATE_REVOKED")
}

test_I10_mandate_expired_denies if {
	has(pay({"mandate": object.union(mandate, {"expires_at_ms": now_ms})}), "MANDATE_EXPIRED")
}

test_I10_mandate_not_yet_valid_denies if {
	has(pay({"mandate": object.union(mandate, {"not_before_ms": now_ms + 1})}), "MANDATE_EXPIRED")
}

test_S8_change_bank_details_denied_op_forbidden if {
	d := eval(pay({"operation": "change_bank_details"}))
	d.decision == "deny"
	"OP_FORBIDDEN" in d.reasons
}

test_I10_never_operations_denied_even_if_mandate_permits if {
	m := object.union(mandate, {"permitted_operations": ["propose_payment", "approve", "execute"], "forbidden_operations": []})
	every op in ["approve", "execute", "edit_mandate", "change_bank_details"] {
		has(pay({"mandate": m, "operation": op}), "OP_FORBIDDEN")
	}
}

test_I10_op_not_in_permitted_denies if {
	m := object.union(mandate, {"permitted_operations": ["read_invoice"]})
	has(pay({"mandate": m}), "OP_FORBIDDEN")
}

test_S7_over_ceiling_denied if {
	d := eval(record({"amount_minor": 6200000}))
	d.decision == "deny"
	"OVER_CEILING" in d.reasons
}

test_I10_at_ceiling_allowed if {
	m := object.union(mandate, {"second_approver_above_minor": 9000000})
	decided(pay({"mandate": m, "record": object.union(payment.record, {"amount_minor": 5000000})}), "allow")
}

test_I10_daily_ceiling_denies if {
	has(pay({"daily_total_minor": 14000000}), "OVER_CEILING")
}

test_I10_supplier_out_of_scope_denies if {
	m := object.union(mandate, {"supplier_scope": ["sup-other"]})
	has(pay({"mandate": m}), "SUPPLIER_OUT_OF_SCOPE")
}

test_I10_wildcard_scope_allows if {
	m := object.union(mandate, {"supplier_scope": ["*"]})
	decided(pay({"mandate": m}), "allow")
}

test_I10_mandate_version_stale_denies if {
	has(record({"mandate_version": 2}), "MANDATE_VERSION_STALE")
}

# ---------- provenance (I1, I9) ----------

test_I9_trust_class_not_matching_source_denies if {
	f := array.concat(
		[field("beneficiary_account", "email_attachment", "verified_master", true)],
		array.slice(good_fields, 2, 5),
	)
	fs := array.concat([good_fields[0]], f)
	d := eval(pay({"fields": fs}))
	d.decision == "deny"
	"TRUST_CLASS_INVALID" in d.reasons
}

test_I8_missing_material_field_denies if {
	fs := array.slice(good_fields, 1, 5)
	has(pay({"fields": fs}), "EVIDENCE_MISSING")
}

test_I8_duplicate_material_field_denies if {
	fs := array.concat(good_fields, [good_fields[0]])
	has(pay({"fields": fs}), "EVIDENCE_MISSING")
}

test_S9_agent_asserted_beneficiary_denied if {
	fs := array.concat(
		[good_fields[0], field("beneficiary_account", "agent_asserted", "untrusted_external", false)],
		array.slice(good_fields, 2, 5),
	)
	d := eval(pay({"fields": fs, "beneficiary": null}))
	d.decision == "deny"
	"FIELD_NO_PROVENANCE" in d.reasons
	"BENEFICIARY_NOT_VERIFIED" in d.reasons
}

test_I1_untrusted_unmatched_material_holds if {
	fs := array.concat(
		[good_fields[0], field("beneficiary_account", "email_attachment", "untrusted_external", false)],
		array.slice(good_fields, 2, 5),
	)
	d := eval(pay({"fields": fs}))
	d.decision == "hold"
	"FIELD_UNTRUSTED_MATERIAL" in d.reasons
}

test_I1_span_inconsistent_holds if {
	f := object.union(good_fields[0], {"consistency": "inconsistent"})
	fs := array.concat([f], array.slice(good_fields, 1, 5))
	has(pay({"fields": fs}), "FIELD_INCONSISTENT")
	decided(pay({"fields": fs}), "hold")
}

test_I1_span_unchecked_holds if {
	f := object.union(good_fields[0], {"consistency": "unchecked"})
	fs := array.concat([f], array.slice(good_fields, 1, 5))
	has(pay({"fields": fs}), "FIELD_UNCHECKED")
}

test_I1_user_entered_amount_trusted if {
	fs := array.concat([field("amount", "user_entered", "user_entered", false)], array.slice(good_fields, 1, 5))
	decided(pay({"fields": fs}), "allow")
}

# ---------- supplier and beneficiary (I2) ----------

test_S2_account_not_in_master_holds if {
	d := eval(pay({"beneficiary": null}))
	d.decision == "hold"
	"BENEFICIARY_NOT_VERIFIED" in d.reasons
	"BENEFICIARY_MISMATCH" in d.reasons
}

test_I2_pending_account_holds if {
	b := object.union(payment.beneficiary, {"status": "pending"})
	d := eval(pay({"beneficiary": b}))
	d.decision == "hold"
	"BENEFICIARY_NOT_VERIFIED" in d.reasons
}

test_I2_suspended_account_denies if {
	b := object.union(payment.beneficiary, {"status": "suspended"})
	has(pay({"beneficiary": b}), "ACCOUNT_SUSPENDED")
	decided(pay({"beneficiary": b}), "deny")
}

test_I2_revoked_account_denies if {
	b := object.union(payment.beneficiary, {"status": "revoked"})
	has(pay({"beneficiary": b}), "ACCOUNT_SUSPENDED")
}

test_I2_account_of_other_supplier_holds if {
	b := object.union(payment.beneficiary, {"supplier_id": "sup-evil"})
	has(pay({"beneficiary": b}), "BENEFICIARY_MISMATCH")
	not decided(pay({"beneficiary": b}), "allow")
}

test_I2_beneficiary_id_not_record_id_denies if {
	b := object.union(payment.beneficiary, {"account_id": "acct-other"})
	has(pay({"beneficiary": b}), "INPUT_INVALID")
}

test_L2_cooling_off_holds_then_allows if {
	b := object.union(payment.beneficiary, {"cooling_off_until_ms": now_ms + 1000})
	has(pay({"beneficiary": b}), "COOLING_OFF_ACTIVE")
	b2 := object.union(payment.beneficiary, {"cooling_off_until_ms": now_ms})
	decided(pay({"beneficiary": b2}), "allow")
}

test_supplier_unknown_holds if {
	d := eval(pay({"supplier": null}))
	"SUPPLIER_UNKNOWN" in d.reasons
	d.decision == "hold"
}

test_supplier_unverified_holds if {
	s := object.union(payment.supplier, {"status": "unverified"})
	has(pay({"supplier": s}), "SUPPLIER_NOT_VERIFIED")
}

test_supplier_record_mismatch_denies if {
	s := object.union(payment.supplier, {"supplier_id": "sup-other"})
	has(pay({"supplier": s}), "INPUT_INVALID")
}

test_unsupported_currency_denies if {
	has(record({"currency": "EUR"}), "INPUT_INVALID")
}

# ---------- duplicates and signals ----------

test_S3_duplicate_invoice_holds if {
	d := eval(pay({"duplicate_invoice": true}))
	d.decision == "hold"
	d.reasons == ["DUPLICATE_INVOICE"]
}

test_S4_hidden_text_signal_holds_never_allows if {
	d := eval(pay({"signals": [{"code": "SIGNAL_HIDDEN_TEXT", "severity": "high"}]}))
	d.decision == "hold"
	"SIGNAL_HIDDEN_TEXT" in d.reasons
}

test_low_severity_signal_does_not_hold if {
	decided(pay({"signals": [{"code": "SIGNAL_REPLY_TO_MISMATCH", "severity": "low"}]}), "allow")
}

test_cleared_signal_allows if {
	inp := pay({
		"signals": [{"code": "SIGNAL_LOOKALIKE_DOMAIN", "severity": "medium"}],
		"hold_clearances": [{"code": "SIGNAL_LOOKALIKE_DOMAIN", "cleared_by": "u-analyst", "at_ms": now_ms}],
	})
	decided(inp, "allow")
}

test_I2_clearance_cannot_clear_beneficiary_hold if {
	inp := pay({
		"beneficiary": null,
		"hold_clearances": [{"code": "BENEFICIARY_NOT_VERIFIED", "cleared_by": "u-analyst", "at_ms": now_ms}],
	})
	has(inp, "BENEFICIARY_NOT_VERIFIED")
	not decided(inp, "allow")
}
