package paylineage_test

import rego.v1

now_ms := 1800000000000

day_ms := 86400000

digest_a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

digest_b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

mandate := {
	"mandate_id": "mdt-001",
	"version": 3,
	"agent_id": "AP-Agent-001",
	"permitted_operations": ["read_invoice", "extract_fields", "propose_payment"],
	"forbidden_operations": ["change_bank_details", "approve", "execute", "edit_mandate"],
	"supplier_scope": ["sup-acme"],
	"per_proposal_ceiling_minor": 5000000,
	"daily_ceiling_minor": 15000000,
	"approver_role": "finance_approver",
	"second_approver_above_minor": 2500000,
	"not_before_ms": now_ms - (30 * day_ms),
	"expires_at_ms": now_ms + (30 * day_ms),
	"revoked": false,
}

field(name, kind, trust, matched) := {
	"field_name": name,
	"source_kind": kind,
	"trust_class": trust,
	"consistency": "consistent",
	"master_matched": matched,
}

good_fields := [
	field("amount", "email_attachment", "untrusted_external", true),
	field("beneficiary_account", "email_attachment", "untrusted_external", true),
	field("currency", "email_attachment", "untrusted_external", true),
	field("invoice_number", "system", "system_generated", false),
	field("supplier_name", "email_attachment", "untrusted_external", true),
]

approval(id, who) := {
	"approval_id": id,
	"approver_id": who,
	"digest": digest_a,
	"payment_version": 1,
	"expires_at_ms": now_ms + 600000,
	"revoked": false,
	"approver_active": true,
	"approver_roles": ["finance_approver"],
}

payment := {
	"stage": "evaluate",
	"operation": "propose_payment",
	"agent": {"agent_id": "AP-Agent-001", "signature_valid": true},
	"mandate": mandate,
	"record": {
		"payment_id": "pay-1",
		"version": 1,
		"amount_minor": 1250000,
		"currency": "USD",
		"supplier_id": "sup-acme",
		"beneficiary_account_id": "acct-acme-1",
		"invoice_id": "inv-1",
		"mandate_version": 3,
		"policy_version": "1.0.0",
		"digest": digest_a,
	},
	"requested_by": "AP-Agent-001",
	"daily_total_minor": 0,
	"fields": good_fields,
	"supplier": {"supplier_id": "sup-acme", "status": "verified", "has_verified_account": true},
	"beneficiary": {"account_id": "acct-acme-1", "supplier_id": "sup-acme", "status": "verified", "cooling_off_until_ms": null},
	"duplicate_invoice": false,
	"signals": [],
	"hold_clearances": [],
	"supplier_changes": [],
	"approvals": [],
	"permit": null,
}

base := {"schema_version": "1", "request_kind": "payment", "now_ms": now_ms, "payment": payment}

# Shallow override of payment keys.
pay(overrides) := object.union(base, {"payment": object.union(payment, overrides)})

record(overrides) := pay({"record": object.union(payment.record, overrides)})

permit_stage(overrides) := pay(object.union(
	{"stage": "permit", "approvals": [approval("apr-1", "u-fin-1")]},
	overrides,
))

execute_stage(overrides) := pay(object.union(
	{
		"stage": "execute",
		"approvals": [approval("apr-1", "u-fin-1")],
		"permit": {"permit_id": "pmt-1", "digest": digest_a, "expires_at_ms": now_ms + 60000, "consumed": false},
	},
	overrides,
))

eval(inp) := d if {
	d := data.paylineage.decision with input as inp
}

has(inp, code) if {
	code in eval(inp).reasons
}

decided(inp, outcome) if {
	eval(inp).decision == outcome
}
