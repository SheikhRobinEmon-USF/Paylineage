# Evidence: field provenance, supplier master, beneficiary, duplicates, signals (I1, I2, I9).
package paylineage

import rego.v1

# ---------- field provenance ----------

field_by_name[f.field_name] := f if {
	some f in p.fields
}

# I9: the trust class is a pure function of the source kind. Anything else is a
# client trying to set its own trust level.
payment_deny contains "TRUST_CLASS_INVALID" if {
	some f in p.fields
	f.trust_class != cfg.trust_class_by_source[f.source_kind]
}

payment_deny contains "EVIDENCE_MISSING" if {
	some name in cfg.material_fields
	not field_by_name[name]
}

payment_deny contains "EVIDENCE_MISSING" if {
	some name in cfg.material_fields
	count([f | some f in p.fields; f.field_name == name]) > 1
}

# A material value the agent asserted without any document or master source.
payment_deny contains "FIELD_NO_PROVENANCE" if {
	some name in cfg.material_fields
	field_by_name[name].source_kind == "agent_asserted"
}

field_trusted(f) if {
	f.trust_class in cfg.trusted_classes
}

field_trusted(f) if {
	f.trust_class == "untrusted_external"
	f.master_matched == true
	f.consistency == "consistent"
}

payment_hold contains "FIELD_UNTRUSTED_MATERIAL" if {
	some name in cfg.material_fields
	f := field_by_name[name]
	f.trust_class == "untrusted_external"
	f.master_matched != true
}

payment_hold contains "FIELD_INCONSISTENT" if {
	some name in cfg.material_fields
	field_by_name[name].consistency == "inconsistent"
}

payment_hold contains "FIELD_UNCHECKED" if {
	some name in cfg.material_fields
	f := field_by_name[name]
	f.trust_class == "untrusted_external"
	f.consistency == "unchecked"
}

all_material_trusted if {
	every name in cfg.material_fields {
		field_trusted(field_by_name[name])
	}
}

# ---------- supplier master ----------

payment_hold contains "SUPPLIER_UNKNOWN" if {
	p.supplier == null
}

payment_hold contains "SUPPLIER_NOT_VERIFIED" if {
	p.supplier != null
	p.supplier.status != "verified"
}

payment_deny contains "INPUT_INVALID" if {
	p.supplier != null
	p.supplier.supplier_id != p.record.supplier_id
}

supplier_verified if {
	p.supplier != null
	p.supplier.status == "verified"
	p.supplier.supplier_id == p.record.supplier_id
}

# ---------- beneficiary (I2) ----------

payment_hold contains "BENEFICIARY_NOT_VERIFIED" if {
	p.beneficiary == null
}

payment_hold contains "BENEFICIARY_NOT_VERIFIED" if {
	p.beneficiary != null
	p.beneficiary.status == "pending"
}

payment_hold contains "BENEFICIARY_MISMATCH" if {
	p.beneficiary == null
	p.supplier != null
	p.supplier.has_verified_account == true
}

payment_hold contains "BENEFICIARY_MISMATCH" if {
	p.beneficiary != null
	p.beneficiary.supplier_id != p.record.supplier_id
}

payment_deny contains "ACCOUNT_SUSPENDED" if {
	p.beneficiary != null
	p.beneficiary.status in {"suspended", "revoked"}
}

payment_hold contains "COOLING_OFF_ACTIVE" if {
	p.beneficiary != null
	p.beneficiary.status == "verified"
	p.beneficiary.cooling_off_until_ms != null
	now < p.beneficiary.cooling_off_until_ms
}

payment_deny contains "INPUT_INVALID" if {
	p.beneficiary != null
	p.beneficiary.account_id != p.record.beneficiary_account_id
}

beneficiary_payable if {
	p.beneficiary != null
	p.beneficiary.status == "verified"
	p.beneficiary.supplier_id == p.record.supplier_id
	p.beneficiary.account_id == p.record.beneficiary_account_id
	not _cooling_off(p.beneficiary)
}

_cooling_off(b) if {
	b.cooling_off_until_ms != null
	now < b.cooling_off_until_ms
}

# ---------- currency ----------

payment_deny contains "INPUT_INVALID" if {
	not p.record.currency in cfg.supported_currencies
}

# ---------- duplicates and signals (holds, never allow) ----------

cleared_codes contains c.code if {
	some c in p.hold_clearances
	c.code in cfg.clearable_hold_codes
}

clearing_actors contains c.cleared_by if {
	some c in p.hold_clearances
}

payment_hold contains "DUPLICATE_INVOICE" if {
	p.duplicate_invoice == true
	not "DUPLICATE_INVOICE" in cleared_codes
}

payment_hold contains s.code if {
	some s in p.signals
	severity_rank(s.severity) >= hold_min_rank
	not s.code in cleared_codes
}

# ---------- evaluate-stage allow gate ----------

evidence_gate if {
	mandate_active
	op_permitted
	within_ceiling
	supplier_in_scope
	p.agent.signature_valid == true
	supplier_verified
	beneficiary_payable
	all_material_trusted
	p.record.currency in cfg.supported_currencies
}
