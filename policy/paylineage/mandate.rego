# Agent authority: identity, mandate, ceilings, scope (I10).
package paylineage

import rego.v1

p := input.payment

has_mandate if {
	p.mandate != null
}

mandate_active if {
	has_mandate
	p.mandate.revoked == false
	now >= p.mandate.not_before_ms
	now < p.mandate.expires_at_ms
}

op_permitted if {
	has_mandate
	p.operation in p.mandate.permitted_operations
	not p.operation in p.mandate.forbidden_operations
	not p.operation in cfg.agent_never_operations
}

supplier_in_scope if {
	"*" in p.mandate.supplier_scope
}

supplier_in_scope if {
	p.record.supplier_id != null
	p.record.supplier_id in p.mandate.supplier_scope
}

within_ceiling if {
	has_mandate
	p.record.amount_minor <= p.mandate.per_proposal_ceiling_minor
	p.daily_total_minor + p.record.amount_minor <= p.mandate.daily_ceiling_minor
}

payment_deny contains "AGENT_SIGNATURE_INVALID" if {
	p.agent.signature_valid != true
}

payment_deny contains "MANDATE_MISSING" if {
	not has_mandate
}

payment_deny contains "MANDATE_REVOKED" if {
	has_mandate
	p.mandate.revoked != false
}

payment_deny contains "MANDATE_EXPIRED" if {
	has_mandate
	now >= p.mandate.expires_at_ms
}

payment_deny contains "MANDATE_EXPIRED" if {
	has_mandate
	now < p.mandate.not_before_ms
}

payment_deny contains "MANDATE_MISSING" if {
	has_mandate
	p.mandate.agent_id != p.agent.agent_id
}

# The agent can never change bank details, approve, execute or edit mandates,
# whatever a mandate says.
payment_deny contains "OP_FORBIDDEN" if {
	p.operation in cfg.agent_never_operations
}

payment_deny contains "OP_FORBIDDEN" if {
	has_mandate
	not op_permitted
}

payment_deny contains "OVER_CEILING" if {
	has_mandate
	not within_ceiling
}

payment_deny contains "SUPPLIER_OUT_OF_SCOPE" if {
	has_mandate
	p.record.supplier_id != null
	not supplier_in_scope
}

# A payment proposed under one mandate version can only proceed while that
# version is still the current one.
payment_deny contains "MANDATE_VERSION_STALE" if {
	has_mandate
	p.record.mandate_version != p.mandate.version
}
