# Approval, permit and execution revalidation (I3, I4, I5 policy side, I7).
package paylineage

import rego.v1

stage := p.stage

needs_approval if {
	stage in {"permit", "execute"}
}

# People who touched this supplier's bank details inside the SoD window.
sod_conflicted contains a.actor_id if {
	some a in p.supplier_changes
	now - a.at_ms < cfg.sod_window_ms
}

# Hold clearers and the payment requester may not approve either.
sod_conflicted contains a if {
	some a in clearing_actors
}

sod_conflicted contains p.requested_by if {
	p.requested_by != null
}

approval_valid(a) if {
	a.digest == p.record.digest
	a.payment_version == p.record.version
	a.revoked == false
	now < a.expires_at_ms
	a.approver_active == true
	p.mandate.approver_role in a.approver_roles
	not a.approver_id in sod_conflicted
}

valid_approvers contains a.approver_id if {
	some a in p.approvals
	approval_valid(a)
}

required_approvers := 2 if {
	p.record.amount_minor > p.mandate.second_approver_above_minor
} else := 1

payment_deny contains "APPROVAL_MISSING" if {
	needs_approval
	count(p.approvals) == 0
}

payment_deny contains "APPROVAL_DIGEST_MISMATCH" if {
	needs_approval
	some a in p.approvals
	a.digest != p.record.digest
}

payment_deny contains "APPROVAL_DIGEST_MISMATCH" if {
	needs_approval
	some a in p.approvals
	a.payment_version != p.record.version
}

payment_deny contains "APPROVAL_EXPIRED" if {
	needs_approval
	some a in p.approvals
	now >= a.expires_at_ms
}

payment_deny contains "APPROVAL_REVOKED" if {
	needs_approval
	some a in p.approvals
	a.revoked != false
}

payment_deny contains "APPROVER_NOT_AUTHORIZED" if {
	needs_approval
	some a in p.approvals
	a.approver_active != true
}

payment_deny contains "APPROVER_NOT_AUTHORIZED" if {
	needs_approval
	has_mandate
	some a in p.approvals
	not p.mandate.approver_role in a.approver_roles
}

payment_deny contains "SOD_VIOLATION" if {
	needs_approval
	some a in p.approvals
	a.approver_id in sod_conflicted
}

payment_hold contains "SECOND_APPROVAL_REQUIRED" if {
	needs_approval
	has_mandate
	count(valid_approvers) > 0
	count(valid_approvers) < required_approvers
}

# I4: the policy that approved must still be the policy in force.
payment_deny contains "POLICY_VERSION_STALE" if {
	needs_approval
	p.record.policy_version != cfg.policy_version
}

approval_gate if {
	has_mandate
	count(valid_approvers) >= required_approvers
	count(valid_approvers) == count({a.approver_id | some a in p.approvals})
	p.record.policy_version == cfg.policy_version
}

# ---------- permit (execute stage) ----------

payment_deny contains "PERMIT_MISSING" if {
	stage == "execute"
	p.permit == null
}

payment_deny contains "PERMIT_CONSUMED" if {
	stage == "execute"
	p.permit != null
	p.permit.consumed != false
}

payment_deny contains "PERMIT_EXPIRED" if {
	stage == "execute"
	p.permit != null
	now >= p.permit.expires_at_ms
}

payment_deny contains "PERMIT_DIGEST_MISMATCH" if {
	stage == "execute"
	p.permit != null
	p.permit.digest != p.record.digest
}

permit_gate if {
	p.permit != null
	p.permit.consumed == false
	now < p.permit.expires_at_ms
	p.permit.digest == p.record.digest
}

# ---------- stage gates ----------

default payment_allow_gate := false

payment_allow_gate if {
	stage == "evaluate"
	evidence_gate
}

payment_allow_gate if {
	stage == "permit"
	evidence_gate
	approval_gate
}

payment_allow_gate if {
	stage == "execute"
	evidence_gate
	approval_gate
	permit_gate
}
