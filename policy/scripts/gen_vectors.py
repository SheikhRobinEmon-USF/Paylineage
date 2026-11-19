"""Generate shared decision vectors (T0.6).

Expected outcomes are written by hand here, from the spec, never computed by a
runtime. `make parity` then checks Python and Node both reproduce them exactly.

Usage: python policy/scripts/gen_vectors.py
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "vectors" / "decision"

NOW = 1_800_000_000_000
DAY = 86_400_000
DA = "a" * 64
DB = "b" * 64


def field(name: str, kind: str, trust: str, matched: bool, consistency: str = "consistent") -> dict[str, Any]:
    return {
        "field_name": name,
        "source_kind": kind,
        "trust_class": trust,
        "consistency": consistency,
        "master_matched": matched,
    }


GOOD_FIELDS = [
    field("amount", "email_attachment", "untrusted_external", True),
    field("beneficiary_account", "email_attachment", "untrusted_external", True),
    field("currency", "email_attachment", "untrusted_external", True),
    field("invoice_number", "system", "system_generated", False),
    field("supplier_name", "email_attachment", "untrusted_external", True),
]

MANDATE = {
    "mandate_id": "mdt-001",
    "version": 3,
    "agent_id": "AP-Agent-001",
    "permitted_operations": ["read_invoice", "extract_fields", "propose_payment"],
    "forbidden_operations": ["change_bank_details", "approve", "execute", "edit_mandate"],
    "supplier_scope": ["sup-acme"],
    "per_proposal_ceiling_minor": 5_000_000,
    "daily_ceiling_minor": 15_000_000,
    "approver_role": "finance_approver",
    "second_approver_above_minor": 2_500_000,
    "not_before_ms": NOW - 30 * DAY,
    "expires_at_ms": NOW + 30 * DAY,
    "revoked": False,
}


def approval(aid: str, who: str, **kw: Any) -> dict[str, Any]:
    a = {
        "approval_id": aid,
        "approver_id": who,
        "digest": DA,
        "payment_version": 1,
        "expires_at_ms": NOW + 600_000,
        "revoked": False,
        "approver_active": True,
        "approver_roles": ["finance_approver"],
    }
    a.update(kw)
    return a


def base() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "request_kind": "payment",
        "now_ms": NOW,
        "payment": {
            "stage": "evaluate",
            "operation": "propose_payment",
            "agent": {"agent_id": "AP-Agent-001", "signature_valid": True},
            "mandate": copy.deepcopy(MANDATE),
            "record": {
                "payment_id": "pay-1",
                "version": 1,
                "amount_minor": 1_250_000,
                "currency": "USD",
                "supplier_id": "sup-acme",
                "beneficiary_account_id": "acct-acme-1",
                "invoice_id": "inv-1",
                "mandate_version": 3,
                "policy_version": "1.0.0",
                "digest": DA,
            },
            "requested_by": "AP-Agent-001",
            "daily_total_minor": 0,
            "fields": copy.deepcopy(GOOD_FIELDS),
            "supplier": {"supplier_id": "sup-acme", "status": "verified", "has_verified_account": True},
            "beneficiary": {
                "account_id": "acct-acme-1",
                "supplier_id": "sup-acme",
                "status": "verified",
                "cooling_off_until_ms": None,
            },
            "duplicate_invoice": False,
            "signals": [],
            "hold_clearances": [],
            "supplier_changes": [],
            "approvals": [],
            "permit": None,
        },
    }


def permit_stage() -> dict[str, Any]:
    b = base()
    b["payment"]["stage"] = "permit"
    b["payment"]["approvals"] = [approval("apr-1", "u-fin-1")]
    return b


def execute_stage() -> dict[str, Any]:
    b = permit_stage()
    b["payment"]["stage"] = "execute"
    b["payment"]["permit"] = {
        "permit_id": "pmt-1",
        "digest": DA,
        "expires_at_ms": NOW + 60_000,
        "consumed": False,
    }
    return b


def onboarding(**kw: Any) -> dict[str, Any]:
    o = {
        "action": "record_verification",
        "kind": "bank_change",
        "actor_id": "u-ver-1",
        "actor_roles": ["verifier"],
        "supplier_id": "sup-acme",
        "requester_id": "u-ap-1",
        "verifier_id": "u-ver-1",
        "assignee_id": None,
        "verification": {
            "method": "callback_on_file",
            "contact_source": "on_file",
            "contact_recorded_at_ms": NOW - 90 * DAY,
            "request_created_at_ms": NOW - DAY,
            "registry_match": True,
            "bank_confirmed": True,
        },
    }
    o.update(kw)
    return {"schema_version": "1", "request_kind": "onboarding", "now_ms": NOW, "onboarding": o}


def p(inp: dict[str, Any]) -> dict[str, Any]:
    return inp["payment"]  # type: ignore[no-any-return]


VECTORS: list[tuple[str, Any, str, list[str]]] = []


def vec(name: str, inp: Any, decision: str, reasons: list[str]) -> None:
    VECTORS.append((name, inp, decision, sorted(reasons)))


def build() -> None:
    # ---- legitimate ----
    vec("L1_allow_recurring_verified", base(), "allow", [])
    vec("permit_allow_valid_approval", permit_stage(), "allow", [])
    vec("execute_allow_valid_permit", execute_stage(), "allow", [])

    # ---- agent authority ----
    b = base()
    p(b)["record"]["amount_minor"] = 6_200_000
    vec("S7_over_ceiling", b, "deny", ["OVER_CEILING"])
    b = base()
    p(b)["operation"] = "change_bank_details"
    vec("S8_change_bank_details", b, "deny", ["OP_FORBIDDEN"])
    b = base()
    p(b)["mandate"] = None
    vec("mandate_missing", b, "deny", ["MANDATE_MISSING"])
    b = base()
    p(b)["mandate"]["revoked"] = True
    vec("mandate_revoked", b, "deny", ["MANDATE_REVOKED"])
    b = base()
    p(b)["mandate"]["expires_at_ms"] = NOW
    vec("mandate_expired_boundary", b, "deny", ["MANDATE_EXPIRED"])
    b = base()
    p(b)["mandate"]["supplier_scope"] = ["sup-other"]
    vec("supplier_out_of_scope", b, "deny", ["SUPPLIER_OUT_OF_SCOPE"])
    b = base()
    p(b)["agent"]["signature_valid"] = False
    vec("agent_signature_invalid", b, "deny", ["AGENT_SIGNATURE_INVALID"])
    b = base()
    p(b)["mandate"]["supplier_scope"] = ["*"]
    vec("wildcard_supplier_scope_allows", b, "allow", [])
    b = base()
    p(b)["mandate"]["supplier_scope"] = ["sup-*"]
    vec("malformed_partial_wildcard_scope", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["daily_total_minor"] = 14_000_000
    vec("daily_ceiling", b, "deny", ["OVER_CEILING"])

    # ---- supplier integrity ----
    b = base()
    p(b)["beneficiary"] = None
    p(b)["fields"][1]["master_matched"] = False
    vec(
        "S1_S2_new_account_not_in_master",
        b,
        "hold",
        ["BENEFICIARY_MISMATCH", "BENEFICIARY_NOT_VERIFIED", "FIELD_UNTRUSTED_MATERIAL"],
    )
    b = base()
    p(b)["beneficiary"]["status"] = "pending"
    vec("pending_account", b, "hold", ["BENEFICIARY_NOT_VERIFIED"])
    b = base()
    p(b)["beneficiary"]["status"] = "suspended"
    vec("suspended_account", b, "deny", ["ACCOUNT_SUSPENDED"])
    b = base()
    p(b)["beneficiary"]["cooling_off_until_ms"] = NOW + 1
    vec("L2_cooling_off_active", b, "hold", ["COOLING_OFF_ACTIVE"])
    b = base()
    p(b)["beneficiary"]["cooling_off_until_ms"] = NOW
    vec("L2_cooling_off_elapsed", b, "allow", [])
    b = base()
    p(b)["duplicate_invoice"] = True
    vec("S3_duplicate_invoice", b, "hold", ["DUPLICATE_INVOICE"])
    b = base()
    p(b)["signals"] = [
        {"code": "SIGNAL_HIDDEN_TEXT", "severity": "high"},
        {"code": "SIGNAL_PROMPT_INJECTION", "severity": "high"},
    ]
    vec("S4_hidden_injection_signals", b, "hold", ["SIGNAL_HIDDEN_TEXT", "SIGNAL_PROMPT_INJECTION"])
    b = base()
    p(b)["signals"] = [{"code": "SIGNAL_REPLY_TO_MISMATCH", "severity": "low"}]
    vec("low_signal_no_hold", b, "allow", [])
    b = base()
    p(b)["fields"][0]["consistency"] = "inconsistent"
    vec("field_inconsistent", b, "hold", ["FIELD_INCONSISTENT"])
    b = base()
    p(b)["fields"][1] = field("beneficiary_account", "agent_asserted", "untrusted_external", False)
    p(b)["beneficiary"] = None
    p(b)["signals"] = [{"code": "SIGNAL_TOOL_POISONING", "severity": "high"}]
    vec(
        "S9_poisoned_tool_backup_account",
        b,
        "deny",
        [
            "BENEFICIARY_MISMATCH",
            "BENEFICIARY_NOT_VERIFIED",
            "FIELD_NO_PROVENANCE",
            "FIELD_UNTRUSTED_MATERIAL",
            "SIGNAL_TOOL_POISONING",
        ],
    )
    b = base()
    p(b)["fields"][1]["trust_class"] = "verified_master"
    vec("I9_client_sets_trust_class", b, "deny", ["TRUST_CLASS_INVALID"])
    b = base()
    p(b)["fields"] = p(b)["fields"][1:]
    vec("evidence_missing_amount", b, "deny", ["EVIDENCE_MISSING"])
    b = base()
    p(b)["supplier"] = None
    vec("supplier_unknown", b, "hold", ["SUPPLIER_UNKNOWN"])

    # ---- authorization ----
    b = permit_stage()
    p(b)["record"]["digest"] = DB
    vec("S10_edited_after_approval", b, "deny", ["APPROVAL_DIGEST_MISMATCH"])
    b = permit_stage()
    p(b)["approvals"][0]["expires_at_ms"] = NOW
    vec("S12_expired_approval", b, "deny", ["APPROVAL_EXPIRED"])
    b = permit_stage()
    p(b)["supplier_changes"] = [{"actor_id": "u-fin-1", "role": "bank_change_recorder", "at_ms": NOW - 1}]
    vec("S12_approver_changed_bank_details", b, "deny", ["SOD_VIOLATION"])
    b = permit_stage()
    p(b)["approvals"][0]["revoked"] = True
    vec("approval_revoked", b, "deny", ["APPROVAL_REVOKED"])
    b = permit_stage()
    p(b)["mandate"]["revoked"] = True
    vec("R1_mandate_revoked_after_approval", b, "deny", ["MANDATE_REVOKED"])
    b = permit_stage()
    p(b)["record"]["amount_minor"] = 3_000_000
    vec("second_approver_required", b, "hold", ["SECOND_APPROVAL_REQUIRED"])
    b = permit_stage()
    p(b)["record"]["policy_version"] = "0.9.0"
    vec("policy_version_stale", b, "deny", ["POLICY_VERSION_STALE"])
    b = execute_stage()
    p(b)["permit"]["consumed"] = True
    vec("S11_permit_replayed", b, "deny", ["PERMIT_CONSUMED"])
    b = execute_stage()
    p(b)["permit"]["expires_at_ms"] = NOW
    vec("permit_expired", b, "deny", ["PERMIT_EXPIRED"])
    b = execute_stage()
    p(b)["permit"] = None
    vec("permit_missing", b, "deny", ["PERMIT_MISSING"])

    # ---- onboarding ----
    vec("onboarding_verifier_allowed", onboarding(), "allow", [])
    vec(
        "onboarding_requester_self_verify",
        onboarding(actor_id="u-ap-1", verifier_id="u-ap-1"),
        "deny",
        ["SOD_VIOLATION"],
    )
    o = onboarding()
    o["onboarding"]["verification"]["contact_source"] = "invoice"
    vec("onboarding_contact_from_invoice", o, "deny", ["VERIFICATION_CONTACT_INVALID"])

    # ---- malformed and missing (all fail closed, identical in both runtimes) ----
    vec("malformed_empty_object", {}, "deny", ["INPUT_INVALID"])
    b = base()
    del b["schema_version"]
    vec("malformed_missing_schema_version", b, "deny", ["INPUT_INVALID"])
    b = base()
    b["extra"] = 1
    vec("malformed_extra_top_level_key", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["amount_minor"] = "1250000"
    vec("malformed_amount_string", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["amount_minor"] = 0
    vec("malformed_amount_zero", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["amount_minor"] = -5
    vec("malformed_amount_negative", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["amount_minor"] = 9_223_372_036_854_775_807
    vec("malformed_amount_int64_max", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["amount_minor"] = 9_007_199_254_740_993
    vec("malformed_amount_above_safe_integer", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["operation"] = "transfer_all_funds"
    vec("malformed_unknown_operation_enum", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["signals"] = [{"code": "SIGNAL_TRUST_ME", "severity": "low"}]
    vec("malformed_unknown_signal_code", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["fields"][0]["trust_class"] = "super_trusted"
    vec("malformed_unknown_trust_class", b, "deny", ["INPUT_INVALID"])
    b = base()
    del p(b)["mandate"]
    vec("missing_mandate_key", b, "deny", ["INPUT_INVALID"])
    b = base()
    p(b)["record"]["digest"] = "not-a-digest"
    vec("malformed_digest", b, "deny", ["INPUT_INVALID"])
    b = base()
    b["request_kind"] = "onboarding"
    vec("malformed_kind_payload_mismatch", b, "deny", ["INPUT_INVALID"])
    vec("malformed_input_is_array", [base()], "deny", ["INPUT_INVALID"])
    vec("malformed_input_is_null", None, "deny", ["INPUT_INVALID"])


RAW_VECTORS: list[tuple[str, str]] = [
    ("malformed_raw_truncated_json", '{"schema_version": "1", "request_kind": "payment"'),
    ("malformed_raw_nan", '{"schema_version": "1", "request_kind": "payment", "now_ms": NaN}'),
    ("malformed_raw_trailing_comma", '{"schema_version": "1",}'),
]


def main() -> None:
    build()
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    names: set[str] = set()
    for i, (name, inp, decision, reasons) in enumerate(VECTORS):
        assert name not in names, name
        names.add(name)
        doc = {"name": name, "input": inp, "expected": {"decision": decision, "reasons": reasons}}
        (OUT / f"{i:03d}_{name}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    for j, (name, raw) in enumerate(RAW_VECTORS, start=len(VECTORS)):
        doc = {"name": name, "input_raw": raw, "expected": {"decision": "deny", "reasons": ["INPUT_INVALID"]}}
        (OUT / f"{j:03d}_{name}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(VECTORS) + len(RAW_VECTORS)} vectors to {OUT}")


if __name__ == "__main__":
    main()
