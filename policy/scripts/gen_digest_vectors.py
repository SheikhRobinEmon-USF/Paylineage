"""Generate cross-language digest vectors (T0.7).

Two kinds of expectation:
  * known answers from RFC 8785 itself (hand copied canonical text), and
  * values whose canonical text the Python implementation produces; the
    TypeScript implementation must reproduce text and digest byte for byte.
Error vectors must fail in both languages.

Usage: uv run python policy/scripts/gen_digest_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from paylineage.canonical import CanonicalError, canonical_bytes

OUT = ROOT / "policy" / "vectors" / "digest"

# RFC 8785 section 3.2.2 example, minus 1E30 (an integral value outside the
# I-JSON safe range, which our profile rejects; see error_integral_float_1e30).
RFC_INPUT = (
    '{"numbers": [333333333.33333329, 4.50, 2e-3, 0.000000000000000000000000001],'
    ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
    ' "literals": [null, true, false]}'
)
RFC_CANONICAL = (
    '{"literals":[null,true,false],"numbers":[333333333.3333333,4.5,0.002,1e-27],'
    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
)

PAYMENT = {
    "schema": "paylineage.payment.v1",
    "payment_id": "0190f5a2-7c1e-7d3a-9b2f-3c4d5e6f7a8b",
    "version": 1,
    "amount_minor": 1250000,
    "currency": "USD",
    "supplier_id": "0190f5a2-0000-7000-8000-000000000001",
    "beneficiary_account_id": "0190f5a2-0000-7000-8000-0000000000a1",
    "invoice_id": "0190f5a2-0000-7000-8000-0000000000f1",
    "invoice_digest": "c" * 64,
    "agent_id": "AP-Agent-001",
    "mandate_version": 3,
    "policy_version": "1.0.0",
    "policy_sha256": "d" * 64,
    "operation": "pay_invoice",
    "nonce": "n-7f3a",
    "expires_at_ms": 1800000600000,
}

VALUES: list[tuple[str, Any]] = [
    ("empty_object", {}),
    ("empty_array", []),
    ("scalars", [None, True, False, 0, -0, 1, -1]),
    ("key_order_ascii", {"b": 1, "a": 2, "aa": 3, "A": 4, "_": 5}),
    ("nested", {"z": {"y": [3, {"b": 2, "a": 1}]}, "a": []}),
    ("payment_record", PAYMENT),
    ("payment_record_amount_plus_one", {**PAYMENT, "amount_minor": 1250001}),
    ("payment_record_beneficiary_changed", {**PAYMENT, "beneficiary_account_id": "acct-attacker"}),
    ("max_safe_integer", {"n": 2**53 - 1, "m": -(2**53 - 1)}),
    ("unicode_bmp", {"name": "Café Müller Straße", "jp": "請求書", "rtl": "חשבונית"}),
    ("unicode_astral_emoji", {"e": "💸 invoice 🧾"}),
    # UTF-16 order: U+1F600 (surrogates D83D DE00) sorts BEFORE U+E000. Code point order is the reverse.
    ("key_order_utf16_vs_codepoint", {"": 1, "\U0001f600": 2, "a": 3}),
    ("control_chars", {"s": "tab\tnl\ncr\rnul\u0000bell\u0007"}),
    ("escapes", {"s": 'quote " backslash \\ slash / '}),
    ("floats_es6_format", [0.1, 1.5, 100.0, 1e-7, 123456789.123, 5e-324, 1.7976931348623157e308 / 1e300]),
    ("zero_width_and_homoglyphs", {"domain": "acme-supp\u200bly.com", "cyr": "аcme"}),
    ("long_string", {"s": "x" * 4096}),
    ("deep_array", [[[[[[["deep"]]]]]]]),
]

ERRORS: list[tuple[str, str]] = [
    ("error_integer_2_pow_53", '{"n": 9007199254740992}'),
    ("error_integer_int64", '{"amount_minor": 9223372036854775807}'),
    ("error_negative_beyond_safe", '{"n": -9007199254740993}'),
    ("error_lone_surrogate", '{"s": "\\ud800"}'),
    ("error_integral_float_1e30", '{"numbers": [1E30]}'),
    ("error_integral_float_1e21", "[1e21]"),
]


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    docs: list[dict[str, Any]] = []
    rfc_value = json.loads(RFC_INPUT)
    rfc_bytes = canonical_bytes(rfc_value)
    if rfc_bytes.decode() != RFC_CANONICAL:
        raise SystemExit(f"Python disagrees with RFC 8785 example: {rfc_bytes!r}")
    docs.append(
        {
            "name": "rfc8785_section_3_2_2",
            "value_raw": RFC_INPUT,
            "expected": {"canonical": RFC_CANONICAL, "sha256": hashlib.sha256(rfc_bytes).hexdigest()},
        }
    )
    for name, value in VALUES:
        b = canonical_bytes(value)
        docs.append(
            {
                "name": name,
                "value_raw": json.dumps(value, ensure_ascii=True),
                "expected": {"canonical": b.decode("utf-8"), "sha256": hashlib.sha256(b).hexdigest()},
            }
        )
    for name, raw in ERRORS:
        try:
            canonical_bytes(json.loads(raw))
        except CanonicalError:
            pass
        else:
            raise SystemExit(f"{name} did not fail in Python")
        docs.append({"name": name, "value_raw": raw, "expected": {"error": True}})
    for i, doc in enumerate(docs):
        (OUT / f"{i:03d}_{doc['name']}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {len(docs)} digest vectors")


if __name__ == "__main__":
    main()
