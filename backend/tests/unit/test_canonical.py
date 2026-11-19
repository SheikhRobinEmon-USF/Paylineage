"""T0.7: canonical digest, shared vectors with packages/canonical."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from paylineage.canonical import (
    PAYMENT_RECORD_FIELDS,
    CanonicalError,
    canonical_bytes,
    digest,
    payment_record_digest,
    sha256_hex,
)
from paylineage.policy.engine import strict_json_loads
from paylineage.settings import get_settings

DIGEST_DIR = get_settings().policy_dir / "vectors" / "digest"
VECTORS = sorted(DIGEST_DIR.glob("*.json"))


def test_at_least_twenty_vectors() -> None:
    assert len(VECTORS) >= 20


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: Path(p).stem)
def test_digest_vector(path: Path) -> None:
    vec = json.loads(path.read_text())
    value = strict_json_loads(vec["value_raw"])
    if vec["expected"].get("error"):
        with pytest.raises(CanonicalError):
            canonical_bytes(value)
        return
    b = canonical_bytes(value)
    assert b.decode("utf-8") == vec["expected"]["canonical"]
    assert sha256_hex(b) == vec["expected"]["sha256"]


def _record() -> dict[str, Any]:
    for p in VECTORS:
        v = json.loads(p.read_text())
        if v["name"] == "payment_record":
            return strict_json_loads(v["value_raw"])  # type: ignore[no-any-return]
    raise KeyError


def test_payment_record_requires_exact_fields() -> None:
    rec = _record()
    assert set(rec) == set(PAYMENT_RECORD_FIELDS)
    assert payment_record_digest(rec) == digest(rec)
    with pytest.raises(CanonicalError):
        payment_record_digest({**rec, "memo": "pay fast"})
    rec.pop("nonce")
    with pytest.raises(CanonicalError):
        payment_record_digest(rec)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount_minor", 1250001),
        ("beneficiary_account_id", "acct-x"),
        ("supplier_id", "s"),
        ("currency", "EUR"),
        ("invoice_id", "i"),
        ("operation", "refund"),
    ],
)
def test_I3_any_material_change_changes_digest(field: str, value: Any) -> None:
    rec = _record()
    assert payment_record_digest({**rec, field: value}) != payment_record_digest(rec)


json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53) + 1, 2**53 - 1) | st.text(),
    lambda kids: st.lists(kids, max_size=4) | st.dictionaries(st.text(max_size=8), kids, max_size=4),
    max_leaves=20,
)


@given(json_values)
def test_canonical_is_idempotent_and_order_independent(value: Any) -> None:
    b = canonical_bytes(value)
    assert canonical_bytes(json.loads(b)) == b


@given(st.dictionaries(st.text(max_size=6), st.integers(0, 10), min_size=2, max_size=6))
def test_key_insertion_order_irrelevant(d: dict[str, int]) -> None:
    reversed_d = dict(reversed(list(d.items())))
    assert digest(d) == digest(reversed_d)


@pytest.mark.parametrize("bad", [2**53, -(2**53), 1e30, float("inf"), "\ud800", b"bytes", {1: "x"}, object()])
def test_rejects_values_ts_cannot_match(bad: Any) -> None:
    with pytest.raises(CanonicalError):
        canonical_bytes(bad)
