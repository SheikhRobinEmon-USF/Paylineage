"""RFC 8785 canonical JSON and SHA-256 digests (T0.7).

Shares vectors with packages/canonical via policy/vectors/digest/. Rules both
languages enforce identically:
  * I-JSON profile (RFC 7493): any integral value, int or float, must be inside
    the IEEE 754 safe range (|n| < 2**53). JS cannot tell 1e30 from a 31 digit
    integer, so the rule is by value in both languages;
  * strings must be well formed Unicode (no lone surrogates);
  * only JSON types (dict with str keys, list, str, int, float, bool, None).
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from typing import Any

import rfc8785

MAX_SAFE_INTEGER = 2**53 - 1
PAYMENT_RECORD_SCHEMA = "paylineage.payment.v1"


class CanonicalError(ValueError):
    """Value cannot be canonicalized identically in Python and TypeScript."""


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError(f"{path}: integer outside safe range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError(f"{path}: non-finite number")
        if value.is_integer() and abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError(f"{path}: integral value outside safe range")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalError(f"{path}: string is not well formed Unicode") from exc
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"{path}: non-string key")
            _check(k, f"{path}.<key>")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check(value, "$")
    try:
        out: bytes = rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, ValueError, TypeError) as exc:
        raise CanonicalError(str(exc)) from exc
    return out


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


PAYMENT_RECORD_FIELDS: tuple[str, ...] = (
    "schema",
    "payment_id",
    "version",
    "amount_minor",
    "currency",
    "supplier_id",
    "beneficiary_account_id",
    "invoice_id",
    "invoice_digest",
    "agent_id",
    "mandate_version",
    "policy_version",
    "policy_sha256",
    "operation",
    "nonce",
    "expires_at_ms",
)


def payment_record_digest(record: Mapping[str, Any]) -> str:
    """Digest of the canonical payment record. Exactly the listed fields, nothing else."""
    keys = set(record)
    expected = set(PAYMENT_RECORD_FIELDS)
    if keys != expected:
        raise CanonicalError(
            f"record fields differ: missing {sorted(expected - keys)} extra {sorted(keys - expected)}"
        )
    if record["schema"] != PAYMENT_RECORD_SCHEMA:
        raise CanonicalError("wrong record schema tag")
    return digest(dict(record))
