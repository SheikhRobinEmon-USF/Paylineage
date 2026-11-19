"""Reason code registry, loaded from policy/schema/reason_codes.v1.json (single source)."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Literal

from paylineage.settings import get_settings

CodeClass = Literal["deny", "hold"]

FAIL_CLOSED_CODES = frozenset({"POLICY_UNDEFINED", "POLICY_ERROR", "INPUT_INVALID", "PARITY_MISMATCH"})


@lru_cache(maxsize=1)
def registry() -> dict[str, CodeClass]:
    path = get_settings().policy_dir / "schema" / "reason_codes.v1.json"
    raw = json.loads(path.read_text())
    out: dict[str, CodeClass] = {}
    for code, meta in raw["codes"].items():
        cls = meta["class"]
        if cls not in ("deny", "hold"):
            raise ValueError(f"bad class for {code}: {cls}")
        out[code] = cls
    missing = FAIL_CLOSED_CODES - out.keys()
    if missing:
        raise ValueError(f"registry lacks fail-closed codes: {sorted(missing)}")
    return out


@lru_cache(maxsize=1)
def meanings() -> dict[str, str]:
    path = get_settings().policy_dir / "schema" / "reason_codes.v1.json"
    raw = json.loads(path.read_text())
    return {code: str(meta["meaning"]) for code, meta in raw["codes"].items()}


def is_known(code: str) -> bool:
    return code in registry()


def code_class(code: str) -> CodeClass:
    return registry()[code]
