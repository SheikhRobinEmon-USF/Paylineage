"""Tokenization for sensitive values (fictional account numbers).

Tokens are a keyed hash of the normalized value, so the same account always has
the same token and can be compared without reading the raw value. Raw values
live only in `vault_values`. Logs and API responses carry tokens or masks.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from paylineage.db.models import VaultValue
from paylineage.settings import get_settings

_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")


def normalize_account(raw: str) -> str:
    return _NON_ALNUM.sub("", raw).upper()


def _pepper() -> bytes:
    return ("vault:" + get_settings().session_secret.get_secret_value()).encode()


def account_token(raw: str) -> str:
    norm = normalize_account(raw)
    if not norm:
        raise ValueError("empty account value")
    mac = hmac.new(_pepper(), norm.encode(), hashlib.sha256).hexdigest()[:32]
    return f"acct_{mac}"


def mask_account(raw: str) -> str:
    norm = normalize_account(raw)
    return f"•••• {norm[-4:]}" if len(norm) >= 4 else "••••"


def store_account(session: Session, raw: str) -> str:
    token = account_token(raw)
    session.execute(
        insert(VaultValue)
        .values(token=token, kind="account_number", value=normalize_account(raw))
        .on_conflict_do_nothing(index_elements=["token"])
    )
    return token


def value_token(kind: str, raw: str) -> str:
    """Generic token for non-account fields (used for field provenance rows)."""
    mac = hmac.new(_pepper(), f"{kind}:{raw}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"val_{mac}"
