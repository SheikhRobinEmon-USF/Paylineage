"""A simulated AP agent process: it may only talk to the API, with signed requests (I6).

python -m paylineage.agents.sim_agent --api http://localhost:8000 [--invoice <id>] [--once]

Without --invoice it polls the API for invoices that have no proposal yet.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paylineage.agents.signing import sign_request


def load_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("agent key must be Ed25519")
    return key


def signed(
    client: httpx.Client,
    key: Ed25519PrivateKey,
    method: str,
    url: str,
    body: bytes = b"",
    extra: dict[str, str] | None = None,
) -> httpx.Response:
    h = sign_request(
        key,
        keyid=os.environ.get("AGENT_KEY_ID", "AP-Agent-001-k1"),
        method=method,
        target_uri=url,
        body=body,
        created=int(time.time()),
    ).as_dict()
    return client.request(
        method, url, content=body, headers={**h, **(extra or {}), "Content-Type": "application/json"}
    )


def amount_minor(text: str) -> int:
    """Major units text to integer minor units. Never a float (CLAUDE.md money rule)."""
    try:
        value = Decimal(text.replace(",", "").strip() or "0")
    except InvalidOperation as exc:
        raise ValueError(f"unreadable amount: {text!r}") from exc
    return int((value * 100).to_integral_value())


def propose_for(c: httpx.Client, key: Ed25519PrivateKey, api: str, inv: dict[str, Any]) -> None:
    print("typed fields (untrusted):", inv["fields"])
    try:
        amount = amount_minor(str(inv["fields"].get("amount", "0")))
    except ValueError as exc:
        print("skip:", exc)
        return
    body = json.dumps(
        {
            "invoice_id": inv["invoice_id"],
            "supplier_id": inv["supplier_id"],
            "amount_minor": amount,
            "currency": inv["fields"].get("currency", "USD"),
            # The agent sees masked values only; a real deployment gives it a tokenized reference.
            "beneficiary_account": os.environ.get("PROPOSE_ACCOUNT", "000123456789"),
        }
    ).encode()
    # One key per invoice, so a retry after a timeout returns the first answer.
    idem = f"inv-{inv['invoice_id']}"
    r = signed(c, key, "POST", f"{api}/v1/agent/proposals", body, {"Idempotency-Key": idem})
    print(r.status_code, r.json())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("PAYLINEAGE_API_URL", "http://localhost:8000"))
    ap.add_argument("--invoice")
    ap.add_argument("--once", action="store_true", help="poll one time and exit")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("AGENT_POLL_S", "15")))
    ap.add_argument("--key", default=os.environ.get("AGENT_KEY_PATH", "var/keys/agent_ed25519.pem"))
    a = ap.parse_args()
    key = load_key(a.key)
    with httpx.Client(timeout=10) as c:
        if a.invoice:
            inv = signed(c, key, "GET", f"{a.api}/v1/agent/invoices/{a.invoice}").json()
            propose_for(c, key, a.api, inv)
            return
        while True:
            try:
                r = signed(c, key, "GET", f"{a.api}/v1/agent/invoices")
                if r.status_code == 200:
                    for inv in r.json()["invoices"]:
                        propose_for(c, key, a.api, inv)
                else:
                    print("poll refused:", r.status_code, r.text[:200])
            except httpx.HTTPError as exc:
                print("api unreachable:", exc)
            if a.once:
                return
            time.sleep(a.interval)


if __name__ == "__main__":
    main()
