"""A simulated AP agent process: it may only talk to the API, with signed requests (I6).

python -m paylineage.agents.sim_agent --api http://localhost:8000 --invoice <id>
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from pathlib import Path

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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--invoice", required=True)
    ap.add_argument("--key", default=os.environ.get("AGENT_KEY_PATH", "var/keys/agent_ed25519.pem"))
    a = ap.parse_args()
    key = load_key(a.key)
    with httpx.Client(timeout=10) as c:
        inv = signed(c, key, "GET", f"{a.api}/v1/agent/invoices/{a.invoice}").json()
        print("typed fields (untrusted):", inv["fields"])
        print("The agent sees masked values only; a real deployment gives it a tokenized account reference.")
        body = json.dumps(
            {
                "invoice_id": a.invoice,
                "supplier_id": inv["supplier_id"],
                "amount_minor": int(float(inv["fields"].get("amount", "0").replace(",", "")) * 100),
                "currency": inv["fields"].get("currency", "USD"),
                "beneficiary_account": os.environ.get("PROPOSE_ACCOUNT", "000123456789"),
            }
        ).encode()
        r = signed(
            c, key, "POST", f"{a.api}/v1/agent/proposals", body, {"Idempotency-Key": secrets.token_hex(12)}
        )
        print(r.status_code, r.json())


if __name__ == "__main__":
    main()
