"""API: sessions, passkey approval over HTTP, signed agent requests, I9 tampering."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from paylineage.agents.signing import sign_request
from paylineage.eval.soft_authenticator import SoftAuthenticator
from paylineage.eval.world import World

from ..api_support import client_for
from ..conftest import TEST_DB
from ..payment_support import ACCT, Shop, make_shop


@pytest.fixture
def api(world: World) -> tuple[TestClient, Shop]:
    shop = make_shop(world)
    return client_for(world, TEST_DB), shop


def _login(c: TestClient, handle: str) -> None:
    r = c.post("/v1/auth/dev-login", json={"handle": handle})
    assert r.status_code == 200, r.text


def test_health_and_policy_bytes(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    h = c.get("/v1/health").json()
    assert h["policy_runtime"] == "wasm"
    r = c.get("/v1/policy/policy.wasm")
    assert r.headers["x-policy-sha256"] == h["policy_sha256"]


def test_unauthenticated_queue_refused(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    assert c.get("/v1/queue").status_code == 401


def test_cross_origin_post_refused(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    r = c.post("/v1/auth/dev-login", json={"handle": "fin1"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_full_flow_over_http(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("http1")
    _login(c, "fin1")
    q = c.get("/v1/queue").json()
    assert any(i["id"] == pid and i["state"] == "awaiting_approval" for i in q["items"])
    d = c.get(f"/v1/payments/{pid}").json()
    assert len(d["digest"]) == 64
    begin = c.post(f"/v1/payments/{pid}/approval/begin").json()
    assert begin["digest"] == d["digest"]
    cred = world.keys["fin1"].get_assertion(json.dumps(begin["options"]))
    fin = c.post(
        f"/v1/payments/{pid}/approval/finish",
        json={"challenge_id": begin["challenge_id"], "credential": cred},
    )
    assert fin.status_code == 200, fin.text
    assert fin.json()["receipt"]["digest"] == d["digest"]
    pm = c.post(f"/v1/payments/{pid}/permit")
    assert pm.status_code == 200, pm.text
    ex = c.post(f"/v1/payments/{pid}/execute").json()
    assert ex["executed"] is True
    assert ex["bank_reference"].startswith("SIM-")
    again = c.post(f"/v1/payments/{pid}/execute")
    assert again.status_code == 409  # permit consumed: nothing left to execute


def test_I9_client_cannot_send_digest_or_trust(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("i9")
    _login(c, "ap1")
    r = c.post(f"/v1/payments/{pid}/edit", json={"amount_minor": 1_250_000, "trust_class": "verified_master"})
    assert r.status_code == 422
    r = c.post(f"/v1/payments/{pid}/edit", json={"digest": "a" * 64})
    assert r.status_code == 422


def test_approval_refused_by_policy_is_403_and_recorded(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("big", amount=6_200_000)  # denied over ceiling
    _login(c, "fin1")
    r = c.post(f"/v1/payments/{pid}/approval/begin")
    assert r.status_code == 409


def test_passkey_registration_and_login(world: World, api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    _login(c, "ana1")
    auth = SoftAuthenticator()
    b = c.post("/v1/auth/passkey/register/begin").json()
    r = c.post(
        "/v1/auth/passkey/register/finish",
        json={"challenge_id": b["challenge_id"], "credential": auth.register(json.dumps(b["options"]))},
    )
    assert r.status_code == 200, r.text
    c.post("/v1/auth/logout")
    lb = c.post("/v1/auth/passkey/login/begin").json()
    r = c.post(
        "/v1/auth/passkey/login/finish",
        json={
            "challenge_id": lb["challenge_id"],
            "credential": auth.get_assertion(json.dumps(lb["options"])),
        },
    )
    assert r.status_code == 200, r.text
    assert c.get("/v1/me").json()["roles"] == ["analyst"]


def test_wrong_origin_passkey_rejected(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("origin")
    _login(c, "fin1")
    begin = c.post(f"/v1/payments/{pid}/approval/begin").json()
    cred = world.keys["fin1"].get_assertion(json.dumps(begin["options"]), origin="https://phish.example")
    r = c.post(
        f"/v1/payments/{pid}/approval/finish",
        json={"challenge_id": begin["challenge_id"], "credential": cred},
    )
    assert r.status_code == 403


# ---------------- agent endpoints ----------------


def _agent_post(world: World, c: TestClient, path: str, body: dict, key: str, tamper: bool = False):  # type: ignore[no-untyped-def]
    raw = json.dumps(body).encode()
    url = f"http://localhost:8000{path}"
    assert world.agent_key is not None
    h = sign_request(
        world.agent_key,
        keyid="AP-Agent-001-k1",
        method="POST",
        target_uri=url,
        body=raw,
        created=int(world.clock.now().timestamp()),
    ).as_dict()
    if tamper:
        raw = raw.replace(b"1250000", b"9250000")
    return c.post(
        path, content=raw, headers={**h, "Idempotency-Key": key, "Content-Type": "application/json"}
    )


def _proposal(shop: Shop, inv: str, account: str = ACCT) -> dict:  # type: ignore[type-arg]
    return {
        "invoice_id": inv,
        "supplier_id": shop.supplier_id,
        "amount_minor": 1_250_000,
        "currency": "USD",
        "beneficiary_account": account,
    }


def test_signed_agent_proposal(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    inv = shop.invoice()
    r = _agent_post(world, c, "/v1/agent/proposals", _proposal(shop, inv), "idem-00001")
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "allow"
    again = _agent_post(world, c, "/v1/agent/proposals", _proposal(shop, inv), "idem-00001")
    assert again.json()["payment_id"] == r.json()["payment_id"]


def test_I9_tampered_agent_body_rejected(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    r = _agent_post(
        world, c, "/v1/agent/proposals", _proposal(shop, shop.invoice()), "idem-00002", tamper=True
    )
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "AGENT_SIGNATURE_INVALID"


def test_unsigned_agent_request_rejected(api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    r = c.post(
        "/v1/agent/proposals", json=_proposal(shop, shop.invoice()), headers={"Idempotency-Key": "idem-00003"}
    )
    assert r.status_code == 401


def test_I9_agent_cannot_smuggle_trust_fields(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    body = {**_proposal(shop, shop.invoice()), "trust_class": "verified_master", "approved": True}
    r = _agent_post(world, c, "/v1/agent/proposals", body, "idem-00004")
    assert r.status_code == 422


def test_agent_invoice_view_has_no_raw_text(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    inv = shop.invoice()
    url = f"http://localhost:8000/v1/agent/invoices/{inv}"
    assert world.agent_key is not None
    h = sign_request(
        world.agent_key,
        keyid="AP-Agent-001-k1",
        method="GET",
        target_uri=url,
        body=b"",
        created=int(world.clock.now().timestamp()),
    ).as_dict()
    r = c.get(f"/v1/agent/invoices/{inv}", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "text" not in json.dumps(data).lower() or "note" in data
    assert data["fields"]["beneficiary_account"].startswith("••••")
