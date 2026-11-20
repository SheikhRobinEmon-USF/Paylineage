"""Regression tests for the API hardening batch (sessions, challenges, ingest, checkpoints, agents)."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from paylineage.agents.signing import sign_request
from paylineage.agents.sim_agent import amount_minor
from paylineage.eval.world import World
from paylineage.settings import Settings, get_settings

from ..api_support import client_for
from ..conftest import TEST_DB
from ..payment_support import ACCT, Shop, make_shop


@pytest.fixture
def api(world: World) -> tuple[TestClient, Shop]:
    shop = make_shop(world)
    return client_for(world, TEST_DB), shop


@pytest.fixture(autouse=True)
def _fresh_settings() -> object:
    yield
    get_settings.cache_clear()


def _login(c: TestClient, handle: str) -> None:
    assert c.post("/v1/auth/dev-login", json={"handle": handle}).status_code == 200


def _signed_get(world: World, c: TestClient, path: str) -> object:
    assert world.agent_key is not None
    h = sign_request(
        world.agent_key,
        keyid="AP-Agent-001-k1",
        method="GET",
        target_uri=f"http://localhost:8000{path}",
        body=b"",
        created=int(world.clock.now().timestamp()),
    ).as_dict()
    return c.get(path, headers=h)


# ---- session probe ----


def test_session_probe_is_null_then_user(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    r = c.get("/v1/session")
    assert r.status_code == 200
    assert r.json() == {"user": None}
    _login(c, "fin1")
    u = c.get("/v1/session").json()["user"]
    assert u["roles"] == ["finance_approver"]
    assert isinstance(u["passkeys"], int)


# ---- approval challenge binding ----


def test_I4_challenge_from_another_user_refused(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("chal-user")
    _login(c, "fin1")
    begin = c.post(f"/v1/payments/{pid}/approval/begin").json()
    cred = world.keys["fin1"].get_assertion(json.dumps(begin["options"]))
    _login(c, "fin2")  # a different signed in user replays fin1's challenge
    r = c.post(
        f"/v1/payments/{pid}/approval/finish",
        json={"challenge_id": begin["challenge_id"], "credential": cred},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "CHALLENGE_INVALID"


def test_I4_challenge_for_another_payment_refused(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid_a = shop.ready_payment("chal-a")
    pid_b = shop.ready_payment("chal-b")
    _login(c, "fin1")
    begin = c.post(f"/v1/payments/{pid_a}/approval/begin").json()
    cred = world.keys["fin1"].get_assertion(json.dumps(begin["options"]))
    r = c.post(
        f"/v1/payments/{pid_b}/approval/finish",
        json={"challenge_id": begin["challenge_id"], "credential": cred},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "CHALLENGE_INVALID"


def test_I4_failed_assertion_burns_challenge(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    pid = shop.ready_payment("chal-burn")
    _login(c, "fin1")
    begin = c.post(f"/v1/payments/{pid}/approval/begin").json()
    bad = world.keys["fin1"].get_assertion(json.dumps(begin["options"]), origin="https://phish.example")
    url = f"/v1/payments/{pid}/approval/finish"
    assert c.post(url, json={"challenge_id": begin["challenge_id"], "credential": bad}).status_code == 403
    good = world.keys["fin1"].get_assertion(json.dumps(begin["options"]))
    r = c.post(url, json={"challenge_id": begin["challenge_id"], "credential": good})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "CHALLENGE_INVALID"


# ---- inbound email token ----


def test_inbound_email_requires_token_outside_dev(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    make_shop(world)
    client_for(world, TEST_DB)
    monkeypatch.setenv("PAYLINEAGE_ENV", "test")
    monkeypatch.setenv("INGEST_TOKEN", "test-ingest-token")
    get_settings.cache_clear()
    from paylineage.api.main import create_app

    from ..api_support import InProcessExecutor

    c = TestClient(create_app(executor=InProcessExecutor(world)), base_url="http://localhost:8000")
    assert c.post("/v1/inbound/email", content=b"From: a@b\n\nhi").status_code == 401
    r = c.post("/v1/inbound/email", content=b"x", headers={"X-Ingest-Token": "wrong"})
    assert r.status_code == 401
    r = c.post("/v1/inbound/email", content=b"not an email", headers={"X-Ingest-Token": "test-ingest-token"})
    assert r.status_code != 401


# ---- production settings ----


def test_prod_refuses_dev_secrets() -> None:
    with pytest.raises(ValidationError, match="SESSION_SECRET"):
        Settings(paylineage_env="prod")
    ok = Settings(
        paylineage_env="prod",
        session_secret=SecretStr("s" * 32),
        vault_pepper=SecretStr("p" * 32),
        executor_token=SecretStr("e" * 32),
    )
    assert ok.paylineage_env == "prod"


# ---- rate limit buckets ----


def test_rate_limit_buckets_by_agent_keyid(api: tuple[TestClient, Shop]) -> None:
    from paylineage.api import deps

    c, _ = api
    deps.LIMITER._state.clear()
    for _ in range(40):  # burst is 30: the noisy key runs dry
        c.post("/v1/agent/proposals", headers={"Signature-Input": 'sig1=();keyid="noisy-k1"'})
    noisy = c.post("/v1/agent/proposals", headers={"Signature-Input": 'sig1=();keyid="noisy-k1"'})
    assert noisy.status_code == 429
    quiet = c.post("/v1/agent/proposals", headers={"Signature-Input": 'sig1=();keyid="quiet-k1"'})
    assert quiet.status_code != 429
    human = c.post("/v1/auth/logout")
    assert human.status_code != 429


# ---- audit checkpoints at runtime (I11) ----


def test_I11_checkpoint_written_and_verified(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shop = make_shop(world)
    shop.ready_payment("ckpt")
    monkeypatch.setenv("AUDIT_CHECKPOINT_KEY_PATH", str(tmp_path / "key.pem"))
    monkeypatch.setenv("AUDIT_CHECKPOINT_DIR", str(tmp_path / "checkpoints"))
    c = client_for(world, TEST_DB)
    _login(c, "ana1")
    r = c.post("/v1/audit/checkpoint")
    assert r.status_code == 200, r.text
    assert r.json()["written"] is True
    assert list((tmp_path / "checkpoints").glob("*.json"))
    ev = c.get("/v1/audit/events").json()
    assert ev["checkpoints"] == 1
    assert ev["verified"] is True
    assert c.get("/v1/audit/verify").json()["problems"] == []


def test_checkpoint_needs_admin_or_analyst(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    _login(c, "ap1")
    assert c.post("/v1/audit/checkpoint").status_code == 403


# ---- agent polling and idempotency ----


def test_agent_invoice_list_drops_proposed(world: World, api: tuple[TestClient, Shop]) -> None:
    c, shop = api
    inv = shop.invoice()
    r = _signed_get(world, c, "/v1/agent/invoices")
    assert r.status_code == 200, r.text  # type: ignore[attr-defined]
    listed = [i["invoice_id"] for i in r.json()["invoices"]]  # type: ignore[attr-defined]
    assert inv in listed
    shop.propose(inv, "list-00001")
    after = _signed_get(world, c, "/v1/agent/invoices").json()["invoices"]  # type: ignore[attr-defined]
    assert inv not in [i["invoice_id"] for i in after]
    assert all(v.startswith("••••") for i in after for k, v in i["fields"].items() if "account" in k)


def test_agent_invoice_list_needs_signature(api: tuple[TestClient, Shop]) -> None:
    c, _ = api
    assert c.get("/v1/agent/invoices").status_code == 401


@pytest.mark.concurrency
def test_concurrent_same_idempotency_key_one_payment(world: World) -> None:
    shop = make_shop(world)
    inv = shop.invoice()
    n = 8
    barrier = threading.Barrier(n)

    def run(_i: int) -> str:
        barrier.wait()
        res = world.propose(
            inv, amount_minor=1_250_000, account=ACCT, supplier_id=shop.supplier_id, key="race-00001"
        )
        return res.payment.id

    with ThreadPoolExecutor(n) as pool:
        ids = list(pool.map(run, range(n)))
    assert len(set(ids)) == 1


# ---- sim agent money parsing ----


@pytest.mark.parametrize(
    ("text", "minor"), [("12,500.00", 1_250_000), ("0.10", 10), ("19.99", 1999), ("", 0)]
)
def test_sim_agent_amounts_are_exact(text: str, minor: int) -> None:
    assert amount_minor(text) == minor


def test_sim_agent_rejects_unreadable_amount() -> None:
    with pytest.raises(ValueError, match="unreadable"):
        amount_minor("12 thousand")


def test_I11_unreadable_checkpoint_key_is_a_problem_not_a_pass(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_shop(world).ready_payment("ckpt-bad")
    bad = tmp_path / "key.pem"
    bad.write_text("not a key")
    monkeypatch.setenv("AUDIT_CHECKPOINT_KEY_PATH", str(bad))
    monkeypatch.setenv("AUDIT_CHECKPOINT_DIR", str(tmp_path / "checkpoints"))
    c = client_for(world, TEST_DB)
    _login(c, "ana1")
    ev = c.get("/v1/audit/events").json()
    assert ev["verified"] is False
    assert [p["kind"] for p in ev["problems"]] == ["checkpoint_key_unavailable"]
    assert c.post("/v1/audit/checkpoint").json()["written"] is False


def test_devkeys_creates_group_readable_keys_and_keeps_existing(tmp_path: Path) -> None:
    from paylineage.devkeys import ensure_keys

    made = ensure_keys(tmp_path)
    assert len(made) == 2
    before = {p.name: p.read_bytes() for p in made}
    assert all(p.stat().st_mode & 0o777 == 0o640 for p in made)
    assert ensure_keys(tmp_path) == []
    assert {p.name: p.read_bytes() for p in made} == before
