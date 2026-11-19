"""I6: the agent cannot reach the executor or obtain bank credentials except through a permit."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from paylineage.mockbank.app import create_app as mockbank_app
from paylineage.settings import REPO_ROOT

COMPOSE = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]


def nets(svc: str) -> set[str]:
    return set(SERVICES[svc].get("networks", []))


def test_I6_agent_network_reaches_only_the_api() -> None:
    members = {name for name, svc in SERVICES.items() if "agent" in svc.get("networks", [])}
    assert members == {"api", "ap-agent"}
    assert nets("ap-agent") == {"agent"}


def test_I6_rails_network_is_internal_and_private() -> None:
    members = {name for name, svc in SERVICES.items() if "rails" in svc.get("networks", [])}
    assert members == {"executor", "mockbank"}
    assert COMPOSE["networks"]["rails"]["internal"] is True
    assert COMPOSE["networks"]["agent"]["internal"] is True


def test_I6_only_executor_and_bank_hold_the_bank_token() -> None:
    holders = {name for name, svc in SERVICES.items() if "MOCKBANK_TOKEN" in (svc.get("environment") or {})}
    assert holders == {"executor", "mockbank"}
    assert "MOCKBANK_URL" not in (SERVICES["api"].get("environment") or {})


def test_I6_agent_shares_no_network_with_executor_or_bank() -> None:
    assert not nets("ap-agent") & (nets("executor") | nets("mockbank"))


@pytest.mark.parametrize("token", [None, "", "wrong"])
def test_I6_mock_bank_refuses_without_executor_token(token: str | None) -> None:
    c = TestClient(mockbank_app(token="right-token"))
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    r = c.post(
        "/transfers",
        json={
            "idempotency_key": "k" * 36,
            "amount_minor": 100,
            "currency": "USD",
            "beneficiary_token": "acct_" + "0" * 32,
            "reference": "x",
        },
        headers=headers,
    )
    assert r.status_code == 401


def test_I6_mock_bank_is_idempotent_on_permit_id() -> None:
    c = TestClient(mockbank_app(token="t"))
    body = {
        "idempotency_key": "p" * 36,
        "amount_minor": 100,
        "currency": "USD",
        "beneficiary_token": "acct_" + "1" * 32,
        "reference": "x",
    }
    a = c.post("/transfers", json=body, headers={"Authorization": "Bearer t"}).json()
    b = c.post("/transfers", json=body, headers={"Authorization": "Bearer t"}).json()
    assert a["bank_reference"] == b["bank_reference"]
    assert b["replayed"] is True
    other = {**body, "amount_minor": 999}
    assert c.post("/transfers", json=other, headers={"Authorization": "Bearer t"}).status_code == 409


def test_I6_executor_refuses_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from paylineage.executor.app import create_app
    from paylineage.settings import get_settings

    monkeypatch.setenv("EXECUTOR_TOKEN", "exec-secret")
    get_settings.cache_clear()
    try:
        c = TestClient(create_app())
        r = c.post("/execute", json={"permit_id": "0" * 36, "request_id": "r" * 10})
        assert r.status_code == 401
        r = c.post(
            "/execute",
            json={"permit_id": "0" * 36, "request_id": "r" * 10},
            headers={"Authorization": "Bearer guess"},
        )
        assert r.status_code == 401
    finally:
        get_settings.cache_clear()


def test_I6_api_code_never_imports_the_bank() -> None:
    """Static check: nothing reachable from the API package imports the mock bank or its client."""
    api_dir = REPO_ROOT / "backend" / "src" / "paylineage" / "api"
    for path in api_dir.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("paylineage.mockbank"), path
                assert node.module != "paylineage.executor.app", path
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("paylineage.mockbank") for a in node.names), path
    assert "MOCKBANK" not in Path(api_dir / "main.py").read_text()
