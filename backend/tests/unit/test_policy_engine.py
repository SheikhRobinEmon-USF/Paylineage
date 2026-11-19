"""T0.4: Python runtime adapter. I8: every failure mode denies. Mirrored in TS (T0.5)."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest

from paylineage.policy import engine as eng
from paylineage.policy.engine import (
    UnavailablePolicy,
    WasmPolicyEngine,
    build_engine,
    run_vectors,
    vector_paths,
)
from paylineage.policy.wasm_host import OpaWasmPolicy, UnsupportedBuiltinError, WasmPolicyError
from paylineage.settings import Settings, get_settings

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _vector(name: str) -> dict[str, Any]:
    for p in vector_paths(get_settings()):
        doc = json.loads(p.read_text())
        if doc["name"] == name:
            return doc["input"]  # type: ignore[no-any-return]
    raise KeyError(name)


@pytest.fixture(scope="module")
def engine() -> WasmPolicyEngine:
    e = build_engine()
    assert isinstance(e, WasmPolicyEngine)
    return e


@pytest.fixture
def l1() -> dict[str, Any]:
    return copy.deepcopy(_vector("L1_allow_recurring_verified"))


def _copy_policy_dir(tmp_path: Path) -> Settings:
    dst = tmp_path / "policy"
    shutil.copytree(get_settings().policy_dir, dst, ignore=shutil.ignore_patterns("build"))
    return Settings(policy_dir=dst)


def test_loads_verified_wasm(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    d = engine.evaluate(l1)
    assert d.decision == "allow"
    assert d.reasons == ()
    assert d.policy_version == "1.0.0"
    assert d.policy_sha256 == eng.read_expected_sha(get_settings())
    assert d.runtime == "wasm"


def test_all_shared_vectors_match(engine: WasmPolicyEngine) -> None:
    assert run_vectors(engine, vector_paths(get_settings())) == []


def test_I8_invalid_input_denies(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    l1["payment"]["record"]["amount_minor"] = "lots"
    d = engine.evaluate(l1)
    assert (d.decision, d.reasons) == ("deny", ("INPUT_INVALID",))


def test_I8_non_json_input_denies(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    l1["payment"]["record"]["amount_minor"] = float("nan")
    assert engine.evaluate(l1).reasons == ("INPUT_INVALID",)


def test_I8_unknown_enum_value_denies(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    l1["payment"]["fields"][0]["source_kind"] = "trusted_by_llm"
    assert engine.evaluate(l1).reasons == ("INPUT_INVALID",)


def test_I8_hash_mismatch_denies(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    s.policy_sha256_path.write_text("0" * 64 + "  policy.wasm\n")
    e = build_engine(s)
    assert isinstance(e, UnavailablePolicy)
    assert e.evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_pinned_sha_mismatch_denies(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    s.policy_sha256 = "f" * 64
    assert build_engine(s).evaluate(l1).decision == "deny"


def test_I8_tampered_wasm_denies(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    raw = bytearray(s.policy_wasm_path.read_bytes())
    raw[-10] ^= 0xFF
    s.policy_wasm_path.write_bytes(bytes(raw))
    assert build_engine(s).evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_missing_wasm_denies(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    s.policy_wasm_path.unlink()
    assert build_engine(s).evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_garbage_module_with_matching_hash_denies(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    s.policy_wasm_path.write_bytes(b"\x00asm garbage")
    s.policy_sha256_path.write_text(hashlib.sha256(b"\x00asm garbage").hexdigest() + "  policy.wasm\n")
    e = build_engine(s)
    assert e.runtime == "unavailable"
    assert e.evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_unsupported_builtin_module_refused() -> None:
    with pytest.raises(UnsupportedBuiltinError):
        OpaWasmPolicy((FIXTURES / "needs_builtin.wasm").read_bytes(), fuel=10_000_000)


def test_I8_unsupported_builtin_module_denies_via_loader(tmp_path: Path, l1: dict[str, Any]) -> None:
    s = _copy_policy_dir(tmp_path)
    raw = (FIXTURES / "needs_builtin.wasm").read_bytes()
    s.policy_wasm_path.write_bytes(raw)
    s.policy_sha256_path.write_text(hashlib.sha256(raw).hexdigest() + "  policy.wasm\n")
    d = build_engine(s).evaluate(l1)
    assert d.decision == "deny"
    assert d.reasons == ("POLICY_ERROR",)


def test_I8_timeout_denies(l1: dict[str, Any]) -> None:
    s = Settings(policy_fuel=100_000)
    e = build_engine(s)
    d = e.evaluate(l1)
    assert (d.decision, d.reasons) == ("deny", ("POLICY_ERROR",))
    assert d.detail == "timeout"


def test_I8_runtime_exception_denies(
    engine: WasmPolicyEngine, l1: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_encoded: bytes) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(engine, "_raw_eval", boom)
    assert engine.evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_host_error_denies(
    engine: WasmPolicyEngine, l1: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_encoded: bytes) -> Any:
        raise WasmPolicyError("trap")

    monkeypatch.setattr(engine, "_raw_eval", boom)
    assert engine.evaluate(l1).reasons == ("POLICY_ERROR",)


def test_I8_undefined_result_denies(
    engine: WasmPolicyEngine, l1: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def undefined(_encoded: bytes) -> Any:
        raise WasmPolicyError("policy result undefined")

    monkeypatch.setattr(engine, "_raw_eval", undefined)
    assert engine.evaluate(l1).reasons == ("POLICY_UNDEFINED",)


@pytest.mark.parametrize(
    "bad_output",
    [
        None,
        True,
        "allow",
        {"decision": "allow"},
        {"decision": "ALLOW", "reasons": [], "policy_version": "1.0.0"},
        {"decision": "allow", "reasons": ["OVER_CEILING"], "policy_version": "1.0.0"},
        {"decision": "hold", "reasons": [], "policy_version": "1.0.0"},
        {"decision": "hold", "reasons": ["OVER_CEILING"], "policy_version": "1.0.0"},
        {"decision": "deny", "reasons": [], "policy_version": "1.0.0"},
        {"decision": "deny", "reasons": ["DUPLICATE_INVOICE"], "policy_version": "1.0.0"},
        {"decision": "deny", "reasons": ["MADE_UP_CODE"], "policy_version": "1.0.0"},
        {"decision": "hold", "reasons": ["SUPPLIER_UNKNOWN", "DUPLICATE_INVOICE"], "policy_version": "1.0.0"},
        {"decision": "allow", "reasons": [], "policy_version": "unknown"},
        {"decision": "allow", "reasons": [], "policy_version": "1.0.0", "extra": 1},
    ],
)
def test_I8_malformed_output_denies(
    engine: WasmPolicyEngine, l1: dict[str, Any], monkeypatch: pytest.MonkeyPatch, bad_output: Any
) -> None:
    monkeypatch.setattr(engine, "_raw_eval", lambda _e: bad_output)
    d = engine.evaluate(l1)
    assert d.decision == "deny"
    assert d.reasons == ("POLICY_ERROR",)


# ---- OPA server fallback guard (never silent) ----


def _server_client(engine: WasmPolicyEngine) -> httpx.Client:
    """A fake OPA server that answers with the real Wasm result."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        try:
            result = engine._policy.evaluate(json.dumps(body["input"]).encode(), eng.ENTRYPOINT)
        except WasmPolicyError:
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"result": result})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_I8_fallback_requires_explicit_sha(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    s = Settings(policy_runtime="opa-server", opa_server_url="http://opa:8181")
    e = build_engine(s, opa_client=_server_client(engine))
    assert e.runtime == "unavailable"
    assert e.evaluate(l1).reasons == ("PARITY_MISMATCH",)


def test_fallback_enabled_only_with_parity(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    s = Settings(policy_runtime="opa-server", opa_server_url="http://opa:8181", policy_sha256=engine.sha256)
    e = build_engine(s, opa_client=_server_client(engine))
    assert e.runtime == "opa-server"
    assert e.evaluate(l1).decision == "allow"


def test_I8_fallback_parity_mismatch_denies(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    def lying_server(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"result": {"decision": "allow", "reasons": [], "policy_version": "1.0.0"}}
        )

    s = Settings(policy_runtime="opa-server", opa_server_url="http://opa:8181", policy_sha256=engine.sha256)
    e = build_engine(s, opa_client=httpx.Client(transport=httpx.MockTransport(lying_server)))
    assert e.runtime == "unavailable"
    assert e.evaluate(l1).reasons == ("PARITY_MISMATCH",)


def test_I8_fallback_server_down_denies(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    state = {"down": False}
    good = _server_client(engine)

    def flaky(request: httpx.Request) -> httpx.Response:
        if state["down"]:
            raise httpx.ConnectError("down")
        return good._transport.handle_request(request)  # type: ignore[attr-defined,no-any-return]

    s = Settings(policy_runtime="opa-server", opa_server_url="http://opa:8181", policy_sha256=engine.sha256)
    e = build_engine(s, opa_client=httpx.Client(transport=httpx.MockTransport(flaky)))
    assert e.runtime == "opa-server"
    state["down"] = True
    assert e.evaluate(l1).reasons == ("POLICY_ERROR",)


def test_decision_latency_recorded(engine: WasmPolicyEngine, l1: dict[str, Any]) -> None:
    d = engine.evaluate(l1)
    assert 0 < d.latency_us < 250_000
