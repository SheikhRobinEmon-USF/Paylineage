"""Fail-closed policy runtime adapter (T0.4, I8).

Every path that is not a clean, schema-valid, self-consistent decision from the
verified policy.wasm becomes `deny` with an explicit fail-closed reason code:

  input fails JSON Schema ............ INPUT_INVALID
  module missing or hash mismatch .... POLICY_ERROR
  host built-in required ............. POLICY_ERROR
  trap, exception, fuel exhausted .... POLICY_ERROR
  empty result set ................... POLICY_UNDEFINED
  malformed or inconsistent output ... POLICY_ERROR
  fallback without parity ............ PARITY_MISMATCH

There is no code path that returns allow without the module saying allow.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from jsonschema import Draft202012Validator

from paylineage.domain.reason_codes import code_class, is_known
from paylineage.policy.wasm_host import OpaWasmPolicy, PolicyTimeoutError, WasmPolicyError
from paylineage.settings import Settings, get_settings

log = logging.getLogger("paylineage.policy")

ENTRYPOINT = "paylineage/decision"
Decision = Literal["allow", "hold", "deny"]
RuntimeName = Literal["wasm", "opa-server", "unavailable"]


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    reasons: tuple[str, ...]
    policy_version: str
    policy_sha256: str
    runtime: RuntimeName
    latency_us: int = 0
    detail: str | None = field(default=None, compare=False)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "runtime": self.runtime,
        }


def fail_closed(code: str, sha: str, runtime: RuntimeName, detail: str | None = None) -> PolicyDecision:
    return PolicyDecision("deny", (code,), "unknown", sha, runtime, 0, detail)


class PolicyEngine(Protocol):
    sha256: str
    runtime: RuntimeName

    def evaluate(self, policy_input: Mapping[str, Any]) -> PolicyDecision: ...


# ---------------- schema ----------------


@lru_cache(maxsize=4)
def _validator(schema_path: Path) -> Draft202012Validator:
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def input_validator(settings: Settings | None = None) -> Draft202012Validator:
    s = settings or get_settings()
    return _validator(s.policy_dir / "schema" / "input.v1.json")


def output_validator(settings: Settings | None = None) -> Draft202012Validator:
    s = settings or get_settings()
    return _validator(s.policy_dir / "schema" / "output.v1.json")


def _check_output(raw: Any, out_validator: Draft202012Validator) -> tuple[Decision, tuple[str, ...], str]:
    """Validate shape and internal consistency. Raises ValueError on any problem."""
    errors = list(out_validator.iter_errors(raw))
    if errors:
        raise ValueError(f"output schema: {errors[0].message}")
    decision: Decision = raw["decision"]
    reasons = tuple(raw["reasons"])
    version = str(raw["policy_version"])
    if list(reasons) != sorted(set(reasons)):
        raise ValueError("reasons not sorted and unique")
    for r in reasons:
        if not is_known(r):
            raise ValueError(f"unknown reason code {r}")
    classes = {code_class(r) for r in reasons}
    if decision == "allow" and reasons:
        raise ValueError("allow with reasons")
    if decision == "hold" and (classes != {"hold"}):
        raise ValueError("hold must carry only hold codes")
    if decision == "deny" and not reasons:
        raise ValueError("deny without reasons")
    if decision == "deny" and "deny" not in classes:
        raise ValueError("deny without a deny-class code")
    if version == "unknown" and decision != "deny":
        raise ValueError("undefined policy version")
    return decision, reasons, version


def _no_constants(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def strict_json_loads(text: str) -> Any:
    """JSON parse that rejects NaN and Infinity, matching JSON.parse in JS."""
    return json.loads(text, parse_constant=_no_constants)


def _encode_input(policy_input: Mapping[str, Any]) -> bytes:
    return json.dumps(policy_input, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


# ---------------- engines ----------------


class UnavailablePolicy:
    """Used when no trustworthy policy could be loaded. Always denies."""

    runtime: RuntimeName = "unavailable"

    def __init__(self, code: str, detail: str, sha: str = "") -> None:
        self.sha256 = sha
        self._code = code
        self._detail = detail

    def evaluate(self, policy_input: Mapping[str, Any]) -> PolicyDecision:
        return fail_closed(self._code, self.sha256, self.runtime, self._detail)


class _ValidatingEngine:
    runtime: RuntimeName
    sha256: str

    def __init__(self, settings: Settings) -> None:
        self._in = input_validator(settings)
        self._out = output_validator(settings)

    def _raw_eval(self, encoded: bytes) -> Any:
        raise NotImplementedError

    def evaluate(self, policy_input: Mapping[str, Any]) -> PolicyDecision:
        start = time.perf_counter_ns()
        try:
            errors = list(self._in.iter_errors(policy_input))
            if errors:
                return fail_closed("INPUT_INVALID", self.sha256, self.runtime, errors[0].message[:200])
            encoded = _encode_input(policy_input)
        except (TypeError, ValueError) as exc:
            return fail_closed("INPUT_INVALID", self.sha256, self.runtime, str(exc)[:200])
        try:
            raw = self._raw_eval(encoded)
        except PolicyTimeoutError as exc:
            log.error("policy timeout: %s", exc)
            return fail_closed("POLICY_ERROR", self.sha256, self.runtime, "timeout")
        except WasmPolicyError as exc:
            detail = str(exc)
            code = "POLICY_UNDEFINED" if "undefined" in detail else "POLICY_ERROR"
            log.error("policy error: %s", detail)
            return fail_closed(code, self.sha256, self.runtime, detail[:200])
        except Exception as exc:  # Any surprise in the authorization path denies.
            log.exception("unexpected policy failure")
            return fail_closed("POLICY_ERROR", self.sha256, self.runtime, type(exc).__name__)
        try:
            decision, reasons, version = _check_output(raw, self._out)
        except (ValueError, KeyError, TypeError) as exc:
            log.error("policy output rejected: %s", exc)
            return fail_closed("POLICY_ERROR", self.sha256, self.runtime, str(exc)[:200])
        latency = (time.perf_counter_ns() - start) // 1000
        return PolicyDecision(decision, reasons, version, self.sha256, self.runtime, latency)


class WasmPolicyEngine(_ValidatingEngine):
    runtime: RuntimeName = "wasm"

    def __init__(self, settings: Settings, wasm_bytes: bytes, sha256: str) -> None:
        super().__init__(settings)
        self.sha256 = sha256
        self._policy = OpaWasmPolicy(wasm_bytes, fuel=settings.policy_fuel)
        if ENTRYPOINT not in self._policy.entrypoints:
            raise WasmPolicyError(f"entrypoint {ENTRYPOINT} missing")

    def _raw_eval(self, encoded: bytes) -> Any:
        return self._policy.evaluate(encoded, ENTRYPOINT)


class OpaServerPolicyEngine(_ValidatingEngine):
    """Explicit fallback only. Never constructed unless POLICY_RUNTIME=opa-server."""

    runtime: RuntimeName = "opa-server"

    def __init__(self, settings: Settings, url: str, sha256: str, client: httpx.Client | None = None) -> None:
        super().__init__(settings)
        self.sha256 = sha256
        self._url = url.rstrip("/") + "/v1/data/paylineage/decision"
        self._client = client or httpx.Client(timeout=0.5)

    def _raw_eval(self, encoded: bytes) -> Any:
        try:
            resp = self._client.post(self._url, content=b'{"input":' + encoded + b"}")
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise WasmPolicyError(f"opa server unavailable: {type(exc).__name__}") from exc
        if not isinstance(body, dict) or "result" not in body:
            raise WasmPolicyError("policy result undefined")
        return body["result"]


# ---------------- loading and self test ----------------


@lru_cache(maxsize=4)
def _configured_version(policy_dir: Path) -> str:
    cfg = json.loads((policy_dir / "data" / "config.v1.json").read_text())
    return str(cfg["config"]["policy_version"])


def configured_policy_version(settings: Settings | None = None) -> str:
    """The policy version compiled into policy.wasm (from the same config file)."""
    return _configured_version((settings or get_settings()).policy_dir)


def read_expected_sha(settings: Settings) -> str:
    line = settings.policy_sha256_path.read_text().strip().split()
    if not line or len(line[0]) != 64:
        raise ValueError("policy.sha256 malformed")
    return line[0]


def vector_paths(settings: Settings) -> list[Path]:
    return sorted((settings.policy_dir / "vectors" / "decision").glob("*.json"))


def run_vectors(engine: PolicyEngine, paths: list[Path]) -> list[str]:
    """Run shared decision vectors. Returns a list of mismatch descriptions."""
    mismatches: list[str] = []
    for path in paths:
        vec = json.loads(path.read_text())
        policy_input = vec.get("input")
        if "input_raw" in vec:
            try:
                policy_input = strict_json_loads(vec["input_raw"])
            except ValueError:
                policy_input = None
        got = (
            engine.evaluate(policy_input)
            if isinstance(policy_input, dict)
            else fail_closed("INPUT_INVALID", engine.sha256, engine.runtime)
        )
        want = vec["expected"]
        if got.decision != want["decision"] or list(got.reasons) != want["reasons"]:
            mismatches.append(f"{path.name}: want {want} got {got.decision} {list(got.reasons)}")
    return mismatches


def build_engine(settings: Settings | None = None, *, opa_client: httpx.Client | None = None) -> PolicyEngine:
    """Load the configured runtime. Every failure returns an always-deny engine."""
    s = settings or get_settings()
    try:
        expected = read_expected_sha(s)
        wasm = s.policy_wasm_path.read_bytes()
    except (OSError, ValueError) as exc:
        log.critical("policy not loadable: %s", exc)
        return UnavailablePolicy("POLICY_ERROR", f"policy not loadable: {exc}")
    actual = hashlib.sha256(wasm).hexdigest()
    if actual != expected or (s.policy_sha256 is not None and s.policy_sha256 != actual):
        log.critical("policy.wasm hash mismatch: %s", actual)
        return UnavailablePolicy("POLICY_ERROR", "policy.wasm hash mismatch", actual)

    if s.policy_runtime == "opa-server":
        if not s.opa_server_url or s.policy_sha256 != actual:
            return UnavailablePolicy(
                "PARITY_MISMATCH", "opa-server needs OPA_SERVER_URL and POLICY_SHA256", actual
            )
        server = OpaServerPolicyEngine(s, s.opa_server_url, actual, opa_client)
        mismatches = run_vectors(server, vector_paths(s))
        if mismatches:
            log.critical("opa-server parity failed: %s", mismatches[:3])
            return UnavailablePolicy("PARITY_MISMATCH", f"{len(mismatches)} vector mismatches", actual)
        log.warning("POLICY RUNTIME IS THE OPA SERVER FALLBACK (explicitly enabled, parity passed)")
        return server

    try:
        return WasmPolicyEngine(s, wasm, actual)
    # Loading must never raise; an unloadable policy denies everything.
    except Exception as exc:  # noqa: BLE001
        log.critical("policy.wasm rejected: %s", exc)
        return UnavailablePolicy("POLICY_ERROR", str(exc)[:200], actual)


_engine_factory: Callable[[], PolicyEngine] = build_engine


@lru_cache(maxsize=1)
def get_engine() -> PolicyEngine:
    return _engine_factory()
