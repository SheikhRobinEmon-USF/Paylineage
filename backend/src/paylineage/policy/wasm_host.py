"""Minimal, audited host for OPA-compiled Wasm policies (ABI 1.2+, fastpath eval).

Why our own host (ADR-010): the PyPI `opa-wasm` SDK runs on wasmer, which does
not support Python above 3.10, and the small `opa-wasmtime` package has no fuel
metering. Authorization code needs a hard compute budget (timeouts must deny,
I8) and must refuse modules that import host built-ins (unsupported built-ins
must deny). This host does exactly that and nothing else.

ABI reference: https://www.openpolicyagent.org/docs/wasm (opa_eval fastpath).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import wasmtime


class WasmPolicyError(Exception):
    """Any failure inside the Wasm host. Callers must turn it into deny."""


class UnsupportedBuiltinError(WasmPolicyError):
    pass


class PolicyTimeoutError(WasmPolicyError):
    pass


_MAX_RESULT_BYTES = 1 << 20  # 1 MiB of result JSON is far beyond any legitimate decision.
_MAX_INPUT_BYTES = 1 << 20


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON number {name}")


def _strict_loads(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_constant)


class OpaWasmPolicy:
    """One compiled module and one instance. Thread safe via a lock.

    The heap is reset to its post-instantiation mark before every evaluation, so
    no evaluation can observe memory from the previous one.
    """

    # Instantiation runs OPA's own initializer once; give it a fixed, generous budget
    # so a small per-evaluation budget cannot break loading.
    INIT_FUEL = 2_000_000_000

    def __init__(self, wasm_bytes: bytes, *, fuel: int, max_memory_pages: int = 1024) -> None:
        try:
            self._init(wasm_bytes, fuel=fuel, max_memory_pages=max_memory_pages)
        except WasmPolicyError:
            raise
        except (wasmtime.WasmtimeError, wasmtime.Trap, ValueError, KeyError, TypeError) as exc:
            raise WasmPolicyError(f"module rejected: {type(exc).__name__}: {str(exc)[:200]}") from exc

    def _init(self, wasm_bytes: bytes, *, fuel: int, max_memory_pages: int) -> None:
        self._fuel = fuel
        self._lock = threading.Lock()
        config = wasmtime.Config()
        config.consume_fuel = True
        engine = wasmtime.Engine(config)
        self._store = wasmtime.Store(engine)
        module = wasmtime.Module(engine, wasm_bytes)

        min_pages = 2
        for imp in module.imports:
            if imp.module == "env" and imp.name == "memory":
                ty = imp.type
                if isinstance(ty, wasmtime.MemoryType):
                    min_pages = max(min_pages, ty.limits.min)
        self._memory = wasmtime.Memory(
            self._store, wasmtime.MemoryType(wasmtime.Limits(min_pages, max(min_pages, max_memory_pages)))
        )

        linker = wasmtime.Linker(engine)
        linker.define(self._store, "env", "memory", self._memory)
        i32 = wasmtime.ValType.i32()

        def abort(addr: int) -> None:
            raise WasmPolicyError(f"opa_abort: {self._read_cstr(addr, 4096)}")

        def println(addr: int) -> None:  # Policies must not print; ignore quietly.
            return None

        def make_builtin(n: int) -> wasmtime.Func:
            def call(*_args: int) -> int:
                raise UnsupportedBuiltinError(f"host built-in call (arity {n}) is not supported")

            return wasmtime.Func(self._store, wasmtime.FuncType([i32] * (n + 2), [i32]), call)

        linker.define(
            self._store, "env", "opa_abort", wasmtime.Func(self._store, wasmtime.FuncType([i32], []), abort)
        )
        linker.define(
            self._store,
            "env",
            "opa_println",
            wasmtime.Func(self._store, wasmtime.FuncType([i32], []), println),
        )
        for n in range(5):
            linker.define(self._store, "env", f"opa_builtin{n}", make_builtin(n))

        self._store.set_fuel(self.INIT_FUEL)
        instance = linker.instantiate(self._store, module)
        self._exports = instance.exports(self._store)

        major = self._global("opa_wasm_abi_version")
        minor = self._global("opa_wasm_abi_minor_version")
        if major != 1 or minor < 2:
            raise WasmPolicyError(f"unsupported OPA Wasm ABI {major}.{minor}")

        builtins = self._read_json(self._call("builtins"))
        if not isinstance(builtins, dict):
            raise WasmPolicyError("builtins() did not return an object")
        if builtins:
            raise UnsupportedBuiltinError(f"policy needs host built-ins: {sorted(builtins)}")
        self.required_builtins: dict[str, int] = builtins

        entrypoints = self._read_json(self._call("entrypoints"))
        if not isinstance(entrypoints, dict):
            raise WasmPolicyError("entrypoints() did not return an object")
        self.entrypoints: dict[str, int] = {str(k): int(v) for k, v in entrypoints.items()}

        # Empty data document; all policy data is compiled into the module.
        self._data_addr = self._load_json_value(b"{}")
        self._base_heap = int(self._call("opa_heap_ptr_get"))

    # ---- low level helpers ----

    def _global(self, name: str) -> int:
        g = self._exports[name]
        if not isinstance(g, wasmtime.Global):
            raise WasmPolicyError(f"{name} is not a global")
        return int(g.value(self._store))

    def _call(self, name: str, *args: int) -> int:
        fn = self._exports[name]
        if not isinstance(fn, wasmtime.Func):
            raise WasmPolicyError(f"{name} is not a function")
        try:
            out = fn(self._store, *args)
        except wasmtime.Trap as exc:
            if "fuel" in str(exc).lower():
                raise PolicyTimeoutError("policy evaluation exceeded its compute budget") from exc
            raise WasmPolicyError(f"trap in {name}: {exc}") from exc
        except wasmtime.WasmtimeError as exc:
            if "fuel" in str(exc).lower():
                raise PolicyTimeoutError("policy evaluation exceeded its compute budget") from exc
            raise WasmPolicyError(f"wasmtime error in {name}: {exc}") from exc
        return int(out) if out is not None else 0

    def _read_cstr(self, addr: int, limit: int) -> str:
        data = self._memory.read(self._store, addr, min(addr + limit, self._memory.data_len(self._store)))
        end = data.find(b"\x00")
        if end < 0:
            raise WasmPolicyError("unterminated string in Wasm memory")
        return data[:end].decode("utf-8")

    def _read_json(self, value_addr: int) -> Any:
        str_addr = self._call("opa_json_dump", value_addr)
        return _strict_loads(self._read_cstr(str_addr, _MAX_RESULT_BYTES))

    def _write_bytes(self, raw: bytes) -> int:
        addr = self._call("opa_malloc", len(raw))
        self._memory.write(self._store, raw, addr)
        return addr

    def _load_json_value(self, raw: bytes) -> int:
        addr = self._write_bytes(raw)
        value = self._call("opa_json_parse", addr, len(raw))
        if value == 0:
            raise WasmPolicyError("opa_json_parse failed")
        return value

    # ---- public API ----

    def evaluate(self, input_json: bytes, entrypoint: str) -> Any:
        """Evaluate one entrypoint. Returns the `result` value, or raises."""
        if len(input_json) > _MAX_INPUT_BYTES:
            raise WasmPolicyError("input too large")
        if entrypoint not in self.entrypoints:
            raise WasmPolicyError(f"unknown entrypoint {entrypoint}")
        ep = self.entrypoints[entrypoint]
        with self._lock:
            self._store.set_fuel(self._fuel)
            self._call("opa_heap_ptr_set", self._base_heap)
            input_addr = self._write_bytes(input_json)
            heap = int(self._call("opa_heap_ptr_get"))
            result_addr = self._call("opa_eval", 0, ep, self._data_addr, input_addr, len(input_json), heap, 0)
            text = self._read_cstr(result_addr, _MAX_RESULT_BYTES)
            self._call("opa_heap_ptr_set", self._base_heap)
        results = _strict_loads(text)
        if not isinstance(results, list):
            raise WasmPolicyError("result set is not a list")
        if len(results) != 1 or not isinstance(results[0], dict) or "result" not in results[0]:
            # Empty result set means the entrypoint is undefined.
            raise WasmPolicyError("policy result undefined")
        return results[0]["result"]


def load_policy(path: Path, *, fuel: int) -> OpaWasmPolicy:
    return OpaWasmPolicy(path.read_bytes(), fuel=fuel)
