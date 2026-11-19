"""`make parity` (T0.6): run shared vectors through Python and Node; they must match.

Checks, in order:
  1. Python decision for every vector equals its hand-written expectation.
  2. Node decision for every vector equals its hand-written expectation.
  3. Python and Node agree with each other line for line.
  4. Python canonical digests match every digest vector (Node checks the same
     vectors in packages/canonical vitest).
Any mismatch exits non-zero, so CI fails.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from paylineage.canonical import CanonicalError, canonical_bytes, sha256_hex
from paylineage.policy.engine import (
    build_engine,
    fail_closed,
    strict_json_loads,
    vector_paths,
)
from paylineage.settings import get_settings


def python_results() -> list[dict[str, object]]:
    engine = build_engine()
    if engine.runtime != "wasm":
        raise SystemExit(f"python runtime unavailable: {engine.runtime}")
    out: list[dict[str, object]] = []
    for path in vector_paths(get_settings()):
        vec = json.loads(path.read_text())
        inp = vec.get("input")
        bad_parse = False
        if "input_raw" in vec:
            try:
                inp = strict_json_loads(vec["input_raw"])
            except ValueError:
                bad_parse = True
        d = fail_closed("INPUT_INVALID", engine.sha256, engine.runtime) if bad_parse else engine.evaluate(inp)
        out.append(
            {
                "name": vec["name"],
                "decision": d.decision,
                "reasons": list(d.reasons),
                "expected": vec["expected"],
            }
        )
    return out


def node_results() -> list[dict[str, object]]:
    proc = subprocess.run(
        ["node", str(ROOT / "packages/policy-runtime/scripts/run-vectors.ts"), str(ROOT / "policy")],
        check=True,
        capture_output=True,
        text=True,
    )
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def digest_mismatches() -> list[str]:
    bad: list[str] = []
    for path in sorted((ROOT / "policy/vectors/digest").glob("*.json")):
        vec = json.loads(path.read_text())
        exp = vec["expected"]
        try:
            b = canonical_bytes(strict_json_loads(vec["value_raw"]))
        except CanonicalError:
            if not exp.get("error"):
                bad.append(f"{vec['name']}: python raised")
            continue
        if exp.get("error"):
            bad.append(f"{vec['name']}: python accepted an error vector")
        elif b.decode() != exp["canonical"] or sha256_hex(b) != exp["sha256"]:
            bad.append(f"{vec['name']}: python digest differs")
    return bad


def main() -> int:
    py = python_results()
    node = node_results()
    problems: list[str] = []
    if len(py) != len(node):
        problems.append(f"vector count differs: python {len(py)} node {len(node)}")
    for p, n in zip(py, node, strict=False):
        exp = p["expected"]
        assert isinstance(exp, dict)
        if p["name"] != n["name"]:
            problems.append(f"order differs: {p['name']} vs {n['name']}")
            continue
        if [p["decision"], p["reasons"]] != [exp["decision"], exp["reasons"]]:
            problems.append(f"python {p['name']}: {p['decision']} {p['reasons']} != {exp}")
        if [n["decision"], n["reasons"]] != [exp["decision"], exp["reasons"]]:
            problems.append(f"node {n['name']}: {n['decision']} {n['reasons']} != {exp}")
        if [p["decision"], p["reasons"]] != [n["decision"], n["reasons"]]:
            problems.append(f"PARITY_MISMATCH {p['name']}: python {p['reasons']} node {n['reasons']}")
    problems += digest_mismatches()
    if problems:
        print("\n".join(problems))
        print(f"parity FAILED: {len(problems)} problems")
        return 1
    n_dig = len(list((ROOT / "policy/vectors/digest").glob("*.json")))
    print(f"parity OK: {len(py)} decision vectors identical in Python and Node; {n_dig} digest vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
