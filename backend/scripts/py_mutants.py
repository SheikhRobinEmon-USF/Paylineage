"""Hand-planted Python mutants for the authorization path (make mutation).

Each mutant weakens one guard in policy, approvals, permits or the executor.
The backend suite must fail on every one; a surviving mutant names a guard that
no test would notice gone. This replaces mutmut, which cannot map mutants to
tests in this workspace layout (docs/STATUS.md).

The checkout is never edited. Each mutant is applied to a temporary copy of
backend/src/paylineage, which goes first on PYTHONPATH. Mutants run one at a
time against the single test database.

Usage: uv run python backend/scripts/py_mutants.py [name-substring ...]
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "src" / "paylineage"
PYTEST = [
    sys.executable,
    "-m",
    "pytest",
    "backend/tests",
    "-m",
    "not deep",
    "-x",
    "-q",
    "-p",
    "no:cacheprovider",
]

# (name, module path under paylineage/, original text, mutated text)
MUTANTS: list[tuple[str, str, str, str]] = [
    # ---- executor: one permit, one execution (I5) ----
    (
        "consume ignores consumed_at",
        "executor/service.py",
        "WHERE id = :id AND consumed_at IS NULL AND expires_at > :now",
        "WHERE id = :id AND expires_at > :now",
    ),
    (
        "consume ignores permit expiry",
        "executor/service.py",
        "WHERE id = :id AND consumed_at IS NULL AND expires_at > :now",
        "WHERE id = :id AND consumed_at IS NULL",
    ),
    (
        "consume result ignored",
        "executor/service.py",
        "    if not consume(ctx, permit_id, request_id, now):",
        "    if not (consume(ctx, permit_id, request_id, now) or True):",
    ),
    (
        "execute skips policy revalidation",
        "executor/service.py",
        "    if not d.allowed or p.state != PaymentState.PERMIT_ISSUED.value:",
        "    if p.state != PaymentState.PERMIT_ISSUED.value:",
    ),
    (
        "execute skips state check",
        "executor/service.py",
        "    if not d.allowed or p.state != PaymentState.PERMIT_ISSUED.value:",
        "    if not d.allowed:",
    ),
    # ---- permits: revalidate before issuing (R1) ----
    (
        "permit issued without revalidation",
        "permits/service.py",
        '    if not d.allowed:\n        if "APPROVAL_EXPIRED" in d.reasons:',
        '    if False:\n        if "APPROVAL_EXPIRED" in d.reasons:',
    ),
    (
        "permit lives ten times longer",
        "permits/service.py",
        "PERMIT_TTL = timedelta(minutes=2)",
        "PERMIT_TTL = timedelta(minutes=20)",
    ),
    # ---- approvals: bound to the canonical digest (I4) ----
    (
        "challenge commitment not checked",
        "approvals/service.py",
        "    if expected != ch.challenge:",
        "    if False:",
    ),
    (
        "record change after challenge accepted",
        "approvals/service.py",
        "    if p.version != ch.payment_version or compute_digest(p) != ch.digest:",
        "    if False:",
    ),
    (
        "approval from any state",
        "approvals/service.py",
        '    if p.state != PaymentState.AWAITING_APPROVAL.value:\n        raise ConflictError("ILLEGAL_TRANSITION", f"payment is {p.state}")\n',
        '    if False:\n        raise ConflictError("ILLEGAL_TRANSITION", f"payment is {p.state}")\n',
    ),
    (
        "hold treated as approvable",
        "approvals/service.py",
        'if d.decision == "deny" or (d.decision == "hold" and set(d.reasons) != {"SECOND_APPROVAL_REQUIRED"}):',
        'if d.decision == "deny":',
    ),
    (
        "anyone revokes an approval",
        "approvals/service.py",
        'if actor.id != a.approver_id and not actor.has("admin"):',
        "if False:",
    ),
    # ---- policy engine: fail closed (rule 2) ----
    (
        "input schema not enforced",
        "policy/engine.py",
        '            if errors:\n                return fail_closed("INPUT_INVALID"',
        '            if False:\n                return fail_closed("INPUT_INVALID"',
    ),
    (
        "unknown reason code accepted",
        "policy/engine.py",
        "        if not is_known(r):",
        "        if False:",
    ),
    (
        "allow with reasons accepted",
        "policy/engine.py",
        '    if decision == "allow" and reasons:',
        "    if False:",
    ),
    (
        "hold with deny codes accepted",
        "policy/engine.py",
        '    if decision == "hold" and (classes != {"hold"}):',
        "    if False:",
    ),
    (
        "undefined policy version accepted",
        "policy/engine.py",
        '    if version == "unknown" and decision != "deny":',
        "    if False:",
    ),
    (
        "surprise exception allows",
        "policy/engine.py",
        '            return fail_closed("POLICY_ERROR", self.sha256, self.runtime, type(exc).__name__)',
        '            return PolicyDecision("allow", (), "1.0.0", self.sha256, self.runtime, 0)',
    ),
    (
        "wasm hash pin ignored",
        "policy/engine.py",
        "    if actual != expected or (s.policy_sha256 is not None and s.policy_sha256 != actual):",
        "    if False:",
    ),
    (
        "opa-server fallback without a pin",
        "policy/engine.py",
        "        if not s.opa_server_url or s.policy_sha256 != actual:",
        "        if not s.opa_server_url:",
    ),
    # ---- idempotency ----
    (
        "no lock on idempotency key",
        "payments/service.py",
        '    idempotency_lock(ctx.session, f"agent:{agent.id}", prop.idempotency_key)\n',
        "",
    ),
]


def run_suite(pythonpath: Path) -> tuple[bool, float]:
    """True if the suite passes (mutant survived)."""
    env = {**os.environ, "PYTHONPATH": str(pythonpath), "PAYLINEAGE_ROOT": str(ROOT)}
    start = time.monotonic()
    proc = subprocess.run(PYTEST, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    return proc.returncode == 0, time.monotonic() - start


def main(argv: list[str]) -> int:
    wanted = [m for m in MUTANTS if not argv or any(a in m[0] for a in argv)]
    with tempfile.TemporaryDirectory(prefix="py-mutants-") as tmp:
        base = Path(tmp) / "base"
        shutil.copytree(SRC, base / "paylineage", ignore=shutil.ignore_patterns("__pycache__"))
        alive, secs = run_suite(base)
        if not alive:
            print("baseline backend suite fails; fix it first")
            return 2
        print(f"baseline passes in {secs:.0f}s; running {len(wanted)} mutants")
        survived: list[str] = []
        for name, module, original, mutated in wanted:
            work = Path(tmp) / "work"
            if work.exists():
                shutil.rmtree(work)
            shutil.copytree(base, work)
            target = work / "paylineage" / module
            text = target.read_text()
            if text.count(original) != 1:
                print(f"  ??        {name}: pattern not found exactly once (mutant needs updating)")
                survived.append(name)
                continue
            target.write_text(text.replace(original, mutated, 1))
            alive, secs = run_suite(work)
            print(f"  {'SURVIVED' if alive else 'killed  '}  {name} ({secs:.0f}s)")
            if alive:
                survived.append(name)
    print(f"{len(wanted) - len(survived)}/{len(wanted)} Python mutants killed")
    for s in survived:
        print(f"  survived: {s}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
