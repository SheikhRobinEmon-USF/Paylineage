"""Hand-planted Rego mutants (EVALUATION: every critical mutant killed).

Each mutant weakens one security rule. The OPA test suite must fail on every
mutant; a surviving mutant means a rule has no test that would notice it gone.

Usage: uv run python policy/scripts/rego_mutants.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build import stage  # noqa: E402

# (name, file, original text, mutated text)
MUTANTS: list[tuple[str, str, str, str]] = [
    ("default allow", "decision.rego", '"decision": "deny", "reasons": ["POLICY_UNDEFINED"]',
     '"decision": "allow", "reasons": []'),
    ("gate ignored", "decision.rego", '} else := "allow" if {\n\tgate == true\n}', '} else := "allow"'),
    ("deny loses to hold", "decision.rego", 'count(deny) > 0\n} else := "hold" if {', 'count(deny) > 99\n} else := "hold" if {'),
    ("ceiling off by one", "mandate.rego", "p.record.amount_minor <= p.mandate.per_proposal_ceiling_minor",
     "p.record.amount_minor <= p.mandate.per_proposal_ceiling_minor + 1"),
    ("revocation ignored", "mandate.rego", "\tp.mandate.revoked == false\n", "\ttrue\n"),
    ("expiry boundary", "mandate.rego", "now < p.mandate.expires_at_ms\n}", "now <= p.mandate.expires_at_ms\n}"),
    ("never-ops dropped", "mandate.rego", "\tnot p.operation in cfg.agent_never_operations\n}", "}"),
    ("scope ignored", "mandate.rego", '"*" in p.mandate.supplier_scope', "true"),
    ("trust from client", "provenance.rego", "f.trust_class != cfg.trust_class_by_source[f.source_kind]", "false"),
    ("unmatched untrusted is trusted", "provenance.rego",
     'f.trust_class == "untrusted_external"\n\tf.master_matched == true', 'f.trust_class == "untrusted_external"'),
    ("pending account payable", "provenance.rego", 'p.beneficiary.status == "verified"\n\tp.beneficiary.supplier_id',
     'p.beneficiary.status in {"verified", "pending"}\n\tp.beneficiary.supplier_id'),
    ("cooling-off ignored", "provenance.rego", "now < b.cooling_off_until_ms", "false"),
    ("beneficiary hold dropped", "provenance.rego", 'payment_hold contains "BENEFICIARY_NOT_VERIFIED" if {\n\tp.beneficiary == null\n}',
     'payment_hold contains "BENEFICIARY_NOT_VERIFIED" if {\n\tfalse\n}'),
    ("duplicate not held", "provenance.rego", "\tp.duplicate_invoice == true\n", "\tfalse\n"),
    ("signals never hold", "provenance.rego", "severity_rank(s.severity) >= hold_min_rank", "false"),
    ("approval digest ignored", "approval.rego", "\ta.digest == p.record.digest\n\ta.payment_version", "\ta.payment_version"),
    ("expired approval valid", "approval.rego", "\tnow < a.expires_at_ms\n\ta.approver_active", "\ta.approver_active"),
    ("sod ignored", "approval.rego", "\tnot a.approver_id in sod_conflicted\n", ""),
    ("one approver always enough", "approval.rego", "} else := 1", "} else := 0"),
    ("permit replay", "approval.rego", "\tp.permit.consumed == false\n\tnow < p.permit.expires_at_ms", "\tnow < p.permit.expires_at_ms"),
    ("permit expiry", "approval.rego", "\tnow < p.permit.expires_at_ms\n\tp.permit.digest", "\tp.permit.digest"),
    ("requester verifies", "onboarding.rego", "\to.actor_id == o.requester_id\n}", "\tfalse\n}"),
    ("invoice contact ok", "onboarding.rego", '\tv.contact_source == "on_file"\n', ""),
    ("steward is verifier", "onboarding.rego", "\to.action == \"steward_approve\"\n\to.actor_id == o.verifier_id", "\tfalse"),
]


def run_tests(stage_dir: Path, opa: str) -> bool:
    """True if the suite passes (mutant survived)."""
    proc = subprocess.run([opa, "test", str(stage_dir), str(ROOT / "tests")], capture_output=True, text=True)
    return proc.returncode == 0


def main() -> int:
    opa = shutil.which("opa") or "opa"
    base = stage()
    if not run_tests(base, opa):
        print("baseline policy tests fail; fix them first")
        return 2
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, file, original, mutated in MUTANTS:
            work = Path(tmp) / name.replace(" ", "_")
            shutil.copytree(base, work)
            target = work / "paylineage" / file
            src = target.read_text()
            if original not in src:
                print(f"  ?? {name}: pattern not found (mutant needs updating)")
                survived.append(name)
                continue
            target.write_text(src.replace(original, mutated, 1))
            alive = run_tests(work, opa)
            print(f"  {'SURVIVED' if alive else 'killed  '}  {name}")
            if alive:
                survived.append(name)
    print(f"{len(MUTANTS) - len(survived)}/{len(MUTANTS)} Rego mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
