"""Read `opa test --coverage --format=json` from stdin and fail under a threshold.

Also fails if any test failed. Usage: opa test ... | python coverage_gate.py 95
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    threshold = float(sys.argv[1]) if len(sys.argv) > 1 else 95.0
    raw = sys.stdin.read()
    doc = json.loads(raw)
    files = doc.get("files", {})
    pct = float(doc.get("coverage", 0.0))
    low = {
        name: f.get("coverage", 0.0)
        for name, f in files.items()
        if "/tests/" not in name and float(f.get("coverage", 0.0)) < threshold
    }
    for name, cov in sorted(low.items()):
        print(f"  {cov:6.2f}%  {name}")
    print(f"policy coverage {pct:.2f}% (threshold {threshold}%)")
    return 1 if pct < threshold else 0


if __name__ == "__main__":
    sys.exit(main())
