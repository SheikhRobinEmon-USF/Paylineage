"""Create the local development keys (make keys). Simulation only, never production keys.

var/keys/checkpoint_ed25519.pem  signs audit checkpoints (I11), held outside the database
var/keys/agent_ed25519.pem       the simulated AP agent's request signing key (RFC 9421)

Existing files are kept, so rerunning never rotates a key behind the database's back.
"""

from __future__ import annotations

import sys
from pathlib import Path

from paylineage.audit.checkpoint import load_or_create_key
from paylineage.settings import REPO_ROOT

KEYS = ("checkpoint_ed25519.pem", "agent_ed25519.pem")


def ensure_keys(directory: Path) -> list[Path]:
    made = []
    for name in KEYS:
        path = directory / name
        if not path.exists():
            load_or_create_key(path, allow_create=True)
            made.append(path)
        # Owner read and write, group read: containers join this group (compose group_add).
        path.chmod(0o640)
    return made


def main() -> None:
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "var" / "keys"
    made = ensure_keys(directory)
    for p in made:
        print(f"created {p}")
    if not made:
        print(f"keys already present in {directory}")


if __name__ == "__main__":
    main()
