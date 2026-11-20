"""Export fixtures for the static demo (apps/demo) from the real system.

Seeds an evaluation database through the real pipeline, then exports for every
payment: the UI detail view and the exact evaluate-stage policy input the
backend used. The browser re-runs that input with the same policy.wasm and
recomputes every digest, so the demo shows parity rather than claiming it.

  uv run python -m paylineage.eval.export_demo [--db URL]
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from paylineage.api import views
from paylineage.db.models import Payment, Supplier, User
from paylineage.eval.run import eval_engine, migrate
from paylineage.policy.engine import read_expected_sha
from paylineage.policy.input_builder import build_payment_input
from paylineage.settings import REPO_ROOT, get_settings

OUT = REPO_ROOT / "apps" / "demo" / "src" / "fixtures" / "demo.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--db",
        default=os.environ.get(
            "EVAL_DATABASE_URL",
            "postgresql+psycopg://paylineage:paylineage_dev@localhost:5432/paylineage_test",
        ),
    )
    args = ap.parse_args()
    engine = eval_engine(args.db)
    migrate(engine)
    os.environ["DATABASE_URL"] = args.db
    from paylineage.db import base

    get_settings.cache_clear()
    base.get_engine.cache_clear()
    base.get_sessionmaker.cache_clear()
    from paylineage.db.seed import seed

    seed(reset=True)
    out: dict[str, Any] = {
        "generated_by": "paylineage.eval.export_demo",
        "policy_sha256": read_expected_sha(get_settings()),
    }
    with Session(engine) as s:
        payments = s.execute(select(Payment).order_by(Payment.created_at)).scalars().all()
        out["payments"] = []
        for p in payments:
            detail = views.payment_detail(s, p)
            op = str((p.last_decision or {}).get("requested_operation", "propose_payment"))
            pin, _ = build_payment_input(s, p, stage="evaluate", now=p.updated_at, operation=op)
            out["payments"].append({"detail": detail, "input": pin})
        out["suppliers"] = [
            views.supplier_detail(s, x)
            for x in s.execute(select(Supplier).order_by(Supplier.legal_name)).scalars()
        ]
        out["agents"] = views.agents_view(s)
        out["personas"] = [
            {"handle": u.email.split("@")[0], "name": u.display_name, "roles": u.roles, "id": u.id}
            for u in s.execute(select(User).order_by(User.email)).scalars()
        ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, default=str) + "\n")
    print(f"wrote {OUT.relative_to(REPO_ROOT)} with {len(out['payments'])} payments")


if __name__ == "__main__":
    main()
