"""Seed a fictional organization and a realistic queue through the real pipeline (make seed).

Every value is fictional. Suppliers are onboarded by three different people,
emails are generated scenarios, the agent proposes through the same service the
signed API uses, and the policy decides. Nothing is written around the policy.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from paylineage.agents.planner import AdversarialPlanner, DeterministicPlanner, PlannerInput
from paylineage.audit.checkpoint import load_or_create_key
from paylineage.db.base import get_engine
from paylineage.domain.clock import FrozenClock
from paylineage.domain.enums import OldAccountOutcome
from paylineage.eval.scenarios import CATALOG, generate
from paylineage.eval.world import World
from paylineage.extraction.extractors import DeterministicExtractor
from paylineage.ingestion.pipeline import ingest_email
from paylineage.payments import service as payments
from paylineage.policy.engine import build_engine
from paylineage.settings import REPO_ROOT

QUEUE = ["L1", "L1", "S1", "S2", "S3", "S4", "S6", "S7", "S9", "L1", "S5", "L2", "S8"]


def agent_key_path() -> Path:
    return Path(os.environ.get("AGENT_KEY_PATH") or REPO_ROOT / "var" / "keys" / "agent_ed25519.pem")


def is_seeded() -> bool:
    """Payments are written last, so a seed that crashed half way reads as not seeded."""
    with get_engine().connect() as c:
        return bool(c.execute(text("SELECT EXISTS (SELECT 1 FROM payments)")).scalar())


def seed(*, reset: bool = True) -> None:
    engine = get_engine()
    if reset:
        with engine.begin() as c:
            tables = [
                r[0]
                for r in c.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"
                    )
                )
            ]
            c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
            c.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
            c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))
    now = datetime.now(UTC).replace(microsecond=0)
    clock = FrozenClock(now - timedelta(days=45))
    w = World(sessionmaker(bind=engine, expire_on_commit=False), clock, build_engine())
    w.setup_people()
    # Reuse the agent key from `make keys` (or the compose secret) so the running
    # agent and the seeded public key always match. Created only when absent.
    w.setup_agent(
        scope=["*"],
        ceiling=5_000_000,
        daily=100_000_000,
        second_above=2_500_000,
        key=load_or_create_key(agent_key_path(), allow_create=True),
    )
    sids = {}
    for sup in CATALOG[:4]:
        sid, _ = w.verified_supplier(sup.legal_name, sup.registry_id, sup.domain, sup.account, sup.bank)
        sids[sup.key] = sid
    clock.advance(timedelta(days=30))
    insts = [i for i in generate(1) if i.supplier in sids]
    by_t: dict[str, list] = {}  # type: ignore[type-arg]
    for i in insts:
        by_t.setdefault(i.template, []).append(i)
    used: set[str] = set()
    changing: set[str] = set()  # one open bank change per supplier
    for n, tid in enumerate(QUEUE):
        needs_change = tid in ("S1", "S4", "L2")
        inst = next(
            i for i in by_t[tid] if i.id not in used and not (needs_change and i.supplier in changing)
        )
        used.add(inst.id)
        if needs_change:
            changing.add(inst.supplier)
        sid = sids[inst.supplier]
        w.purchase_order(sid, inst.po_number, inst.amount_minor)
        if tid in ("S1", "S4", "L2"):
            w.bank_change(
                sid, inst.attacker_account, recorder="ap2", channel="email", old=OldAccountOutcome.STILL_VALID
            )
        clock.advance(timedelta(hours=3))
        with w.tx() as ctx:
            ing = ingest_email(ctx, inst.eml.encode(), DeterministicExtractor(), scenario_id=inst.id)
        planner = (
            DeterministicPlanner()
            if tid not in ("S8", "S9")
            else AdversarialPlanner(
                account=inst.attacker_account if tid == "S9" else None,
                operation="change_bank_details" if tid == "S8" else "propose_payment",
            )
        )
        plan = planner.plan(PlannerInput(ing.invoice_id, ing.supplier_id, ing.fields), key=f"seed-{n}")
        with w.tx() as ctx:
            payments.propose(ctx, w.agent, plan.proposal, signature_valid=True)
    clock.set(now)
    print(
        f"seeded {len(QUEUE)} payments, {len(sids)} suppliers, {len(w.users)} people. "
        f"Sign in with any persona (dev only). Agent key: {agent_key_path()}"
    )


if __name__ == "__main__":
    if "--if-empty" in sys.argv and is_seeded():
        print("database already seeded; leaving it alone")
    else:
        seed(reset="--no-reset" not in sys.argv)
