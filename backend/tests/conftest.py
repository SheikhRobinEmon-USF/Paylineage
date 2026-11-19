"""Shared test configuration: Hypothesis budgets and the PostgreSQL fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, settings
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

settings.register_profile("fast", max_examples=200, deadline=None)
settings.register_profile(
    "deep", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile("dev", max_examples=50, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))

TEST_DB = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://paylineage:paylineage_dev@localhost:5432/paylineage_test"
)
T0 = datetime(2026, 11, 2, 15, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    from alembic import command
    from alembic.config import Config

    eng = create_engine(TEST_DB, pool_size=20, max_overflow=20)
    try:
        with eng.begin() as c:
            c.execute(text("DROP SCHEMA public CASCADE"))
            c.execute(text("CREATE SCHEMA public"))
    except Exception as exc:  # pragma: no cover - environment
        pytest.skip(f"PostgreSQL not reachable at TEST_DATABASE_URL: {exc}")
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.attributes["url"] = TEST_DB
    command.upgrade(cfg, "head")
    yield eng
    eng.dispose()


def reset_db(maker_or_engine) -> None:  # type: ignore[no-untyped-def]
    eng = maker_or_engine.kw["bind"] if isinstance(maker_or_engine, sessionmaker) else maker_or_engine
    with eng.begin() as c:
        tables = [
            r[0]
            for r in c.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname='public' AND tablename <> 'alembic_version'"
                )
            )
        ]
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        c.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))


@pytest.fixture
def maker(db_engine: Engine) -> sessionmaker[Session]:
    reset_db(db_engine)
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def clock():  # type: ignore[no-untyped-def]
    from paylineage.domain.clock import FrozenClock

    return FrozenClock(T0)


@pytest.fixture(scope="session")
def policy_engine():  # type: ignore[no-untyped-def]
    from paylineage.policy.engine import build_engine

    e = build_engine()
    assert e.runtime == "wasm"
    return e


@pytest.fixture
def world(maker, clock, policy_engine):  # type: ignore[no-untyped-def]
    from paylineage.eval.world import World

    w = World(maker, clock, policy_engine)
    w.setup_people()
    w.setup_agent()
    return w
