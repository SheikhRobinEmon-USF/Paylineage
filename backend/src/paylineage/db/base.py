"""Engine and session factory. PostgreSQL only: single use, versions and locks rely on it."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Connection, Engine, MetaData, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from paylineage.settings import get_settings

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def make_engine(url: str) -> Engine:
    if not url.startswith("postgresql"):
        raise ValueError("PayLineage needs PostgreSQL (conditional updates, row locks, arrays)")
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return make_engine(get_settings().database_url)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


@contextmanager
def transaction(factory: sessionmaker[Session] | None = None) -> Iterator[Session]:
    """One unit of work. Commits on success, rolls back on any exception."""
    maker = factory or get_sessionmaker()
    session = maker()
    try:
        with session.begin():
            yield session
    finally:
        session.close()


# One constant statement: Postgres quotes each table name with format('%I'), so no
# identifier is ever spliced into SQL text in Python. The audit trigger that blocks
# deletes is paused for the reset only (dev, seed and test databases).
_TRUNCATE_ALL = text(
    """
    DO $$
    DECLARE stmt text;
    BEGIN
      SELECT 'TRUNCATE ' || string_agg(format('%I', tablename), ', ') || ' RESTART IDENTITY CASCADE'
        INTO stmt
        FROM pg_tables
       WHERE schemaname = 'public' AND tablename <> 'alembic_version';
      ALTER TABLE audit_events DISABLE TRIGGER USER;
      EXECUTE stmt;
      ALTER TABLE audit_events ENABLE TRIGGER USER;
    END $$;
    """
)


def truncate_all(conn: Connection) -> None:
    """Empty every application table. Never call this on a production database."""
    if get_settings().paylineage_env == "prod":
        raise RuntimeError("refusing to truncate a production database")
    conn.execute(_TRUNCATE_ALL)
