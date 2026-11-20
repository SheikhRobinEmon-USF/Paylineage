"""Audit log is append-only at the database layer; supplier_events view (I11).

The trigger stops accidental or application-level rewrites. A database superuser
can still disable it, which is why signed checkpoints live outside the database.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION paylineage_audit_immutable() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'audit_events is append-only (%)', TG_OP USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION paylineage_audit_immutable();
        """
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION paylineage_audit_immutable();"
    )
    op.execute(
        """
        CREATE VIEW supplier_events AS
        SELECT id, subject_id AS supplier_id, actor, kind AS event_type, payload_digest, prev_hash, hash, created_at
        FROM audit_events WHERE kind LIKE 'supplier.%';
        """
    )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS supplier_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS paylineage_audit_immutable()")
