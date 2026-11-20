"""I11: supplier master changes are attributable and tamper evident against signed checkpoints.

The attacker here is a database administrator: they can disable the append-only
trigger and rewrite rows, but they do not hold the checkpoint signing key.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from paylineage.audit.checkpoint import CheckpointStore, checkpoint_now, verify
from paylineage.eval.world import World

from ..payment_support import make_shop


@pytest.fixture
def signed(world: World, tmp_path: Path) -> tuple[World, Ed25519PrivateKey, CheckpointStore]:
    make_shop(world)
    key = Ed25519PrivateKey.generate()
    store = CheckpointStore(tmp_path / "checkpoints")
    with world.tx() as ctx:
        cp = checkpoint_now(ctx.session, key, store, world.clock.now())
        assert cp is not None
    return world, key, store


def _problems(world: World, key: Ed25519PrivateKey, store: CheckpointStore) -> set[str]:
    with world.tx() as ctx:
        return {p.kind for p in verify(ctx.session, key.public_key(), store)}


def _as_admin(world: World, sql: str) -> None:
    with world.tx() as ctx:
        ctx.session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        ctx.session.execute(text(sql))
        ctx.session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))


def test_I11_clean_chain_verifies(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    assert _problems(*signed) == set()


def test_I11_trigger_blocks_rewrites(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, _, _ = signed
    for sql in (
        "UPDATE audit_events SET actor = 'x' WHERE seq = 1",
        "DELETE FROM audit_events WHERE seq = 1",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(DBAPIError), world.tx() as ctx:
            ctx.session.execute(text(sql))


def test_I11_modified_payload_detected(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, key, store = signed
    _as_admin(
        world,
        "UPDATE audit_events SET payload = jsonb_set(payload, '{account}', '\"•••• 0666\"') "
        "WHERE kind = 'supplier.requested'",
    )
    assert "modified" in _problems(world, key, store)


def test_I11_modified_actor_with_recomputed_hash_detected(
    signed: tuple[World, Ed25519PrivateKey, CheckpointStore],
) -> None:
    """Even an attacker who recomputes every hash cannot match the signed checkpoint."""
    world, key, store = signed
    from paylineage.audit.chain import event_hash, load_events
    from paylineage.domain.clock import to_ms

    with world.tx() as ctx:
        events = load_events(ctx.session)
    rows = []
    prev = "0" * 64
    for ev in events:
        actor = "attacker" if ev.kind == "supplier.verified" else ev.actor
        h = event_hash(
            seq=ev.seq,
            prev_hash=prev,
            actor=actor,
            kind=ev.kind,
            subject_id=ev.subject_id,
            payload_digest=ev.payload_digest,
            created_at_ms=to_ms(ev.created_at),
        )
        rows.append((ev.seq, actor, prev, h))
        prev = h
    sql = ";".join(
        f"UPDATE audit_events SET actor='{a}', prev_hash='{p}', hash='{h}' WHERE seq={s}"
        for s, a, p, h in rows
    )
    _as_admin(world, sql)
    problems = _problems(world, key, store)
    assert problems == {"checkpoint_mismatch"}


def test_I11_deleted_event_detected(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, key, store = signed
    _as_admin(world, "DELETE FROM audit_events WHERE seq = 3")
    assert "deleted" in _problems(world, key, store)


def test_I11_reordered_events_detected(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, key, store = signed
    _as_admin(
        world,
        "UPDATE audit_events SET seq = -1 WHERE seq = 2; UPDATE audit_events SET seq = 2 WHERE seq = 3;"
        " UPDATE audit_events SET seq = 3 WHERE seq = -1",
    )
    assert "reordered" in _problems(world, key, store)


def test_I11_truncated_history_detected(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, key, store = signed
    _as_admin(world, "DELETE FROM audit_events WHERE seq > 5")
    assert "truncated" in _problems(world, key, store)


def test_I11_forged_checkpoint_detected(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, key, store = signed
    import json

    path = sorted(store.directory.glob("*.json"))[-1]
    doc = json.loads(path.read_text())
    doc["hash"] = "f" * 64
    path.write_text(json.dumps(doc))
    assert "checkpoint_signature" in _problems(world, key, store)


def test_I11_supplier_events_attributable(signed: tuple[World, Ed25519PrivateKey, CheckpointStore]) -> None:
    world, _, _ = signed
    with world.tx() as ctx:
        rows = ctx.session.execute(
            text("SELECT actor, event_type FROM supplier_events ORDER BY created_at")
        ).all()
    assert rows
    assert all(actor and actor != "system" for actor, _ in rows)
