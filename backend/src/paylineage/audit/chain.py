"""Tamper-evident audit log: hash chain in PostgreSQL plus signed checkpoints outside it (I11).

hash_n = SHA-256(RFC 8785({seq, prev_hash, actor, kind, subject_id, payload_digest, created_at_ms}))

Appends serialize on the single `audit_head` row (SELECT ... FOR UPDATE), so seq
is gap free and the chain is linear even under concurrency.

Tamper-evident, not tamper-proof: the chain proves integrity of what was
recorded relative to the last signed checkpoint, not that the facts were true.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from paylineage.canonical import digest
from paylineage.db.models import AuditEvent, AuditHead
from paylineage.domain.clock import to_ms

GENESIS = "0" * 64


def event_hash(
    *,
    seq: int,
    prev_hash: str,
    actor: str,
    kind: str,
    subject_id: str | None,
    payload_digest: str,
    created_at_ms: int,
) -> str:
    return digest(
        {
            "seq": seq,
            "prev_hash": prev_hash,
            "actor": actor,
            "kind": kind,
            "subject_id": subject_id,
            "payload_digest": payload_digest,
            "created_at_ms": created_at_ms,
        }
    )


def append(
    session: Session,
    *,
    actor: str,
    kind: str,
    subject_id: str | None,
    payload: Mapping[str, Any],
    now: datetime,
) -> AuditEvent:
    """Append one event inside the caller's transaction."""
    session.execute(
        insert(AuditHead).values(id=1, seq=0, hash=GENESIS).on_conflict_do_nothing(index_elements=["id"])
    )
    head = session.execute(select(AuditHead).where(AuditHead.id == 1).with_for_update()).scalar_one()
    seq = head.seq + 1
    body = dict(payload)
    p_digest = digest(body)
    h = event_hash(
        seq=seq,
        prev_hash=head.hash,
        actor=actor,
        kind=kind,
        subject_id=subject_id,
        payload_digest=p_digest,
        created_at_ms=to_ms(now),
    )
    ev = AuditEvent(
        seq=seq,
        actor=actor,
        kind=kind,
        subject_id=subject_id,
        payload=body,
        payload_digest=p_digest,
        prev_hash=head.hash,
        hash=h,
        created_at=now,
    )
    session.add(ev)
    head.seq = seq
    head.hash = h
    session.flush()
    return ev


@dataclass(frozen=True)
class ChainProblem:
    seq: int
    kind: str  # modified | deleted | reordered | truncated | checkpoint_signature | checkpoint_mismatch
    detail: str


def verify_events(events: Iterable[AuditEvent]) -> tuple[list[ChainProblem], int, str]:
    """Recompute every hash and link. Returns problems, last seq, last hash."""
    problems: list[ChainProblem] = []
    expected_seq = 1
    prev = GENESIS
    for ev in sorted(events, key=lambda e: e.seq):
        if ev.seq != expected_seq:
            problems.append(ChainProblem(expected_seq, "deleted", f"gap: next seq is {ev.seq}"))
            expected_seq = ev.seq
        if ev.prev_hash != prev:
            problems.append(ChainProblem(ev.seq, "reordered", "prev_hash does not link to previous event"))
        if digest(ev.payload) != ev.payload_digest:
            problems.append(ChainProblem(ev.seq, "modified", "payload does not match payload_digest"))
        recomputed = event_hash(
            seq=ev.seq,
            prev_hash=ev.prev_hash,
            actor=ev.actor,
            kind=ev.kind,
            subject_id=ev.subject_id,
            payload_digest=ev.payload_digest,
            created_at_ms=to_ms(ev.created_at),
        )
        if recomputed != ev.hash:
            problems.append(ChainProblem(ev.seq, "modified", "event hash does not recompute"))
        prev = ev.hash
        expected_seq += 1
    return problems, expected_seq - 1, prev


def load_events(session: Session) -> list[AuditEvent]:
    return list(session.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars())
