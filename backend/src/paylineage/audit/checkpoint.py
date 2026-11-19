"""Signed checkpoints written outside the database (I11).

A checkpoint signs {seq, hash, created_at_ms} with an Ed25519 key that the
database never sees. The verifier recomputes the chain from the database and
checks it against every checkpoint, which detects modified, deleted, reordered
and truncated history up to the latest checkpoint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from paylineage.audit.chain import ChainProblem, load_events, verify_events
from paylineage.canonical import canonical_bytes, sha256_hex
from paylineage.db.models import AuditHead
from paylineage.domain.clock import to_ms


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    hash: str
    created_at_ms: int
    key_id: str
    signature: str

    def body(self) -> dict[str, object]:
        return {"seq": self.seq, "hash": self.hash, "created_at_ms": self.created_at_ms}


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ckpt-" + sha256_hex(raw)[:16]


def load_or_create_key(path: Path, *, allow_create: bool) -> Ed25519PrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("checkpoint key must be Ed25519")
        return key
    if not allow_create:
        raise FileNotFoundError(f"checkpoint key missing: {path}")
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o600)
    return key


class CheckpointStore:
    """MVP store: one JSON file per checkpoint in a directory (can move off host later)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def write(self, cp: Checkpoint) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{cp.seq:012d}.json"
        doc = {**cp.body(), "key_id": cp.key_id, "signature": cp.signature}
        path.write_text(json.dumps(doc, sort_keys=True) + "\n")
        return path

    def all(self) -> list[Checkpoint]:
        if not self.directory.exists():
            return []
        out = []
        for p in sorted(self.directory.glob("*.json")):
            d = json.loads(p.read_text())
            out.append(
                Checkpoint(
                    int(d["seq"]),
                    str(d["hash"]),
                    int(d["created_at_ms"]),
                    str(d["key_id"]),
                    str(d["signature"]),
                )
            )
        return out


def sign_checkpoint(key: Ed25519PrivateKey, *, seq: int, hash_: str, created_at: datetime) -> Checkpoint:
    created_ms = to_ms(created_at)
    body = {"seq": seq, "hash": hash_, "created_at_ms": created_ms}
    sig = key.sign(canonical_bytes(body)).hex()
    return Checkpoint(seq, hash_, created_ms, key_id(key.public_key()), sig)


def checkpoint_now(
    session: Session, key: Ed25519PrivateKey, store: CheckpointStore, now: datetime
) -> Checkpoint | None:
    """Sign the committed head. Call after commit so a rolled back append is never signed."""
    head = session.execute(select(AuditHead).where(AuditHead.id == 1)).scalar_one_or_none()
    if head is None or head.seq == 0:
        return None
    existing = {c.seq for c in store.all()}
    if head.seq in existing:
        return None
    cp = sign_checkpoint(key, seq=head.seq, hash_=head.hash, created_at=now)
    store.write(cp)
    return cp


def verify(session: Session, public: Ed25519PublicKey, store: CheckpointStore) -> list[ChainProblem]:
    events = load_events(session)
    problems, last_seq, _ = verify_events(events)
    by_seq = {e.seq: e for e in events}
    for cp in store.all():
        try:
            public.verify(bytes.fromhex(cp.signature), canonical_bytes(cp.body()))
        except (InvalidSignature, ValueError):
            problems.append(ChainProblem(cp.seq, "checkpoint_signature", "checkpoint signature invalid"))
            continue
        if cp.seq > last_seq:
            problems.append(
                ChainProblem(cp.seq, "truncated", f"checkpoint at {cp.seq}, database ends at {last_seq}")
            )
            continue
        ev = by_seq.get(cp.seq)
        if ev is None:
            problems.append(ChainProblem(cp.seq, "deleted", "checkpointed event missing"))
        elif ev.hash != cp.hash:
            problems.append(
                ChainProblem(cp.seq, "checkpoint_mismatch", "history differs from signed checkpoint")
            )
    return problems
