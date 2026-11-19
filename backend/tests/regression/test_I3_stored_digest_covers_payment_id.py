"""Regression (found by the Hypothesis payment state machine, minimized to one happy path):
the stored payment digest was computed before the UUID was assigned at flush, so it
hashed payment_id = null. Authorization recomputed and stayed correct; the stored
digest shown to people was wrong. The stored digest must equal the recomputed one."""

from __future__ import annotations

import pytest

from paylineage.db.models import Payment
from paylineage.eval.world import World
from paylineage.payments.record import canonical_record, compute_digest

from ..payment_support import make_shop


def test_I3_stored_digest_matches_recomputed_after_propose(world: World) -> None:
    shop = make_shop(world)
    pid = shop.ready_payment()
    with world.tx() as ctx:
        p = ctx.session.get(Payment, pid)
        assert p is not None
        assert p.digest == compute_digest(p)
        assert canonical_record(p)["payment_id"] == pid


def test_I3_canonical_record_refuses_missing_id() -> None:
    with pytest.raises(ValueError, match="ids and fields"):
        canonical_record(Payment(invoice_id="i", agent_id="a"))
