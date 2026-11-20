"""Regression (found by the demo's in-browser replay check): the operation an agent requested
was not recorded with its decision, so S8 (change_bank_details) could not be replayed and
re-evaluated as propose_payment. The recorded snapshot must carry the requested operation."""

from __future__ import annotations

from paylineage.eval.world import World

from ..payment_support import make_shop


def test_I10_requested_operation_is_part_of_the_record(world: World) -> None:
    shop = make_shop(world)
    inv = shop.invoice()
    pid = shop.propose(inv, "op-s8", operation="change_bank_details")
    p = world.payment(pid)
    assert p.state == "denied"
    assert (p.last_decision or {})["requested_operation"] == "change_bank_details"
