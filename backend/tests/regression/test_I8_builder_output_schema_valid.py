"""Regression: a wildcard mandate scope ("*") failed the input schema, so every
payment for a wildcard-scoped agent was denied INPUT_INVALID. Fail closed worked;
the contract was wrong. The builder's output must always validate."""

from __future__ import annotations

from paylineage.db.models import Payment
from paylineage.eval.world import World
from paylineage.policy.engine import input_validator
from paylineage.policy.input_builder import build_payment_input

from ..payment_support import make_shop


def test_I8_wildcard_scope_input_is_schema_valid(world: World) -> None:
    shop = make_shop(world)
    pid = shop.ready_payment()
    with world.tx() as ctx:
        p = ctx.session.get(Payment, pid)
        assert p is not None
        for stage in ("evaluate", "permit", "execute"):
            pin, _ = build_payment_input(ctx.session, p, stage=stage, now=world.clock.now())  # type: ignore[arg-type]
            errors = [e.message for e in input_validator().iter_errors(pin)]
            assert errors == [], (stage, errors)
    assert world.payment(pid).state == "awaiting_approval"
