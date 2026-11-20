"""I5: each permit is consumed at most once, including under concurrency (real PostgreSQL)."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from paylineage.domain.context import Ctx
from paylineage.eval.world import World
from paylineage.executor.service import consume

from ..payment_support import Shop, make_shop

pytestmark = pytest.mark.concurrency


@pytest.fixture
def permitted(world: World) -> tuple[Shop, str, str]:
    shop = make_shop(world)
    pid = shop.ready_payment()
    world.approve(pid, "fin1")
    po = world.issue_permit(pid)
    assert po.permit is not None
    return shop, pid, po.permit.id


def test_I5_replayed_permit_refused(world: World, permitted: tuple[Shop, str, str]) -> None:
    _, _, permit_id = permitted
    first = world.execute(permit_id, "req-1")
    second = world.execute(permit_id, "req-2")
    assert first.executed
    assert not second.executed
    assert "PERMIT_CONSUMED" in second.decision.reasons
    assert world.bank.ledger.count() == 1


@pytest.mark.parametrize("n", [2, 8, 16])
def test_I5_concurrent_consume_executes_once(world: World, permitted: tuple[Shop, str, str], n: int) -> None:
    _, pid, permit_id = permitted
    barrier = threading.Barrier(n)

    def run(i: int) -> bool:
        barrier.wait()
        return world.execute(permit_id, f"req-{i}").executed

    with ThreadPoolExecutor(n) as pool:
        results = list(pool.map(run, range(n)))
    assert results.count(True) == 1
    assert world.bank.ledger.count() == 1
    assert world.payment(pid).state == "executed"
    assert world.permit(permit_id).consumed_at is not None


def test_I5_conditional_update_alone_is_single_use(world: World, permitted: tuple[Shop, str, str]) -> None:
    """Without the payment row lock, the conditional UPDATE still lets exactly one through."""
    _, _, permit_id = permitted
    n = 12
    barrier = threading.Barrier(n)

    def run(i: int) -> bool:
        session = world.maker()
        try:
            with session.begin():
                barrier.wait()
                return consume(
                    Ctx(session, world.clock, world.engine), permit_id, f"raw-{i}", world.clock.now()
                )
        finally:
            session.close()

    with ThreadPoolExecutor(n) as pool:
        results = list(pool.map(run, range(n)))
    assert results.count(True) == 1


def test_I5_expired_permit_refused(world: World, permitted: tuple[Shop, str, str]) -> None:
    from datetime import timedelta

    _, _, permit_id = permitted
    world.clock.advance(timedelta(minutes=3))  # type: ignore[attr-defined]
    out = world.execute(permit_id, "late")
    assert not out.executed
    assert "PERMIT_EXPIRED" in out.decision.reasons
    assert world.bank.ledger.count() == 0


def test_bank_failure_rolls_back_consumption(world: World, permitted: tuple[Shop, str, str]) -> None:
    _, pid, permit_id = permitted

    class Down:
        def transfer(self, **_: object) -> str:
            raise ConnectionError("bank down")

    good = world.bank
    world.bank = Down()  # type: ignore[assignment]
    with pytest.raises(ConnectionError):
        world.execute(permit_id, "req-down")
    assert world.permit(permit_id).consumed_at is None  # rolled back: retry is possible
    assert world.payment(pid).state == "permit_issued"
    world.bank = good
    assert world.execute(permit_id, "req-retry").executed
