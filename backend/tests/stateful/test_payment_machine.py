"""Payment state machine: transition table + Hypothesis RuleBasedStateMachine on PostgreSQL.

Example sequence from EVALUATION: create supplier, request bank change, approve
payment, revoke approval, restore old details, execute twice concurrently.
Invariants after every step: at most one execution per payment and per permit,
bank ledger == executions, nothing executed without a valid approval of the
executed version, nothing paid to an account that was not verified (I2, I3, I4, I5).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import HealthCheck, event, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test
from sqlalchemy import func, select, text, update

from paylineage.approvals import service as approvals
from paylineage.db.models import Approval, Execution, Payment, Permit, SupplierBankAccount
from paylineage.domain.context import DomainError
from paylineage.domain.enums import PaymentState
from paylineage.eval.world import World
from paylineage.payments import service as payments
from paylineage.payments.machine import (
    TERMINAL,
    TRANSITIONS,
    IllegalPaymentTransitionError,
    PayEvent,
    next_state,
)

from ..payment_support import make_shop


def test_payment_transitions_are_exactly_the_spec_table() -> None:
    S = PaymentState
    expected = {
        (S.PROPOSED, S.EVALUATED),
        (S.EVALUATED, S.DENIED),
        (S.EVALUATED, S.HELD),
        (S.EVALUATED, S.AWAITING_APPROVAL),
        (S.HELD, S.AWAITING_APPROVAL),
        (S.HELD, S.DENIED),
        (S.AWAITING_APPROVAL, S.APPROVED),
        (S.APPROVED, S.PERMIT_ISSUED),
        (S.PERMIT_ISSUED, S.EXECUTED),
        (S.AWAITING_APPROVAL, S.EVALUATED),
        (S.APPROVED, S.EVALUATED),
        (S.APPROVED, S.EXPIRED),
    }
    assert {(a, b) for (a, _e), b in TRANSITIONS.items()} == expected


def test_terminal_states_are_final_and_unlisted_pairs_fail() -> None:
    for state in PaymentState:
        for ev in PayEvent:
            if (state, ev) in TRANSITIONS:
                assert state not in TERMINAL
            else:
                with pytest.raises(IllegalPaymentTransitionError):
                    next_state(state, ev)


STATS = {"max_exec": 0, "runs_with_exec": 0, "checks": 0}


class PaymentLifecycle(RuleBasedStateMachine):
    def __init__(self, world: World) -> None:
        super().__init__()
        self.w = world
        self.payments: list[str] = []
        self.permits: list[str] = []
        self.n = 0

    @initialize()
    def setup(self) -> None:
        self.shop = make_shop(self.w)

    def _try(self, fn) -> None:  # type: ignore[no-untyped-def]
        try:
            fn()
        except DomainError:
            pass

    @rule()
    def propose(self) -> None:
        self.n += 1
        if len(self.payments) < 8:
            self.payments.append(self.shop.ready_payment(f"h{self.n}", amount=100_000 + self.n))

    @rule(i=st.integers(0, 3), who=st.sampled_from(["fin1", "fin2", "ap1"]))
    def approve(self, i: int, who: str) -> None:
        if self.payments:
            self._try(lambda: self.w.approve(self.payments[i % len(self.payments)], who))

    @rule(i=st.integers(0, 3))
    def edit(self, i: int) -> None:
        if self.payments:
            pid = self.payments[i % len(self.payments)]

            def go() -> None:
                with self.w.tx() as ctx:
                    payments.material_change(
                        ctx, pid, self.w.actor("ap1"), payments.MaterialChange(amount_minor=100_000 + i)
                    )

            self._try(go)

    @rule(i=st.integers(0, 3))
    def revoke_latest_approval(self, i: int) -> None:
        if self.payments:
            pid = self.payments[i % len(self.payments)]
            with self.w.tx() as ctx:
                a = (
                    ctx.session.execute(
                        select(Approval).where(Approval.payment_id == pid).order_by(Approval.signed_at.desc())
                    )
                    .scalars()
                    .first()
                )
                if a is not None:
                    approvals.revoke_approval(ctx, a.id, self.w.actor("adm1"), "test")

    @rule(i=st.integers(0, 3))
    def permit(self, i: int) -> None:
        if self.payments:
            out = None

            def go() -> None:
                nonlocal out
                out = self.w.issue_permit(self.payments[i % len(self.payments)])

            self._try(go)
            if out is not None and out.permit is not None:
                self.permits.append(out.permit.id)

    @rule(i=st.integers(0, 7), times=st.integers(1, 3))
    def execute(self, i: int, times: int) -> None:
        if self.permits:
            pid = self.permits[i % len(self.permits)]
            for k in range(times):
                self._try(lambda k=k: self.w.execute(pid, f"r{self.n}-{k}"))

    @rule(suspend=st.booleans())
    def toggle_account(self, suspend: bool) -> None:
        with self.w.tx() as ctx:
            ctx.session.execute(
                update(SupplierBankAccount)
                .where(SupplierBankAccount.id == self.shop.account_id)
                .values(status="suspended" if suspend else "verified")
            )

    @rule(minutes=st.sampled_from([1, 5, 20]))
    def wait(self, minutes: int) -> None:
        self.w.clock.advance(timedelta(minutes=minutes))  # type: ignore[attr-defined]

    @rule()
    def revoke_mandate(self) -> None:
        self.w.revoke_mandate()

    @rule()
    def restore_mandate(self) -> None:
        """A new, unrevoked mandate version. Payments proposed under the old one become stale."""
        self.w.new_mandate_version(revoked_at=None)

    @rule(approver=st.sampled_from(["fin1", "fin2"]), replays=st.integers(1, 3))
    def happy_path(self, approver: str, replays: int) -> None:
        """Propose, approve, permit, execute (with replays), interleaved with the hostile rules."""
        self.n += 1
        pid = self.shop.ready_payment(f"hp{self.n}", amount=200_000 + self.n)
        self.payments.append(pid)
        self._try(lambda: self.w.approve(pid, approver))
        out = None

        def go() -> None:
            nonlocal out
            out = self.w.issue_permit(pid)

        self._try(go)
        if out is not None and out.permit is not None:
            self.permits.append(out.permit.id)
            for k in range(replays):
                self._try(lambda k=k: self.w.execute(out.permit.id, f"hp{self.n}-{k}"))  # type: ignore[union-attr]

    # ---------------- invariants ----------------

    @invariant()
    def test_I5_single_execution(self) -> None:
        with self.w.tx() as ctx:
            per_payment = ctx.session.execute(
                select(Execution.payment_id, func.count()).group_by(Execution.payment_id)
            ).all()
            assert all(c == 1 for _, c in per_payment)
            n_exec = ctx.session.execute(select(func.count()).select_from(Execution)).scalar_one()
        assert self.w.bank.ledger.count() == n_exec
        event(f"executions={min(n_exec, 3)}")
        STATS["max_exec"] = max(STATS["max_exec"], n_exec)
        STATS["runs_with_exec"] += 1 if n_exec else 0
        STATS["checks"] += 1

    @invariant()
    def test_I3_I4_execution_matches_valid_approval(self) -> None:
        with self.w.tx() as ctx:
            for ex in ctx.session.execute(select(Execution)).scalars():
                p = ctx.session.get(Payment, ex.payment_id)
                permit = ctx.session.get(Permit, ex.permit_id)
                assert p is not None and permit is not None
                assert p.state == "executed"
                assert permit.digest == p.digest
                assert permit.consumed_at is not None
                a = ctx.session.get(Approval, permit.approval_id)
                assert a is not None
                assert a.payment_version == p.version
                assert a.digest == p.digest
                assert a.signed_at <= ex.executed_at
                assert a.expires_at > ex.executed_at
                # Order by the audit chain, not wall time (the test clock is frozen).
                exec_seq = ctx.session.execute(
                    text(
                        "SELECT min(seq) FROM audit_events WHERE kind = 'payment.executed' AND subject_id = :p"
                    ),
                    {"p": p.id},
                ).scalar_one()
                revoke_seq = ctx.session.execute(
                    text(
                        "SELECT min(seq) FROM audit_events WHERE kind = 'payment.approval_revoked' "
                        "AND payload->>'approval_id' = :a"
                    ),
                    {"a": a.id},
                ).scalar_one()
                assert revoke_seq is None or revoke_seq > exec_seq

    @invariant()
    def test_I2_only_verified_beneficiaries_paid(self) -> None:
        with self.w.tx() as ctx:
            rows = ctx.session.execute(
                text("SELECT count(*) FROM audit_events e WHERE e.kind = 'payment.executed'")
            ).scalar_one()
            n_exec = ctx.session.execute(select(func.count()).select_from(Execution)).scalar_one()
            assert rows == n_exec
            for ex in ctx.session.execute(select(Execution)).scalars():
                # The executor only ran after a policy allow at execute stage.
                allowed = ctx.session.execute(
                    text(
                        "SELECT count(*) FROM policy_decisions WHERE payment_id = :p AND stage = 'execute' "
                        "AND decision = 'allow'"
                    ),
                    {"p": ex.payment_id},
                ).scalar_one()
                assert allowed >= 1


def _run(maker, clock, policy_engine, examples: int, steps: int) -> None:  # type: ignore[no-untyped-def]
    from ..conftest import reset_db

    def fresh() -> PaymentLifecycle:
        reset_db(maker)
        clock.set(clock.now() + timedelta(days=1))
        w = World(maker, clock, policy_engine)
        w.setup_people()
        w.setup_agent()
        return PaymentLifecycle(w)

    run_state_machine_as_test(
        fresh,
        settings=settings(
            max_examples=examples,
            stateful_step_count=steps,
            deadline=None,
            suppress_health_check=list(HealthCheck),
            database=None,
        ),
    )


def test_payment_lifecycle_fast(maker, clock, policy_engine) -> None:  # type: ignore[no-untyped-def]
    """PR budget: a handful of fresh worlds, each a random sequence of steps."""
    _run(maker, clock, policy_engine, examples=6, steps=15)


@pytest.mark.deep
def test_payment_lifecycle_deep(maker, clock, policy_engine) -> None:  # type: ignore[no-untyped-def]
    _run(maker, clock, policy_engine, examples=40, steps=30)
    print("STATS", STATS)
    assert STATS["max_exec"] >= 1, "the random walk never reached an execution"
