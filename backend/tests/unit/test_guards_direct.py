"""Direct tests for defence in depth guards (found by `make mutation`).

On the normal path an earlier layer (the policy, the payment row lock) already
refuses, so removing any of these guards changed no other test. Each test here
reaches one guard with the earlier layer out of the way and checks it refuses.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import update

from paylineage.approvals import service as approvals
from paylineage.db.models import Approval, Payment, User, WebAuthnChallenge
from paylineage.domain.context import Actor, ConflictError, ForbiddenError
from paylineage.eval.world import World
from paylineage.executor import service as executor_service
from paylineage.policy.engine import _check_output, output_validator

from ..payment_support import make_shop


def _permitted(world: World) -> tuple[str, str]:
    pid = make_shop(world).ready_payment("guard")
    world.approve(pid, "fin1")
    po = world.issue_permit(pid)
    assert po.permit is not None
    return pid, po.permit.id


# ---- executor (I5) ----


def test_I5_consume_refuses_an_expired_permit(world: World) -> None:
    """The conditional update itself checks expiry, not only the policy."""
    _, permit_id = _permitted(world)
    expires = world.permit(permit_id).expires_at
    with world.tx() as ctx:
        assert executor_service.consume(ctx, permit_id, "req-late", expires + timedelta(seconds=1)) is False
    assert world.permit(permit_id).consumed_at is None
    with world.tx() as ctx:
        assert executor_service.consume(ctx, permit_id, "req-ok", expires - timedelta(seconds=1)) is True


def test_I5_zero_row_consume_pays_nothing(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the conditional update matches no row, the bank is never called."""
    pid, permit_id = _permitted(world)
    monkeypatch.setattr(executor_service, "consume", lambda *_a, **_k: False)
    out = world.execute(permit_id, "req-race")
    assert out.executed is False
    assert out.decision.reasons == ("PERMIT_CONSUMED",)
    assert world.bank.ledger.count() == 0
    assert world.payment(pid).state == "permit_issued"


def test_I5_executor_refuses_when_payment_left_permit_issued(world: World) -> None:
    """A valid permit on a payment in another state is refused before the bank."""
    pid, permit_id = _permitted(world)
    with world.tx() as ctx:
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(state="approved"))
    out = world.execute(permit_id, "req-state")
    assert out.executed is False
    assert "PERMIT_CONSUMED" in out.decision.reasons or not out.decision.allowed
    assert world.bank.ledger.count() == 0
    assert world.permit(permit_id).consumed_at is None


# ---- approvals (I4) ----


def _begin(world: World, pid: str, who: str = "fin1") -> approvals.IssuedChallenge:
    with world.tx() as ctx:
        u = ctx.session.get(User, world.users[who].id)
        assert u is not None
        return approvals.begin_approval(ctx, pid, u)


def test_I4_broken_challenge_commitment_refused(world: World) -> None:
    """The stored challenge must equal the commitment over the stored fields."""
    pid = make_shop(world).ready_payment("commit")
    issued = _begin(world, pid)
    cred = world.keys["fin1"].get_assertion(issued.options_json)
    with world.tx() as ctx:  # swap a committed field; the signed bytes stay the same
        ctx.session.execute(
            update(WebAuthnChallenge)
            .where(WebAuthnChallenge.id == issued.challenge_id)
            .values(nonce="0" * 32)
        )
    with pytest.raises(ForbiddenError) as e, world.tx() as ctx:
        approvals.finish_approval(ctx, issued.challenge_id, cred)
    assert e.value.code == "APPROVAL_DIGEST_MISMATCH"
    assert world.payment(pid).state == "awaiting_approval"


def test_I4_approval_refused_once_payment_left_awaiting(world: World) -> None:
    pid = make_shop(world).ready_payment("moved")
    issued = _begin(world, pid)
    cred = world.keys["fin1"].get_assertion(issued.options_json)
    with world.tx() as ctx:
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(state="held"))
    with pytest.raises(ConflictError) as e, world.tx() as ctx:
        approvals.finish_approval(ctx, issued.challenge_id, cred)
    assert e.value.code == "ILLEGAL_TRANSITION"
    with world.tx() as ctx:
        assert ctx.session.query(Approval).filter(Approval.payment_id == pid).count() == 0


def test_I7_only_the_approver_or_an_admin_revokes(world: World) -> None:
    pid = make_shop(world).ready_payment("revoke")
    out = world.approve(pid, "fin1")
    assert out.approval is not None
    other = Actor(world.users["ana1"].id, "user", frozenset({"analyst"}))
    with pytest.raises(ForbiddenError) as e, world.tx() as ctx:
        approvals.revoke_approval(ctx, out.approval.id, other, "not mine")
    assert e.value.code == "ROLE_REQUIRED"
    admin = Actor(world.users["adm1"].id, "user", frozenset({"admin"}))
    with world.tx() as ctx:
        assert approvals.revoke_approval(ctx, out.approval.id, admin, "admin").revoked_at is not None


# ---- policy output checks (fail closed) ----


@pytest.mark.parametrize("decision", ["deny", "hold"])
def test_unknown_reason_code_from_the_policy_is_rejected(decision: str) -> None:
    raw = {"decision": decision, "reasons": ["NOT_A_REAL_CODE"], "policy_version": "1.0.0"}
    with pytest.raises(ValueError, match="output schema"):
        _check_output(raw, output_validator())
    # Behind the schema, the registry check must hold on its own (schema and registry can drift).
    with pytest.raises(ValueError, match="unknown reason code"):
        _check_output(raw, Draft202012Validator({}))
