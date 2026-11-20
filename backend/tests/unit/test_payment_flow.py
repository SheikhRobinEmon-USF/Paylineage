"""T0.9: approvals and permits on PostgreSQL. I2, I3, I4, I7, I10 and R1 revalidation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from paylineage.approvals import service as approvals
from paylineage.db.models import Approval, Payment, SupplierBankAccount, User
from paylineage.domain.context import ConflictError, ForbiddenError
from paylineage.domain.enums import OldAccountOutcome
from paylineage.eval.world import World
from paylineage.payments import service as payments

from ..payment_support import ACCT, Shop, make_shop


@pytest.fixture
def shop(world: World) -> Shop:
    return make_shop(world)


def _state(w: World, pid: str) -> str:
    return w.payment(pid).state


def test_L1_happy_path_executes_once(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    assert _state(w, pid) == "awaiting_approval"
    out = w.approve(pid, "fin1")
    assert out.approval is not None
    assert _state(w, pid) == "approved"
    po = w.issue_permit(pid)
    assert po.permit is not None
    assert _state(w, pid) == "permit_issued"
    ex = w.execute(po.permit.id, "req-1")
    assert ex.executed
    assert ex.bank_reference is not None
    assert ex.bank_reference.startswith("SIM-")
    assert _state(w, pid) == "executed"
    assert w.bank.ledger.count() == 1


def test_idempotent_proposal(shop: Shop) -> None:
    pid = shop.ready_payment("same")
    inv = shop.invoice(po="PO-same")
    assert shop.propose(inv, "same") == pid


def test_I3_record_altered_after_approval_rejected(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    with w.tx() as ctx:  # tamper behind the transaction service's back, no version bump
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(amount_minor=1_250_001))
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "APPROVAL_DIGEST_MISMATCH" in po.decision.reasons


def test_S10_material_change_voids_approval(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    first = w.approve(pid, "fin1")
    assert first.approval is not None
    with w.tx() as ctx:
        r = payments.material_change(
            ctx, pid, w.actor("ap1"), payments.MaterialChange(amount_minor=1_200_000)
        )
        assert r.payment.version == 2
    p = w.payment(pid)
    assert p.version == 2
    assert p.digest != first.approval.digest
    # Old approval does not count: the payment is back to needing approval.
    assert p.state in ("awaiting_approval", "held")
    with pytest.raises(ConflictError):
        w.issue_permit(pid)


def test_S12_I4_expired_approval_rejected(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    w.clock.advance(timedelta(minutes=16))  # type: ignore[attr-defined]
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "APPROVAL_EXPIRED" in po.decision.reasons
    assert _state(w, pid) == "expired"


def test_I4_revoked_approval_rejected(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    out = w.approve(pid, "fin1")
    assert out.approval is not None
    with w.tx() as ctx:
        approvals.revoke_approval(ctx, out.approval.id, w.actor("fin1"), "changed my mind")
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "APPROVAL_REVOKED" in po.decision.reasons


def test_R1_mandate_revoked_after_approval(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")  # 10:00
    w.clock.advance(timedelta(minutes=1))  # type: ignore[attr-defined]
    w.revoke_mandate()  # 10:01
    w.clock.advance(timedelta(minutes=1))  # type: ignore[attr-defined]
    po = w.issue_permit(pid)  # 10:02, signature still valid
    assert po.permit is None
    assert "MANDATE_REVOKED" in po.decision.reasons


def test_R1_mandate_revoked_after_permit_blocks_execution(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    po = w.issue_permit(pid)
    assert po.permit is not None
    w.revoke_mandate()
    ex = w.execute(po.permit.id, "req-1")
    assert not ex.executed
    assert "MANDATE_REVOKED" in ex.decision.reasons
    assert w.bank.ledger.count() == 0


def test_R1_mandate_version_changed_after_approval(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    w.new_mandate_version(per_proposal_ceiling_minor=5_000_000)
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "MANDATE_VERSION_STALE" in po.decision.reasons


def test_R1_beneficiary_suspended_after_permit(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    po = w.issue_permit(pid)
    assert po.permit is not None
    with w.tx() as ctx:
        ctx.session.execute(
            update(SupplierBankAccount)
            .where(SupplierBankAccount.id == shop.account_id)
            .values(status="suspended")
        )
    ex = w.execute(po.permit.id, "req-1")
    assert not ex.executed
    assert "ACCOUNT_SUSPENDED" in ex.decision.reasons


def test_R1_supplier_suspended_after_permit(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    po = w.issue_permit(pid)
    assert po.permit is not None
    with w.tx() as ctx:
        from paylineage.db.models import Supplier

        s = ctx.session.get(Supplier, shop.supplier_id)
        assert s is not None
        s.status = "suspended"
    ex = w.execute(po.permit.id, "req-1")
    assert not ex.executed
    assert "SUPPLIER_NOT_VERIFIED" in ex.decision.reasons


def test_R1_approver_permission_revoked(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    with w.tx() as ctx:
        ctx.session.execute(update(User).where(User.id == w.users["fin1"].id).values(active=False))
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "APPROVER_NOT_AUTHORIZED" in po.decision.reasons


def test_R1_policy_version_changed(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    with w.tx() as ctx:
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(policy_version="0.9.0"))
    po = w.issue_permit(pid)
    assert po.permit is None
    assert "POLICY_VERSION_STALE" in po.decision.reasons


def test_I3_tampered_challenge_rejected(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    with pytest.raises(ForbiddenError):
        w.approve(pid, "fin1", tamper=True)
    assert _state(w, pid) == "awaiting_approval"


def test_I3_challenge_cannot_be_replayed(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    with w.tx() as ctx:
        u = ctx.session.get(User, w.users["fin1"].id)
        assert u is not None
        issued = approvals.begin_approval(ctx, pid, u)
    cred = w.keys["fin1"].get_assertion(issued.options_json)
    with w.tx() as ctx:
        approvals.finish_approval(ctx, issued.challenge_id, cred)
    with w.tx() as ctx, pytest.raises(ForbiddenError):
        approvals.finish_approval(ctx, issued.challenge_id, cred)


def test_I3_other_users_passkey_rejected(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    with w.tx() as ctx:
        u = ctx.session.get(User, w.users["fin1"].id)
        assert u is not None
        issued = approvals.begin_approval(ctx, pid, u)
    cred = w.keys["fin2"].get_assertion(issued.options_json)  # fin2 signs fin1's challenge
    with w.tx() as ctx, pytest.raises(ForbiddenError):
        approvals.finish_approval(ctx, issued.challenge_id, cred)


def test_I3_record_changed_between_challenge_and_assertion(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    with w.tx() as ctx:
        u = ctx.session.get(User, w.users["fin1"].id)
        assert u is not None
        issued = approvals.begin_approval(ctx, pid, u)
    with w.tx() as ctx:
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(amount_minor=999))
    cred = w.keys["fin1"].get_assertion(issued.options_json)
    with w.tx() as ctx, pytest.raises(ConflictError):
        approvals.finish_approval(ctx, issued.challenge_id, cred)


def test_I3_wrong_role_cannot_approve(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment()
    out = w.approve(pid, "ap1")
    assert out.approval is None
    assert "APPROVER_NOT_AUTHORIZED" in out.decision.reasons
    assert _state(w, pid) == "awaiting_approval"


def test_second_approver_required_above_threshold(shop: Shop) -> None:
    w = shop.world
    pid = shop.ready_payment("big", amount=3_000_000)
    a1 = w.approve(pid, "fin1")
    assert a1.approval is not None
    assert a1.decision.reasons == ("SECOND_APPROVAL_REQUIRED",)
    assert _state(w, pid) == "awaiting_approval"
    a2 = w.approve(pid, "fin2")
    assert a2.decision.decision == "allow"
    assert _state(w, pid) == "approved"
    po = w.issue_permit(pid)
    assert po.permit is not None


def test_S12_I7_approver_who_changed_bank_details_refused(shop: Shop) -> None:
    w = shop.world
    with w.tx() as ctx:
        u = User(
            display_name="Dual role user (fictional)",
            email="dual@example.test",
            roles=["ap_specialist", "finance_approver"],
            active=True,
        )
        ctx.session.add(u)
        ctx.session.flush()
        w.users["dual"] = u
    from paylineage.approvals import webauthn
    from paylineage.eval.soft_authenticator import SoftAuthenticator

    auth = SoftAuthenticator()
    with w.tx() as ctx:
        issued = webauthn.begin_registration(ctx, w.users["dual"])
    with w.tx() as ctx:
        webauthn.finish_registration(ctx, issued.challenge_id, auth.register(issued.options_json))
    w.keys["dual"] = auth
    w.bank_change(shop.supplier_id, "000987650001", recorder="dual", old=OldAccountOutcome.STILL_VALID)
    pid = shop.ready_payment("sod")  # pays the old, still valid account
    out = w.approve(pid, "dual")
    assert out.approval is None
    assert "SOD_VIOLATION" in out.decision.reasons


def test_I2_unverified_beneficiary_not_payable_even_if_human_approves(shop: Shop) -> None:
    w = shop.world
    w.clock.advance(timedelta(days=30))  # type: ignore[attr-defined]
    w.bank_change(shop.supplier_id, "000987650001")  # pending account
    inv = shop.invoice(account="000987650001", po="PO-7001")
    pid = shop.propose(inv, "pend", account="000987650001")
    p = w.payment(pid)
    assert p.state == "held"
    assert "BENEFICIARY_NOT_VERIFIED" in (p.last_decision or {})["reasons"]
    with pytest.raises(ConflictError):
        w.approve(pid, "fin1")
    # Even if someone forces the state, the approval is refused by policy.
    with w.tx() as ctx:
        ctx.session.execute(update(Payment).where(Payment.id == pid).values(state="awaiting_approval"))
    out = w.approve(pid, "fin1")
    assert out.approval is None
    assert "BENEFICIARY_NOT_VERIFIED" in out.decision.reasons


def test_S7_over_ceiling_denied(shop: Shop) -> None:
    pid = shop.ready_payment("big7", amount=6_200_000)
    p = shop.world.payment(pid)
    assert p.state == "denied"
    assert "OVER_CEILING" in (p.last_decision or {})["reasons"]


def test_S8_agent_bank_change_operation_denied(shop: Shop) -> None:
    inv = shop.invoice()
    pid = shop.propose(inv, "s8", operation="change_bank_details")
    p = shop.world.payment(pid)
    assert p.state == "denied"
    assert "OP_FORBIDDEN" in (p.last_decision or {})["reasons"]


def test_S9_agent_asserted_backup_account_denied(shop: Shop) -> None:
    inv = shop.invoice()  # invoice says ACCT; the poisoned tool told the agent another account
    pid = shop.propose(inv, "s9", account="000666000666")
    p = shop.world.payment(pid)
    assert p.state == "denied"
    reasons = (p.last_decision or {})["reasons"]
    assert "FIELD_NO_PROVENANCE" in reasons
    assert "BENEFICIARY_NOT_VERIFIED" in reasons


def test_I9_agent_signature_invalid_denied(shop: Shop) -> None:
    inv = shop.invoice()
    r = shop.world.propose(
        inv,
        amount_minor=1_250_000,
        account=ACCT,
        supplier_id=shop.supplier_id,
        key="sig",
        signature_valid=False,
    )
    assert r.payment.state == "denied"
    assert "AGENT_SIGNATURE_INVALID" in r.decision.reasons


def test_held_payment_released_by_analyst_clearance(shop: Shop) -> None:
    w = shop.world
    inv = shop.invoice(signals=[("SIGNAL_REPLY_TO_MISMATCH", "medium")])
    pid = shop.propose(inv, "sig1")
    assert _state(w, pid) == "held"
    with w.tx() as ctx:
        r = payments.clear_hold(
            ctx, pid, w.actor("ana1"), "SIGNAL_REPLY_TO_MISMATCH", "called supplier on file"
        )
        assert r.decision.decision == "allow"
    assert _state(w, pid) == "awaiting_approval"


def test_every_decision_is_recorded_and_chained(shop: Shop) -> None:
    from paylineage.audit.chain import load_events, verify_events

    w = shop.world
    pid = shop.ready_payment()
    w.approve(pid, "fin1")
    w.issue_permit(pid)
    with w.tx() as ctx:
        events = load_events(ctx.session)
        problems, last, _ = verify_events(events)
        assert problems == []
        assert last == len(events)
        kinds = {e.kind for e in events if e.subject_id == pid}
        assert {
            "payment.proposed",
            "policy.evaluate",
            "payment.approved",
            "policy.permit",
            "permit.issued",
        } <= kinds
        n_approvals = len(
            ctx.session.execute(select(Approval).where(Approval.payment_id == pid)).scalars().all()
        )
        assert n_approvals == 1
