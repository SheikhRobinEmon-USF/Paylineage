"""Onboarding and bank change workflows against PostgreSQL (T0.8, I1, I7, I11)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from paylineage.db.models import AuditEvent, OnboardingRequest, Supplier, SupplierBankAccount
from paylineage.domain.context import ConflictError, PolicyRefusedError
from paylineage.domain.enums import OldAccountOutcome
from paylineage.eval.world import World
from paylineage.onboarding import service as onb


def _accounts(world: World, sid: str) -> dict[str, str]:
    with world.tx() as ctx:
        rows = ctx.session.execute(
            select(SupplierBankAccount).where(SupplierBankAccount.supplier_id == sid)
        ).scalars()
        return {r.last4: r.status for r in rows}


def test_L3_new_supplier_onboarded_by_three_people(world: World) -> None:
    sid, _ = world.verified_supplier(
        "Acme Industrial Supply Co. (fictional)", "REG-ACME-0001", "acme.example", "000123456789"
    )
    s = world.supplier(sid)
    assert s.status == "verified"
    assert s.verified_domains == ["acme.example"]
    with world.tx() as ctx:
        req = ctx.session.execute(
            select(OnboardingRequest).where(OnboardingRequest.supplier_id == sid)
        ).scalar_one()
        assert len({req.requester_id, req.verifier_id, req.steward_id}) == 3
        kinds = [
            e.kind
            for e in ctx.session.execute(
                select(AuditEvent).where(AuditEvent.subject_id == sid).order_by(AuditEvent.seq)
            ).scalars()
            if e.kind.startswith("supplier.")
        ]
    assert kinds == [
        "supplier.requested",
        "supplier.record_opened",
        "supplier.verifier_assigned",
        "supplier.verification_recorded",
        "supplier.verified",
    ]


def test_I7_requester_cannot_verify_own_request(world: World) -> None:
    with world.tx() as ctx:
        req = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Orbit Fasteners Ltd. (fictional)",
                ["orbit.example"],
                "REG-ORBIT-0004",
                None,
                "000555000111",
                "Bank",
            ),
        )
        rid = req.id
    with world.tx() as ctx, pytest.raises(PolicyRefusedError) as e:
        onb.assign_verifier(ctx, world.actor("stw1"), rid, world.actor("ap1"))
    assert "SOD_VIOLATION" in e.value.decision.reasons


def test_I7_steward_cannot_assign_self_or_approve_own_verification(world: World) -> None:
    with world.tx() as ctx:
        rid = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Orbit Fasteners Ltd. (fictional)",
                ["orbit.example"],
                "REG-ORBIT-0004",
                None,
                "000555000111",
                "Bank",
            ),
        ).id
    with world.tx() as ctx, pytest.raises(PolicyRefusedError):
        onb.assign_verifier(ctx, world.actor("stw1"), rid, world.actor("stw1"))


def test_I7_unassigned_verifier_cannot_record(world: World) -> None:
    with world.tx() as ctx:
        rid = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Orbit Fasteners Ltd. (fictional)", [], "REG-ORBIT-0004", None, "000555000111", "Bank"
            ),
        ).id
    with world.tx() as ctx:
        onb.assign_verifier(ctx, world.actor("stw1"), rid, world.actor("ver1"))
    with world.tx() as ctx, pytest.raises(PolicyRefusedError) as e:
        onb.record_verification(
            ctx, world.actor("ver2"), rid, onb.VerificationClaim("simulated_validation_service")
        )
    assert "VERIFIER_NOT_ASSIGNED" in e.value.decision.reasons


def test_failed_validation_cannot_reach_steward_review(world: World) -> None:
    with world.tx() as ctx:
        rid = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Cedar Logistics Group (fictional)", [], "REG-CEDAR-0005", None, "000999888777", "Bank"
            ),
        ).id
    with world.tx() as ctx:
        onb.assign_verifier(ctx, world.actor("stw1"), rid, world.actor("ver1"))
    # No account holder registered in the simulated validation service.
    with world.tx() as ctx, pytest.raises(PolicyRefusedError) as e:
        onb.record_verification(
            ctx, world.actor("ver1"), rid, onb.VerificationClaim("simulated_validation_service")
        )
    assert "VERIFICATION_FAILED" in e.value.decision.reasons
    with world.tx() as ctx:
        onb.reject(ctx, world.actor("ver1"), rid, "account holder does not match")
    with world.tx() as ctx:
        req = ctx.session.get(OnboardingRequest, rid)
        assert req is not None
        assert req.state == "rejected"


def test_callback_without_contact_on_file_rejected(world: World) -> None:
    with world.tx() as ctx:
        rid = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Harbor Chemicals Corp. (fictional)", [], "REG-HARBOR-0006", None, "000444333222", "Bank"
            ),
        ).id
    with world.tx() as ctx:
        onb.assign_verifier(ctx, world.actor("stw1"), rid, world.actor("ver1"))
    with world.tx() as ctx, pytest.raises(PolicyRefusedError) as e:
        onb.record_verification(
            ctx, world.actor("ver1"), rid, onb.VerificationClaim("callback_on_file", callback_confirmed=True)
        )
    assert "VERIFICATION_CONTACT_INVALID" in e.value.decision.reasons


def test_bank_change_three_outcome_rule(world: World) -> None:
    sid, _ = world.verified_supplier(
        "Acme Industrial Supply Co. (fictional)", "REG-ACME-0001", "acme.example", "000123456789"
    )
    world.clock.advance(timedelta(days=30))  # type: ignore[attr-defined]
    # Ordinary update: old stays verified while the new one is pending.
    rid = world.bank_change(sid, "000987650001", old=OldAccountOutcome.STILL_VALID)
    assert _accounts(world, sid) == {"6789": "verified", "0001": "pending"}
    assert world.supplier(sid).status == "verified"
    world.verify_bank_change(rid)
    accts = _accounts(world, sid)
    assert accts["0001"] == "verified"
    with world.tx() as ctx:
        new = ctx.session.execute(
            select(SupplierBankAccount).where(SupplierBankAccount.last4 == "0001")
        ).scalar_one()
        assert new.cooling_off_until is not None
        assert new.cooling_off_until > world.clock.now()
    # Compromised: old account suspended immediately on recording.
    world.bank_change(sid, "000987650002", old=OldAccountOutcome.COMPROMISED)
    assert _accounts(world, sid)["0001"] == "suspended"


def test_only_one_open_bank_change(world: World) -> None:
    sid, _ = world.verified_supplier(
        "Acme Industrial Supply Co. (fictional)", "REG-ACME-0001", "acme.example", "000123456789"
    )
    world.clock.advance(timedelta(days=30))  # type: ignore[attr-defined]
    world.bank_change(sid, "000987650001")
    with pytest.raises(ConflictError):
        world.bank_change(sid, "000987650003")


def test_I1_unverified_supplier_not_verified_by_invoice(world: World) -> None:
    with world.tx() as ctx:
        req = onb.request_new_supplier(
            ctx,
            world.actor("ap1"),
            onb.NewSupplier(
                "Bluebird Packaging Inc. (fictional)",
                ["bluebird.example"],
                "REG-BLUE-0003",
                None,
                "000777666555",
                "Bank",
                channel="invoice",
            ),
        )
        sid = req.supplier_id
    s = world.supplier(sid)
    assert s.status == "unverified"
    assert s.verified_domains == []  # claimed domains do not become trusted before verification
    with world.tx() as ctx:
        assert ctx.session.get(Supplier, sid) is not None
        r = ctx.session.execute(
            select(OnboardingRequest).where(OnboardingRequest.supplier_id == sid)
        ).scalar_one()
        assert r.risk_tier == "high"


def test_callback_contact_must_predate_request(world: World) -> None:
    """Same instant is not 'before': a contact recorded with the request cannot verify it."""
    sid, _ = world.verified_supplier(
        "Acme Industrial Supply Co. (fictional)", "REG-ACME-0001", "acme.example", "000123456789"
    )
    rid = world.bank_change(sid, "000987650001")
    with pytest.raises(PolicyRefusedError) as e:
        world.verify_bank_change(rid)
    assert "VERIFICATION_CONTACT_INVALID" in e.value.decision.reasons
