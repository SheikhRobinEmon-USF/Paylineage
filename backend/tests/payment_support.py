"""Shared fixtures for payment lifecycle tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from paylineage.eval.world import World

ACME = "Acme Industrial Supply Co. (fictional)"
ACCT = "000123456789"


@dataclass
class Shop:
    world: World
    supplier_id: str
    account_id: str

    def invoice(
        self, amount: int = 1_250_000, account: str = ACCT, po: str | None = "PO-7001", **kw: object
    ) -> str:
        return self.world.invoice(
            supplier_id=self.supplier_id,
            supplier_name=ACME,
            amount_minor=amount,
            account=account,
            po_number=po,
            **kw,
        )  # type: ignore[arg-type]

    def propose(self, inv: str, key: str, amount: int = 1_250_000, account: str = ACCT, **kw: object) -> str:
        r = self.world.propose(
            inv, amount_minor=amount, account=account, supplier_id=self.supplier_id, key=key, **kw
        )  # type: ignore[arg-type]
        return r.payment.id

    def ready_payment(self, key: str = "k1", amount: int = 1_250_000) -> str:
        inv = self.invoice(amount=amount, po=f"PO-{key}")
        self.world.purchase_order(self.supplier_id, f"PO-{key}", amount)
        return self.propose(inv, key, amount=amount)


def make_shop(world: World) -> Shop:
    sid, aid = world.verified_supplier(ACME, "REG-ACME-0001", "acme.example", ACCT)
    world.purchase_order(sid, "PO-7001", 1_250_000)
    # Move past the SoD window for the people who onboarded the supplier.
    world.clock.advance(timedelta(days=8))  # type: ignore[attr-defined]
    return Shop(world, sid, aid)
