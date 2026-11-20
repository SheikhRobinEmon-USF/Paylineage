"""A fictional organization, built through the real workflows. Used by tests, eval and seeding.

All companies, people and accounts are fictional (CLAUDE.md). Every step runs in
its own transaction, like an API call, through the same services the API uses.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from paylineage.approvals import service as approvals
from paylineage.approvals import webauthn
from paylineage.canonical import sha256_hex
from paylineage.db.models import (
    Agent,
    Document,
    ExtractedField,
    Invoice,
    Mandate,
    Payment,
    Permit,
    PurchaseOrder,
    Signal,
    Supplier,
    SupplierBankAccount,
    User,
)
from paylineage.db.vault import account_token, mask_account, normalize_account, store_account
from paylineage.domain.clock import Clock
from paylineage.domain.context import Actor, Ctx
from paylineage.domain.enums import Consistency, OldAccountOutcome, SourceKind, trust_for
from paylineage.eval.soft_authenticator import SoftAuthenticator
from paylineage.executor import service as executor
from paylineage.mockbank.app import Ledger, TransferIn
from paylineage.onboarding import service as onboarding
from paylineage.onboarding import simulated
from paylineage.payments import service as payments
from paylineage.permits import service as permits
from paylineage.policy.engine import PolicyEngine
from paylineage.policy.input_builder import amount_token, text_token

ORG = "Example Manufacturing LLC (fictional)"

PEOPLE: dict[str, tuple[str, list[str]]] = {
    "ap1": ("Avery Park (AP specialist)", ["ap_specialist"]),
    "ap2": ("Jordan Lee (AP specialist)", ["ap_specialist"]),
    "fin1": ("Morgan Diaz (finance approver)", ["finance_approver"]),
    "fin2": ("Riley Chen (finance approver)", ["finance_approver"]),
    "stw1": ("Sam Okafor (vendor data steward)", ["steward"]),
    "ver1": ("Taylor Nguyen (verifier)", ["verifier"]),
    "ver2": ("Casey Romero (verifier)", ["verifier"]),
    "ana1": ("Quinn Patel (fraud analyst)", ["analyst"]),
    "eng1": ("Drew Kim (AP platform engineer)", ["platform_engineer"]),
    "adm1": ("Alex Moreau (administrator)", ["admin"]),
}


class InMemoryBank:
    """Executor-side client for the SIMULATED bank, without HTTP."""

    def __init__(self) -> None:
        self.ledger = Ledger()

    def transfer(
        self,
        *,
        idempotency_key: str,
        amount_minor: int,
        currency: str,
        beneficiary_token: str,
        reference: str,
    ) -> str:
        out = self.ledger.transfer(
            TransferIn(
                idempotency_key=idempotency_key,
                amount_minor=amount_minor,
                currency=currency,
                beneficiary_token=beneficiary_token,
                reference=reference,
            )
        )
        return out.bank_reference


@dataclass
class World:
    maker: sessionmaker[Session]
    clock: Clock
    engine: PolicyEngine
    users: dict[str, User] = field(default_factory=dict)
    keys: dict[str, SoftAuthenticator] = field(default_factory=dict)
    agent_key: Ed25519PrivateKey | None = None
    agent_id: str = "AP-Agent-001"
    bank: InMemoryBank = field(default_factory=InMemoryBank)

    @contextmanager
    def tx(self) -> Iterator[Ctx]:
        session = self.maker()
        try:
            with session.begin():
                yield Ctx(session, self.clock, self.engine)
        finally:
            session.close()

    def actor(self, name: str) -> Actor:
        with self.tx() as ctx:
            u = ctx.session.get(User, self.users[name].id)
            assert u is not None
            return Actor(u.id, "user", frozenset(u.roles), u.active)

    @property
    def agent(self) -> Actor:
        return Actor(self.agent_id, "agent", frozenset({"agent"}))

    # ---------- people and agent ----------

    def setup_people(self) -> None:
        for handle, (name, roles) in PEOPLE.items():
            with self.tx() as ctx:
                u = User(display_name=name, email=f"{handle}@example.test", roles=roles, active=True)
                ctx.session.add(u)
                ctx.session.flush()
                self.users[handle] = u
            auth = SoftAuthenticator()
            with self.tx() as ctx:
                issued = webauthn.begin_registration(ctx, self.users[handle])
            with self.tx() as ctx:
                webauthn.finish_registration(ctx, issued.challenge_id, auth.register(issued.options_json))
            self.keys[handle] = auth

    def setup_agent(
        self,
        *,
        scope: list[str] | None = None,
        ceiling: int = 5_000_000,
        daily: int = 15_000_000,
        second_above: int = 2_500_000,
        expires_in: timedelta = timedelta(days=90),
        key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.agent_key = key or Ed25519PrivateKey.generate()
        pub = self.agent_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        now = self.clock.now()
        with self.tx() as ctx:
            ctx.session.add(
                Agent(
                    id=self.agent_id,
                    display_name="Accounts payable agent (simulated)",
                    key_id=f"{self.agent_id}-k1",
                    public_key=pub,
                    active=True,
                )
            )
            ctx.session.flush()
            ctx.session.add(
                Mandate(
                    agent_id=self.agent_id,
                    version=1,
                    principal_org=ORG,
                    permitted_operations=["read_invoice", "extract_fields", "propose_payment"],
                    forbidden_operations=["change_bank_details", "approve", "execute", "edit_mandate"],
                    supplier_scope=scope or ["*"],
                    per_proposal_ceiling_minor=ceiling,
                    daily_ceiling_minor=daily,
                    approver_role="finance_approver",
                    second_approver_above_minor=second_above,
                    not_before=now - timedelta(days=1),
                    expires_at=now + expires_in,
                    created_by=self.users["eng1"].id if "eng1" in self.users else "system",
                )
            )

    def new_mandate_version(self, **changes: Any) -> int:
        with self.tx() as ctx:
            cur = ctx.session.execute(
                select(Mandate)
                .where(Mandate.agent_id == self.agent_id)
                .order_by(Mandate.version.desc())
                .limit(1)
            ).scalar_one()
            fields = {
                c: getattr(cur, c)
                for c in (
                    "permitted_operations",
                    "forbidden_operations",
                    "supplier_scope",
                    "per_proposal_ceiling_minor",
                    "daily_ceiling_minor",
                    "approver_role",
                    "second_approver_above_minor",
                    "not_before",
                    "expires_at",
                )
            }
            fields.update(changes)
            m = Mandate(
                agent_id=self.agent_id,
                version=cur.version + 1,
                principal_org=ORG,
                created_by="eng1",
                **fields,
            )
            ctx.session.add(m)
            return m.version

    def revoke_mandate(self) -> None:
        with self.tx() as ctx:
            cur = ctx.session.execute(
                select(Mandate)
                .where(Mandate.agent_id == self.agent_id)
                .order_by(Mandate.version.desc())
                .limit(1)
            ).scalar_one()
            cur.revoked_at = self.clock.now()

    # ---------- suppliers ----------

    def verified_supplier(
        self, legal_name: str, registry_id: str, domain: str, account: str, bank: str = "First Fictional Bank"
    ) -> tuple[str, str]:
        """Onboard through the real workflow: requester, verifier and steward are three people."""
        simulated.register_account_holder(normalize_account(account), legal_name)
        with self.tx() as ctx:
            req = onboarding.request_new_supplier(
                ctx,
                self.actor("ap1"),
                onboarding.NewSupplier(
                    legal_name=legal_name,
                    verified_domains=[domain],
                    registry_id=registry_id,
                    contact_on_file={"phone": "+1-555-0100", "name": "Accounts receivable desk"},
                    bank_account_raw=account,
                    bank_name=bank,
                    channel="user_entered",
                ),
            )
            rid, sid = req.id, req.supplier_id
        # The contact on file must predate verification requests; time moves on.
        with self.tx() as ctx:
            onboarding.assign_verifier(ctx, self.actor("stw1"), rid, self.actor("ver1"))
        with self.tx() as ctx:
            onboarding.record_verification(
                ctx, self.actor("ver1"), rid, onboarding.VerificationClaim("simulated_validation_service")
            )
        with self.tx() as ctx:
            onboarding.steward_approve(ctx, self.actor("stw1"), rid)
        with self.tx() as ctx:
            acct = ctx.session.execute(
                select(SupplierBankAccount).where(SupplierBankAccount.supplier_id == sid)
            ).scalar_one()
            return sid, acct.id

    def bank_change(
        self,
        supplier_id: str,
        new_account: str,
        *,
        recorder: str = "ap2",
        channel: str = "email",
        old: OldAccountOutcome = OldAccountOutcome.STILL_VALID,
    ) -> str:
        with self.tx() as ctx:
            req = onboarding.record_bank_change(
                ctx,
                self.actor(recorder),
                supplier_id=supplier_id,
                new_account_raw=new_account,
                bank_name="Second Fictional Bank",
                channel=channel,
                old_account_outcome=old,
            )
            return req.id

    def verify_bank_change(
        self, request_id: str, *, verifier: str = "ver2", steward: str = "stw1", confirmed: bool = True
    ) -> None:
        with self.tx() as ctx:
            onboarding.assign_verifier(ctx, self.actor(steward), request_id, self.actor(verifier))
        with self.tx() as ctx:
            onboarding.record_verification(
                ctx,
                self.actor(verifier),
                request_id,
                onboarding.VerificationClaim("callback_on_file", callback_confirmed=confirmed),
            )
        with self.tx() as ctx:
            onboarding.steward_approve(ctx, self.actor(steward), request_id)

    def purchase_order(
        self, supplier_id: str, po_number: str, amount_minor: int, currency: str = "USD"
    ) -> None:
        with self.tx() as ctx:
            ctx.session.add(
                PurchaseOrder(
                    supplier_id=supplier_id,
                    po_number=po_number,
                    amount_minor=amount_minor,
                    currency=currency,
                    created_by=self.users["ap1"].id,
                )
            )

    # ---------- invoices (simulated ingestion output; M2 replaces with the real pipeline) ----------

    def invoice(
        self,
        *,
        supplier_id: str | None,
        supplier_name: str,
        amount_minor: int,
        account: str,
        po_number: str | None,
        invoice_number: str = "INV-1001",
        currency: str = "USD",
        source: SourceKind = SourceKind.EMAIL_ATTACHMENT,
        consistency: Consistency = Consistency.CONSISTENT,
        signals: list[tuple[str, str]] | None = None,
        duplicate_of: str | None = None,
        body: str | None = None,
    ) -> str:
        now = self.clock.now()
        text = body or (
            f"INVOICE {invoice_number}\nFrom: {supplier_name}\nPO: {po_number}\n"
            f"Amount due: {amount_minor / 100:.2f} {currency}\nRemit to account {account}\n"
        )
        with self.tx() as ctx:
            doc = Document(
                source_kind=source.value,
                trust_class=trust_for(source).value,
                file_digest=sha256_hex(text.encode()),
                filename=f"{invoice_number}.pdf",
                media_type="application/pdf",
                size_bytes=len(text),
                transport={},
                text_content=text,
                pages=[{"page": 1, "text": text}],
                received_at=now,
            )
            ctx.session.add(doc)
            ctx.session.flush()
            inv = Invoice(
                document_id=doc.id,
                supplier_id=supplier_id,
                invoice_number=invoice_number,
                invoice_digest=doc.file_digest,
                amount_minor=amount_minor,
                currency=currency,
                po_number=po_number,
                duplicate_of=duplicate_of,
                created_at=now,
            )
            ctx.session.add(inv)
            ctx.session.flush()
            store_account(ctx.session, account)

            def f(name: str, token: str, display: str) -> None:
                ctx.session.add(
                    ExtractedField(
                        invoice_id=inv.id,
                        field_name=name,
                        value_token=token,
                        display_value=display,
                        source_kind=source.value,
                        trust_class=trust_for(source).value,
                        source_ref={"document_id": doc.id, "page": 1},
                        consistency=consistency.value,
                        extractor={"model": "deterministic", "prompt_version": "n/a"},
                    )
                )

            f("amount", amount_token(amount_minor), f"{amount_minor / 100:.2f}")
            f("currency", text_token("currency", currency), currency)
            f("beneficiary_account", account_token(account), mask_account(account))
            f("supplier_name", text_token("supplier_name", supplier_name), supplier_name)
            for code, sev in signals or []:
                ctx.session.add(Signal(invoice_id=inv.id, code=code, severity=sev, detail={}))
            return inv.id

    # ---------- payment lifecycle ----------

    def propose(
        self,
        invoice_id: str,
        *,
        amount_minor: int,
        account: str,
        supplier_id: str | None,
        key: str,
        currency: str = "USD",
        operation: str = "propose_payment",
        signature_valid: bool = True,
    ) -> payments.EvaluationResult:
        with self.tx() as ctx:
            return payments.propose(
                ctx,
                self.agent,
                payments.Proposal(
                    invoice_id=invoice_id,
                    supplier_id=supplier_id,
                    amount_minor=amount_minor,
                    currency=currency,
                    beneficiary_account=account,
                    idempotency_key=key,
                    operation=operation,
                ),
                signature_valid=signature_valid,
            )

    def approve(self, payment_id: str, approver: str, *, tamper: bool = False) -> approvals.ApprovalOutcome:
        with self.tx() as ctx:
            u = ctx.session.get(User, self.users[approver].id)
            assert u is not None
            issued = approvals.begin_approval(ctx, payment_id, u)
        cred = self.keys[approver].get_assertion(issued.options_json, tamper_challenge=tamper)
        with self.tx() as ctx:
            return approvals.finish_approval(ctx, issued.challenge_id, cred)

    def issue_permit(self, payment_id: str) -> permits.PermitOutcome:
        with self.tx() as ctx:
            return permits.issue_permit(
                ctx, payment_id, Actor("permit-service", "system", frozenset({"system"}))
            )

    def execute(self, permit_id: str, request_id: str) -> executor.ExecutionOutcome:
        with self.tx() as ctx:
            return executor.execute(ctx, permit_id, request_id, self.bank)

    def payment(self, payment_id: str) -> Payment:
        with self.tx() as ctx:
            p = ctx.session.get(Payment, payment_id)
            assert p is not None
            ctx.session.expunge(p)
            return p

    def permit(self, permit_id: str) -> Permit:
        with self.tx() as ctx:
            p = ctx.session.get(Permit, permit_id)
            assert p is not None
            ctx.session.expunge(p)
            return p

    def supplier(self, supplier_id: str) -> Supplier:
        with self.tx() as ctx:
            s = ctx.session.get(Supplier, supplier_id)
            assert s is not None
            ctx.session.expunge(s)
            return s
