"""Ingestion pipeline: email -> documents (trust assigned) -> extraction -> span check -> signals -> invoice.

Order matters (ARCHITECTURE): trust class is assigned from the source before any
model runs. The extractor sees visible text only. Nothing here can create a
verified supplier or a verified account (I1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select

from paylineage.audit.chain import append
from paylineage.db.models import Document, ExtractedField, Invoice, Signal, Supplier
from paylineage.db.vault import account_token, mask_account, store_account
from paylineage.domain.context import Actor, Ctx
from paylineage.domain.enums import FieldName, SourceKind, SupplierStatus, trust_for
from paylineage.extraction.extractors import DocView, Extracted, Extractor, verify_span
from paylineage.ingestion.parse import ParsedEmail, parse_email
from paylineage.policy.input_builder import amount_token, text_token
from paylineage.settings import get_settings
from paylineage.signals.detect import (
    SignalHit,
    damerau,
    email_signals,
    hidden_text_signal,
    prompt_injection_signal,
)

INGESTION = Actor("ingestion", "system", frozenset({"system"}))


@dataclass
class IngestResult:
    invoice_id: str
    supplier_id: str | None
    fields: dict[str, str]  # field -> normalized value (for the planner; never raw document text)
    signals: list[SignalHit] = field(default_factory=list)
    consistency: dict[str, str] = field(default_factory=dict)


def _token(f: FieldName, value: str) -> tuple[str, str]:
    """Token and display value. Account numbers are tokenized and masked (CLAUDE.md)."""
    if f is FieldName.BENEFICIARY_ACCOUNT:
        return account_token(value), mask_account(value)
    if f is FieldName.AMOUNT:
        return amount_token(int(value)), f"{int(value) / 100:,.2f}"
    return text_token(f.value, value), value[:200]


def verified_domains(ctx: Ctx) -> dict[str, str]:
    rows = ctx.session.execute(
        select(Supplier).where(Supplier.status == SupplierStatus.VERIFIED.value)
    ).scalars()
    return {d: s.id for s in rows for d in s.verified_domains}


def resolve_supplier(ctx: Ctx, from_domain: str, supplier_name: str | None) -> str | None:
    domains = verified_domains(ctx)
    if from_domain in domains:
        return domains[from_domain]
    if supplier_name:
        s = (
            ctx.session.execute(select(Supplier).where(Supplier.legal_name.ilike(supplier_name.strip())))
            .scalars()
            .first()
        )
        if s is not None:
            return s.id  # a claim of identity; payability still needs a verified account (I2)
    return None


def find_duplicate(
    ctx: Ctx, supplier_id: str | None, amount: int | None, number: str | None, digest: str
) -> str | None:
    since = ctx.now() - timedelta(days=120)
    q = select(Invoice).where(Invoice.created_at >= since)
    for inv in ctx.session.execute(q).scalars():
        if inv.invoice_digest == digest:
            return inv.id
        if (
            supplier_id
            and inv.supplier_id == supplier_id
            and amount
            and inv.amount_minor == amount
            and number
            and inv.invoice_number
            and damerau(inv.invoice_number.upper(), number.upper()) <= 2
        ):
            return inv.id
    return None


def ingest_email(
    ctx: Ctx, raw: bytes, extractor: Extractor, *, scenario_id: str | None = None
) -> IngestResult:
    parsed: ParsedEmail = parse_email(raw)
    now = ctx.now()
    email_doc = Document(
        source_kind=SourceKind.EMAIL_BODY.value,
        trust_class=trust_for(SourceKind.EMAIL_BODY).value,
        file_digest=parsed.digest,
        filename=None,
        media_type="message/rfc822",
        size_bytes=len(raw),
        transport={
            "from": parsed.from_addr,
            "from_domain": parsed.from_domain,
            "reply_to_domain": parsed.reply_to_domain,
            "auth": parsed.auth,
            "subject": parsed.subject,
            "urls": parsed.urls[:20],
            "message_id": parsed.message_id,
        },
        text_content=parsed.body,
        pages=[{"page": 1, "text": parsed.body}],
        received_at=now,
    )
    ctx.session.add(email_doc)
    ctx.session.flush()
    pdf = next((a for a in parsed.attachments), None)
    inv_doc = email_doc
    if pdf is not None:
        inv_doc = Document(
            parent_id=email_doc.id,
            source_kind=SourceKind.EMAIL_ATTACHMENT.value,
            trust_class=trust_for(SourceKind.EMAIL_ATTACHMENT).value,
            file_digest=pdf.digest,
            filename=pdf.filename,
            media_type=pdf.media_type,
            size_bytes=len(pdf.data),
            transport={},
            text_content=pdf.text,
            pages=[{"page": p.page, "text": p.text, "hidden": p.hidden} for p in pdf.pages],
            received_at=now,
        )
        ctx.session.add(inv_doc)
        ctx.session.flush()

    view = DocView(attachment_pages=[p.text for p in pdf.pages] if pdf else [], body=parsed.body)
    hidden = pdf.hidden_text if pdf else ""
    extracted: list[Extracted] = extractor.extract(view)
    by_field = {e.field: e for e in extracted}

    name = by_field.get(FieldName.SUPPLIER_NAME)
    supplier_id = resolve_supplier(ctx, parsed.from_domain, name.value if name else None)
    amount_e = by_field.get(FieldName.AMOUNT)
    amount = int(amount_e.value) if amount_e and amount_e.value.isdigit() else None
    number_e = by_field.get(FieldName.INVOICE_NUMBER)
    po_e = by_field.get(FieldName.PO_NUMBER)
    cur_e = by_field.get(FieldName.CURRENCY)
    dup = find_duplicate(ctx, supplier_id, amount, number_e.value if number_e else None, inv_doc.file_digest)

    inv = Invoice(
        document_id=inv_doc.id,
        email_document_id=email_doc.id,
        supplier_id=supplier_id,
        invoice_number=number_e.value[:64] if number_e else None,
        invoice_digest=inv_doc.file_digest,
        amount_minor=amount,
        currency=cur_e.value if cur_e else None,
        po_number=po_e.value[:64] if po_e else None,
        duplicate_of=dup,
        scenario_id=scenario_id,
        created_at=now,
    )
    ctx.session.add(inv)
    ctx.session.flush()

    consistency: dict[str, str] = {}
    for e in extracted:
        status, why = verify_span(e, view, hidden)
        consistency[e.field.value] = status
        if e.field is FieldName.BENEFICIARY_ACCOUNT and e.value:
            store_account(ctx.session, e.value)
        if e.field is FieldName.AMOUNT and not e.value.isdigit():
            continue
        token, display = _token(e.field, e.value)
        src = SourceKind.EMAIL_ATTACHMENT if e.where == "attachment" else SourceKind.EMAIL_BODY
        ctx.session.add(
            ExtractedField(
                invoice_id=inv.id,
                field_name=e.field.value,
                value_token=token,
                display_value=display,
                source_kind=src.value,
                trust_class=trust_for(src).value,
                source_ref={
                    "document_id": inv_doc.id if e.where == "attachment" else email_doc.id,
                    "page": e.page,
                    "quote": e.quote[:300],
                    "span_check": why,
                },
                consistency=status,
                extractor={
                    "model": extractor.info.model,
                    "model_digest": extractor.info.model_digest,
                    "prompt_version": extractor.info.prompt_version,
                },
            )
        )

    signals: list[SignalHit] = []
    signals += email_signals(
        parsed.from_domain, parsed.reply_to_domain, parsed.auth, list(verified_domains(ctx))
    )
    signals += hidden_text_signal(hidden)
    model_score = None
    if get_settings().prompt_guard == "model":
        from paylineage.signals.prompt_guard import malicious_probability

        model_score = malicious_probability(
            "\n".join([parsed.body, view.attachment_pages[0] if pdf else "", hidden])
        )
    if get_settings().prompt_guard != "off":
        signals += prompt_injection_signal(
            [parsed.subject, parsed.body, *view.attachment_pages, hidden], model_score=model_score
        )
    for s in signals:
        ctx.session.add(Signal(invoice_id=inv.id, code=s.code, severity=s.severity, detail=s.detail))
    append(
        ctx.session,
        actor=INGESTION.id,
        kind="invoice.ingested",
        subject_id=inv.id,
        payload={
            "email_digest": parsed.digest,
            "attachment_digest": pdf.digest if pdf else None,
            "from_domain": parsed.from_domain,
            "supplier_id": supplier_id,
            "extractor": extractor.info.model,
            "signals": [s.code for s in signals],
            "duplicate_of": dup,
        },
        now=now,
    )
    ctx.session.flush()
    return IngestResult(
        inv.id, supplier_id, {e.field.value: e.value for e in extracted}, signals, consistency
    )
