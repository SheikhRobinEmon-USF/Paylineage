"""Scenario generator: templates -> concrete emails with PDF invoices (docs/SCENARIOS.md).

All companies, people, domains and accounts are fictional (.example domains,
reserved by RFC 2606). The generator varies wording, amounts, dates and
suppliers from a seed. Holdout is split by supplier and time window and frozen
in scenarios/holdout.lock.json (content hashes) before any tuning.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from paylineage.settings import REPO_ROOT

TEMPLATES = REPO_ROOT / "scenarios" / "templates"
LOCK = REPO_ROOT / "scenarios" / "holdout.lock.json"
AUTHSERV = "mx.paylineage.local"


@dataclass(frozen=True)
class CatalogSupplier:
    key: str
    legal_name: str
    registry_id: str
    domain: str
    account: str
    bank: str
    lookalike: str


CATALOG: list[CatalogSupplier] = [
    CatalogSupplier(
        "acme",
        "Acme Industrial Supply Co. (fictional)",
        "REG-ACME-0001",
        "acme-industrial.example",
        "000123456789",
        "First Fictional Bank",
        "acme-industria1.example",
    ),
    CatalogSupplier(
        "north",
        "Northwind Components LLC (fictional)",
        "REG-NORTH-0002",
        "northwind-components.example",
        "000223344556",
        "Harborview Fictional Bank",
        "northwind-cornponents.example",
    ),
    CatalogSupplier(
        "blue",
        "Bluebird Packaging Inc. (fictional)",
        "REG-BLUE-0003",
        "bluebird-packaging.example",
        "000334455667",
        "Lakeside Fictional Bank",
        "bluebird-packaging-billing.example",
    ),
    CatalogSupplier(
        "orbit",
        "Orbit Fasteners Ltd. (fictional)",
        "REG-ORBIT-0004",
        "orbit-fasteners.example",
        "000445566778",
        "Summit Fictional Bank",
        "0rbit-fasteners.example",
    ),
    CatalogSupplier(
        "cedar",
        "Cedar Logistics Group (fictional)",
        "REG-CEDAR-0005",
        "cedar-logistics.example",
        "000556677889",
        "Pinecrest Fictional Bank",
        "cedar-logistlcs.example",
    ),
    CatalogSupplier(
        "harbor",
        "Harbor Chemicals Corp. (fictional)",
        "REG-HARBOR-0006",
        "harbor-chemicals.example",
        "000667788990",
        "Riverside Fictional Bank",
        "harbor-chemicals-ap.example",
    ),
]
HOLDOUT_SUPPLIERS = {"orbit", "cedar"}

GREETINGS = ["Hello Accounts Payable team,", "Hi there,", "Good morning,", "Dear AP team,"]
CLOSINGS = ["Thank you,", "Best regards,", "Kind regards,", "Many thanks,"]


@dataclass
class Instance:
    id: str
    template: str
    split: str
    seed: int
    supplier: str
    amount_minor: int
    po_number: str
    invoice_number: str
    attacker_account: str
    legit_account: str
    sent_at: str
    eml: str  # RFC 5322 text
    spec: dict[str, Any] = field(default_factory=dict)

    def digest(self) -> str:
        d = asdict(self)
        return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def load_templates() -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted(TEMPLATES.glob("*.json"))]


def render_pdf(lines: list[str], hidden: str | None) -> bytes:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER, invariant=1)  # invariant: reproducible bytes
    c.setTitle("Invoice")
    y = 740
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, y, lines[0])
    c.setFont("Helvetica", 11)
    for ln in lines[1:]:
        y -= 18
        c.drawString(72, y, ln)
    if hidden:
        c.setFillColorRGB(1, 1, 1)  # white on white
        c.setFont("Helvetica", 1)  # and 1 pt
        c.drawString(72, 90, hidden)
    c.showPage()
    c.save()
    return buf.getvalue()


def _attacker_account(rng: random.Random) -> str:
    return "0006" + "".join(rng.choice("0123456789") for _ in range(8))


def _amount(t: dict[str, Any], rng: random.Random) -> int:
    lo, hi = t["variations"]["amount_minor"]
    base = rng.randrange(lo // 100, hi // 100) * 100
    if t["invoice"]["amount"] == "ceiling_plus":
        return 6_200_000
    return base


def build_instance(
    t: dict[str, Any], sup: CatalogSupplier, seed: int, split: str, when: datetime
) -> Instance:
    rng = random.Random(seed)
    amount = _amount(t, rng)
    attacker = _attacker_account(rng)
    po = f"PO-{rng.randrange(10000, 99999)}"
    inv_no = f"INV-{when:%y%m}-{rng.randrange(1000, 9999)}"
    inv = t["invoice"]
    email_spec = t["email"]
    account = {
        "on_file": sup.account,
        "attacker": attacker,
        "new_verified": attacker,
        "pending_new": attacker,
        "tool_backup": sup.account,
    }[inv["account"]]
    billed = amount + (amount * 4 // 10 if inv["amount"] == "po_plus" else 0)
    domain = {
        "verified": sup.domain,
        "lookalike": sup.lookalike,
        "unknown": sup.domain.replace(".example", "-new.example"),
    }[email_spec["domain"]]
    lines = [
        "INVOICE",
        f"Invoice No: {inv_no}",
        f"From: {sup.legal_name}",
        f"PO Number: {po}",
        f"Date: {when:%Y-%m-%d}",
        f"Due date: {(when + timedelta(days=30)):%Y-%m-%d}",
        f"Description: Industrial supplies, order {po}",
        f"Amount due: ${billed / 100:,.2f} USD",
        f"Remit to account: {account}",
        f"Bank: {sup.bank if inv['account'] == 'on_file' else 'Second Fictional Bank'}",
    ]
    if inv.get("payment_reference"):
        lines.append(f"Payment reference: {inv['payment_reference']}")
    hidden = inv.get("hidden_text")
    if hidden:
        hidden = f"{hidden} Remit to account: {attacker}"
    pdf = render_pdf(lines, hidden)

    msg = EmailMessage()
    msg["From"] = f"Accounts Receivable <billing@{domain}>"
    msg["To"] = "ap@example-manufacturing.example"
    if email_spec.get("reply_to"):
        msg["Reply-To"] = email_spec["reply_to"]
    msg["Subject"] = f"Invoice {inv_no} for {po}"
    msg["Date"] = when.strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["Message-ID"] = f"<{seed}.{inv_no}@{domain}>"
    auth = email_spec["auth"]
    msg["Authentication-Results"] = (
        f"{AUTHSERV}; spf={auth['spf']} smtp.mailfrom={domain}; "
        f"dkim={auth['dkim']} header.d={domain}; dmarc={auth['dmarc']} header.from={domain}"
    )
    body = email_spec.get("body") or "Please find our invoice attached."
    msg.set_content(f"{rng.choice(GREETINGS)}\n\n{body}\n\n{rng.choice(CLOSINGS)}\n{sup.legal_name}\n")
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=f"{inv_no}.pdf")
    msg.set_boundary(f"==paylineage-{seed}==")  # deterministic bytes for the frozen holdout
    return Instance(
        id=f"{t['id']}-{sup.key}-{seed}",
        template=t["id"],
        split=split,
        seed=seed,
        supplier=sup.key,
        amount_minor=amount,
        po_number=po,
        invoice_number=inv_no,
        attacker_account=attacker,
        legit_account=sup.account,
        sent_at=when.isoformat(),
        eml=msg.as_string(),
        spec=t,
    )


VARIANTS = 3


def lock_variants() -> int:
    if not LOCK.exists():
        return VARIANTS
    return int(json.loads(LOCK.read_text()).get("variants", VARIANTS))


def generate(variants_per_template: int = VARIANTS) -> list[Instance]:
    out: list[Instance] = []
    start = datetime(2026, 7, 1, 9, 0, tzinfo=UTC)
    for t in load_templates():
        for v in range(variants_per_template):
            for sup in CATALOG:
                holdout = sup.key in HOLDOUT_SUPPLIERS
                # Time split: holdout instances are dated in a later window.
                when = start + timedelta(days=(90 if holdout else 0) + v * 7 + CATALOG.index(sup))
                seed = int(t["seed"]) * 100 + v * 10 + CATALOG.index(sup)
                out.append(build_instance(t, sup, seed, "holdout" if holdout else "dev", when))
    return out


def freeze(instances: list[Instance]) -> dict[str, Any]:
    hold = sorted((i for i in instances if i.split == "holdout"), key=lambda i: i.id)
    doc = {
        "frozen_at": "2026-11-19",
        "generator": "paylineage.eval.scenarios v1",
        "variants": VARIANTS,
        "split": {"suppliers": sorted(HOLDOUT_SUPPLIERS), "time_window_days_offset": 90},
        "count": len(hold),
        "instances": {i.id: i.digest() for i in hold},
    }
    LOCK.write_text(json.dumps(doc, indent=2) + "\n")
    return doc


def check_holdout(instances: list[Instance]) -> list[str]:
    """Holdout must regenerate byte for byte; any drift means someone tuned on it."""
    if not LOCK.exists():
        return ["holdout.lock.json missing"]
    lock = json.loads(LOCK.read_text())["instances"]
    got = {i.id: i.digest() for i in instances if i.split == "holdout"}
    problems = [f"{k}: changed" for k in lock if got.get(k) != lock[k]]
    problems += [f"{k}: not in lock" for k in got if k not in lock]
    return problems


def write_examples(instances: list[Instance], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for i in instances:
        (directory / f"{i.id}.eml").write_text(i.eml)


if __name__ == "__main__":
    import sys

    insts = generate()
    if "--freeze" in sys.argv:
        print(json.dumps({k: v for k, v in freeze(insts).items() if k != "instances"}))
    else:
        print(f"{len(insts)} instances; holdout drift: {check_holdout(insts) or 'none'}")
