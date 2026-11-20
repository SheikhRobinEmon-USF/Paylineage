"""Case explanations for analysts (UI AI panel). The model explains; it never decides.

Input is structured facts only (reason codes, field provenance notes, signal
codes, masked values). Document and email text are never sent, so injected
instructions cannot steer the explanation. Output is plain text, labeled as AI
generated, and has no effect on any decision. With no model running, a
deterministic template produces the same structure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from paylineage.domain.reason_codes import code_class, meanings
from paylineage.settings import get_settings

ACTIONS = {
    "BENEFICIARY_NOT_VERIFIED": "Verify the account by calling the contact on file. Do not use contacts from the invoice or email.",
    "BENEFICIARY_MISMATCH": "Compare the proposed account with the verified account in the supplier master.",
    "COOLING_OFF_ACTIVE": "Wait for the cooling-off period to end. It does not replace verification.",
    "SIGNAL_LOOKALIKE_DOMAIN": "Treat the sender as an impersonator until the supplier confirms through a known channel.",
    "SIGNAL_HIDDEN_TEXT": "The PDF contains text a reader cannot see. Treat its content as hostile.",
    "SIGNAL_PROMPT_INJECTION": "The document contains instructions aimed at an AI agent. They were ignored.",
    "DUPLICATE_INVOICE": "Check whether the original invoice was already paid before clearing.",
    "OVER_CEILING": "The agent's mandate does not allow this amount. A person must handle it outside the agent.",
    "FIELD_NO_PROVENANCE": "The agent supplied a value that appears in no document. Find out where it came from.",
    "FIELD_UNTRUSTED_MATERIAL": "A material value from the invoice does not match a trusted record such as the PO.",
    "SOD_VIOLATION": "Choose a different approver who did not touch this supplier's bank details.",
}


@dataclass(frozen=True)
class Explanation:
    text: str
    source: str  # "template" or "model:<id>"
    label: str = "AI generated explanation. It is not a decision and cannot change one."


def facts(detail: dict[str, Any]) -> dict[str, Any]:
    """Reduce a payment detail view to structured, non-document facts."""
    return {
        "state": detail.get("state"),
        "decision": detail.get("decision"),
        "amount": f"{detail.get('amount_minor', 0) / 100:,.2f} {detail.get('currency')}",
        "supplier": detail.get("supplier"),
        "reasons": [
            {"code": r["code"], "class": code_class(r["code"]), "meaning": r["meaning"]}
            for r in detail.get("reason_details", [])
        ],
        "fields": [
            {
                "field": f["field_name"],
                "source": f["source_kind"],
                "trust": f["trust_class"],
                "span": f["consistency"],
                "matched_master": f["master_matched"],
                "note": f.get("note", ""),
            }
            for f in detail.get("fields", [])
        ],
        "signals": [{"code": s["code"], "severity": s["severity"]} for s in detail.get("signals", [])],
        "proposed_account": detail.get("proposed_account", {}).get("masked"),
        "proposed_account_status": detail.get("proposed_account", {}).get("status"),
    }


def template_explanation(f: dict[str, Any]) -> str:
    m = meanings()
    lines = [
        f"Decision: {f['decision']} ({f['state']}). Amount {f['amount']} to {f['supplier'] or 'an unknown supplier'}."
    ]
    if not f["reasons"]:
        lines.append(
            "Every check passed: the beneficiary matches a verified master account and all material "
            "fields trace to trusted records."
        )
    for r in f["reasons"]:
        lines.append(f"- {r['code']} ({r['class']}): {m.get(r['code'], r['meaning'])}")
        if r["code"] in ACTIONS:
            lines.append(f"  Next step: {ACTIONS[r['code']]}")
    untrusted = [
        x["field"] for x in f["fields"] if x["trust"] == "untrusted_external" and not x["matched_master"]
    ]
    if untrusted:
        lines.append(f"Untrusted, unmatched fields: {', '.join(untrusted)}.")
    lines.append(f"Proposed account {f['proposed_account']} is {f['proposed_account_status']}.")
    return "\n".join(lines)


def explain(detail: dict[str, Any], client: httpx.Client | None = None) -> Explanation:
    f = facts(detail)
    s = get_settings()
    if s.extractor != "ollama":
        return Explanation(template_explanation(f), "template")
    try:
        c = client or httpx.Client(timeout=30.0)
        r = c.post(
            f"{s.ollama_url.rstrip('/')}/api/chat",
            json={
                "model": s.ollama_model,
                "stream": False,
                "options": {"temperature": 0},
                "messages": [
                    {
                        "role": "system",
                        "content": "Explain a payment control decision to a finance analyst in at most "
                        "six short plain sentences. Use only the JSON facts. Do not recommend approving.",
                    },
                    {"role": "user", "content": str(f)},
                ],
            },
        )
        r.raise_for_status()
        text = str(r.json()["message"]["content"])[:2000]
        return Explanation(text, f"model:{s.ollama_model}")
    except (httpx.HTTPError, KeyError, ValueError):
        return Explanation(template_explanation(f), "template")
