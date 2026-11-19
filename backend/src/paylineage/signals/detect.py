"""Signals (FR4). Signals raise holds, never allow. All deterministic; no model needed.

Prompt Guard 2 is an optional second opinion for SIGNAL_PROMPT_INJECTION
(PROMPT_GUARD=model). The heuristic always runs, so the app works with no model.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class SignalHit:
    code: str
    severity: Severity
    detail: dict[str, object] = field(default_factory=dict)


# ---------------- lookalike domains ----------------

# Small confusables table: enough for common BEC tricks (digit swaps, Cyrillic, rn -> m).
CONFUSABLES = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ӏ": "l",
    "ԁ": "d",
    "ɡ": "g",
}


def skeleton(domain: str) -> str:
    d = unicodedata.normalize("NFKC", domain.lower())
    with contextlib.suppress(UnicodeError, ValueError):
        d = d.encode("ascii").decode("idna") if d.startswith("xn--") or ".xn--" in d else d
    d = "".join(CONFUSABLES.get(c, c) for c in d)
    d = d.replace("rn", "m").replace("vv", "w").replace("-", "").replace("_", "")
    for z in ("\u200b", "‌", "‍", "﻿"):
        d = d.replace(z, "")
    return d


def _labels(domain: str) -> tuple[str, str]:
    parts = domain.split(".")
    return (".".join(parts[:-1]) if len(parts) > 1 else domain), parts[-1]


def damerau(a: str, b: str) -> int:
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def lookalike_of(sender: str, verified: list[str]) -> str | None:
    """Return the verified domain the sender imitates, or None. Exact matches are not lookalikes."""
    s = sender.lower()
    if s in verified:
        return None
    s_name, s_tld = _labels(skeleton(s))
    for v in verified:
        v_name, v_tld = _labels(skeleton(v))
        if s_name == v_name:  # skeleton equal: confusable or TLD swap
            return v
        if len(v_name) >= 4 and damerau(s_name, v_name) <= 2:
            return v
        if len(v_name) >= 4 and (s_name.startswith(v_name) or s_name.endswith(v_name)) and s_tld:
            return v  # acme -> acmesupply, payacme
        _ = (s_tld, v_tld)
    return None


# ---------------- email transport ----------------


def email_signals(
    from_domain: str, reply_to_domain: str | None, auth: dict[str, str], verified_domains: list[str]
) -> list[SignalHit]:
    hits: list[SignalHit] = []
    target = lookalike_of(from_domain, verified_domains)
    if target:
        hits.append(SignalHit("SIGNAL_LOOKALIKE_DOMAIN", "high", {"sender": from_domain, "imitates": target}))
    if auth.get("dmarc") in ("fail", "permerror"):
        hits.append(SignalHit("SIGNAL_DMARC_FAIL", "high", {"dmarc": auth.get("dmarc")}))
    elif auth.get("dmarc") in (None, "none", "temperror") and from_domain not in verified_domains:
        hits.append(SignalHit("SIGNAL_DMARC_FAIL", "low", {"dmarc": auth.get("dmarc", "absent")}))
    if reply_to_domain and reply_to_domain != from_domain:
        sev: Severity = "high" if lookalike_of(reply_to_domain, verified_domains) else "medium"
        hits.append(
            SignalHit("SIGNAL_REPLY_TO_MISMATCH", sev, {"from": from_domain, "reply_to": reply_to_domain})
        )
    return hits


# ---------------- document content ----------------


def hidden_text_signal(hidden: str) -> list[SignalHit]:
    h = hidden.strip()
    if not h:
        return []
    return [SignalHit("SIGNAL_HIDDEN_TEXT", "high", {"chars": len(h), "excerpt": h[:160]})]


INJECTION_PATTERNS: list[tuple[str, int]] = [
    (r"\bignore (all |any )?(previous|prior|above) (instructions|rules)", 3),
    (r"\b(ai|llm) (assistant|agent)\b", 2),
    (r"\bas an ai\b", 2),
    (r"\b(system|developer) prompt\b", 3),
    (r"\byou are now\b", 2),
    (r"\bnew instructions?\b", 2),
    (r"\bskip (the )?(verification|approval|review|checks?)\b", 3),
    (r"\b(mark|set) (the )?supplier (as )?verified\b", 3),
    (r"\bverification (already|has been) (done|completed)\b", 3),
    (r"\bpay (it )?(immediately|now|today) (to|into)\b", 2),
    (r"\bdo not (tell|notify|inform|contact)\b", 2),
    (r"\b(override|bypass) (the )?(policy|controls?|limits?)\b", 3),
    (r"\b(raise|increase|add) (the )?(amount|total) by\b", 2),
    (r"\bremaining balance to the new account\b", 2),
    (r"\bignora (las )?instrucciones\b|\binstrucci[oó]n para el agente\b", 3),
    (r"\bignorez les instructions\b", 3),
]

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")
_MORSE_RE = re.compile(r"(?:[.\-]{1,6}[ /]){12,}")


def _decoded_blobs(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_RE.findall(text)[:20]:
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() for c in s) / max(len(s), 1) > 0.9:
            out.append(s)
    return out


def injection_score(text: str) -> tuple[int, list[str]]:
    hay = unicodedata.normalize("NFKC", text).lower()
    blobs = _decoded_blobs(text)
    hay_all = hay + "\n" + "\n".join(b.lower() for b in blobs)
    score, hits = 0, []
    for pat, w in INJECTION_PATTERNS:
        if re.search(pat, hay_all):
            score += w
            hits.append(pat)
    if blobs:
        score += 1
        hits.append("encoded_text")
    if _MORSE_RE.search(text):
        score += 2
        hits.append("morse_like")
    return score, hits


def prompt_injection_signal(texts: list[str], *, model_score: float | None = None) -> list[SignalHit]:
    combined = "\n".join(texts)
    score, hits = injection_score(combined)
    if model_score is not None and model_score >= 0.9:
        score += 3
        hits.append("prompt_guard")
    if score >= 3:
        return [SignalHit("SIGNAL_PROMPT_INJECTION", "high", {"score": score, "matched": hits[:6]})]
    if score >= 2:
        return [SignalHit("SIGNAL_PROMPT_INJECTION", "medium", {"score": score, "matched": hits[:6]})]
    return []


TOOL_PATTERNS = [
    r"\b(always|instead) (remit|pay|send|transfer)\b",
    r"\bbackup (settlement )?account\b",
    r"\b(new|updated|alternate) (bank|remittance) (details|account)\b",
    r"\b\d{8,17}\b",
    r"\bignore\b.*\b(verification|policy|approval)\b",
]


def tool_poisoning_signal(tool_descriptions: list[str]) -> list[SignalHit]:
    """Tool descriptions are untrusted. Payment steering inside them is a signal, never authority."""
    for desc in tool_descriptions[:20]:
        low = desc.lower()
        matched = [p for p in TOOL_PATTERNS if re.search(p, low)]
        if matched:
            return [
                SignalHit("SIGNAL_TOOL_POISONING", "high", {"matched": matched[:4], "excerpt": desc[:160]})
            ]
    return []
