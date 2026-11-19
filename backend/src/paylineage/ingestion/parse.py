"""Bounded parsing of inbound email and PDF invoices (FR1, SECURITY application requirements).

Rules: size and page limits, type checked by magic bytes, no network access (links
are parsed and scored, never fetched), no detonation. Trust class is assigned from
the source kind before any model sees the content.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_ATTACHMENTS = 5
MAX_PDF_PAGES = 20
MAX_TEXT_CHARS = 200_000
# The only Authentication-Results we believe: the one our own receiving server adds.
TRUSTED_AUTHSERV_ID = "mx.paylineage.local"
# Known-bad attachment digests (hash list only, no detonation). Fictional sample entry.
KNOWN_BAD_SHA256 = frozenset({"0" * 63 + "1"})

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


class IngestionError(ValueError):
    """Input refused at the boundary."""


@dataclass(frozen=True)
class PageText:
    page: int
    text: str
    hidden: str = ""  # text a person would not see: white, tiny or off page


@dataclass
class Attachment:
    filename: str
    media_type: str
    data: bytes
    digest: str
    pages: list[PageText] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(p.text for p in self.pages)

    @property
    def hidden_text(self) -> str:
        return "\n".join(p.hidden for p in self.pages if p.hidden)


@dataclass
class ParsedEmail:
    digest: str
    from_addr: str
    from_domain: str
    reply_to_domain: str | None
    return_path_domain: str | None
    subject: str
    body: str
    auth: dict[str, str]
    urls: list[str]
    attachments: list[Attachment]
    message_id: str


def _domain(addr: str | None) -> str | None:
    if not addr:
        return None
    _, a = parseaddr(addr)
    if "@" not in a:
        return None
    return a.rsplit("@", 1)[1].strip().lower().rstrip(".")


def parse_auth_results(msg: EmailMessage) -> dict[str, str]:
    """Read spf, dkim and dmarc results only from our own server's header.

    Attackers can add their own Authentication-Results headers; RFC 8601 says to
    trust only those from our authserv-id.
    """
    out: dict[str, str] = {}
    for raw in msg.get_all("Authentication-Results", []) or []:
        value = str(raw)
        authserv = value.split(";", 1)[0].strip().lower()
        if authserv != TRUSTED_AUTHSERV_ID:
            continue
        for method in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{method}=(\w+)", value, re.IGNORECASE)
            if m:
                out[method] = m.group(1).lower()
    return out


def _html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"[ \t]+", " ", text)


def parse_email(raw: bytes) -> ParsedEmail:
    if len(raw) > MAX_EMAIL_BYTES:
        raise IngestionError("email too large")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    if not isinstance(msg, EmailMessage):
        raise IngestionError("not an email")
    from_header = str(msg.get("From", ""))
    from_domain = _domain(from_header)
    if from_domain is None:
        raise IngestionError("From has no address")
    reply_to = msg.get("Reply-To")
    body_parts: list[str] = []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        ctype = part.get_content_type()
        if disp == "attachment" or (part.get_filename() and ctype != "text/plain"):
            if len(attachments) >= MAX_ATTACHMENTS:
                raise IngestionError("too many attachments")
            data = part.get_payload(decode=True) or b""
            if not isinstance(data, bytes):
                raise IngestionError("attachment payload")
            attachments.append(parse_attachment(part.get_filename() or "attachment", data))
        elif ctype == "text/plain":
            body_parts.append(str(part.get_content()))
        elif ctype == "text/html":
            body_parts.append(_html_to_text(str(part.get_content())))
    body = "\n".join(body_parts)[:MAX_TEXT_CHARS]
    tos = getaddresses([str(v) for v in msg.get_all("To", []) or []])
    _ = tos  # recipients are not needed for decisions; kept parsed for validation
    return ParsedEmail(
        digest=hashlib.sha256(raw).hexdigest(),
        from_addr=parseaddr(from_header)[1].lower(),
        from_domain=from_domain,
        reply_to_domain=_domain(str(reply_to)) if reply_to else None,
        return_path_domain=_domain(str(msg.get("Return-Path", "")) or None),
        subject=str(msg.get("Subject", ""))[:300],
        body=body,
        auth=parse_auth_results(msg),
        urls=_URL_RE.findall(body)[:50],
        attachments=attachments,
        message_id=str(msg.get("Message-ID", ""))[:200],
    )


def sniff_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    return "text/plain"


def parse_attachment(filename: str, data: bytes) -> Attachment:
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise IngestionError("attachment too large")
    digest = hashlib.sha256(data).hexdigest()
    if digest in KNOWN_BAD_SHA256:
        raise IngestionError("attachment matches a known-bad hash")
    media = sniff_type(data)  # never trust the declared type or extension
    if media == "application/pdf":
        pages = parse_pdf(data)
    elif media == "text/plain":
        pages = [PageText(1, data.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS])]
    else:
        raise IngestionError(f"unsupported attachment type for {filename}")
    return Attachment(filename=filename[:200], media_type=media, data=data, digest=digest, pages=pages)


def _is_hidden(ch: object, page_w: float, page_h: float) -> bool:
    size = float(getattr(ch, "size", 10.0))
    x0, y0 = float(getattr(ch, "x0", 0.0)), float(getattr(ch, "y0", 0.0))
    if size < 2.0:
        return True
    if x0 < -1 or y0 < -1 or x0 > page_w + 1 or y0 > page_h + 1:
        return True
    gs = getattr(ch, "graphicstate", None)
    color = getattr(gs, "ncolor", None) if gs is not None else None
    if isinstance(color, (int, float)):  # grey
        return float(color) > 0.97
    if isinstance(color, (list, tuple)):
        vals = [float(c) for c in color if isinstance(c, (int, float))]
        if len(vals) == 3:
            return min(vals) > 0.97  # near-white RGB
        if len(vals) == 4:
            return max(vals) < 0.03  # CMYK with no ink is white
    return False


def parse_pdf(data: bytes) -> list[PageText]:
    """Text per page, separating what a reader sees from what is hidden."""
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LAParams, LTChar, LTTextContainer, LTTextLine

    pages: list[PageText] = []
    try:
        for i, layout in enumerate(
            extract_pages(io.BytesIO(data), laparams=LAParams(), maxpages=MAX_PDF_PAGES)
        ):
            w, h = float(layout.width), float(layout.height)
            visible_lines: list[str] = []
            hidden_lines: list[str] = []
            for element in layout:
                if not isinstance(element, LTTextContainer):
                    continue
                for line in element:
                    if not isinstance(line, LTTextLine):
                        continue
                    vis: list[str] = []
                    hid: list[str] = []
                    for ch in line:
                        if isinstance(ch, LTChar):
                            (hid if _is_hidden(ch, w, h) else vis).append(ch.get_text())
                        else:
                            vis.append(ch.get_text())
                    v, hd = "".join(vis).rstrip("\n"), "".join(hid).strip()
                    if v.strip():
                        visible_lines.append(v)
                    if hd:
                        hidden_lines.append(hd)
            pages.append(
                PageText(
                    i + 1, "\n".join(visible_lines)[:MAX_TEXT_CHARS], "\n".join(hidden_lines)[:MAX_TEXT_CHARS]
                )
            )
    except Exception as exc:
        raise IngestionError(f"unreadable PDF: {type(exc).__name__}") from exc
    if not pages:
        raise IngestionError("PDF has no pages")
    return pages
