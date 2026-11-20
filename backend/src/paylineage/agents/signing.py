"""Agent request signing: HTTP Message Signatures (RFC 9421) with Ed25519, Content-Digest (RFC 9530).

Profile (ADR-015), strict by design. Anything else is rejected:
  Signature-Input: sig1=("@method" "@target-uri" "content-digest")
                   ;created=<int>;keyid="<id>";nonce="<n>";alg="ed25519"   (one line on the wire)
  Signature:       sig1=:<base64 Ed25519 signature>:
  Content-Digest:  sha-256=:<base64 SHA-256 of the body>:

Signature base (RFC 9421 section 2.5): one line per covered component, then the
@signature-params line, joined by LF, no trailing LF.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from paylineage.db.models import Agent, AgentNonce

COMPONENTS = ("@method", "@target-uri", "content-digest")
MAX_SKEW_S = 300
_LABEL = "sig1"
_INPUT_RE = re.compile(
    r'^sig1=\("@method" "@target-uri" "content-digest"\)'
    r";created=(?P<created>[0-9]{1,12})"
    r';keyid="(?P<keyid>[A-Za-z0-9._:-]{1,128})"'
    r';nonce="(?P<nonce>[A-Za-z0-9_-]{16,128})"'
    r';alg="ed25519"$'
)
_SIG_RE = re.compile(r"^sig1=:(?P<sig>[A-Za-z0-9+/]{86}==):$")
_DIGEST_RE = re.compile(r"^sha-256=:(?P<d>[A-Za-z0-9+/]{43}=):$")


class SignatureError(Exception):
    """Any signature failure. Callers map it to AGENT_SIGNATURE_INVALID (deny)."""


def content_digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"


def _params(created: int, keyid: str, nonce: str) -> str:
    comps = " ".join(f'"{c}"' for c in COMPONENTS)
    return f'({comps});created={created};keyid="{keyid}";nonce="{nonce}";alg="ed25519"'


def signature_base(method: str, target_uri: str, digest_header: str, params: str) -> bytes:
    lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {digest_header}',
        f'"@signature-params": {params}',
    ]
    return "\n".join(lines).encode()


@dataclass(frozen=True)
class SignedHeaders:
    content_digest: str
    signature_input: str
    signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            "Content-Digest": self.content_digest,
            "Signature-Input": self.signature_input,
            "Signature": self.signature,
        }


def sign_request(
    key: Ed25519PrivateKey,
    *,
    keyid: str,
    method: str,
    target_uri: str,
    body: bytes,
    created: int,
    nonce: str | None = None,
) -> SignedHeaders:
    n = nonce or secrets.token_urlsafe(24)
    params = _params(created, keyid, n)
    digest = content_digest(body)
    sig = key.sign(signature_base(method, target_uri, digest, params))
    return SignedHeaders(digest, f"{_LABEL}={params}", f"{_LABEL}=:{base64.b64encode(sig).decode()}:")


@dataclass(frozen=True)
class VerifiedAgent:
    agent_id: str
    keyid: str
    nonce: str


def verify_request(
    session: Session, *, method: str, target_uri: str, body: bytes, headers: dict[str, str], now: datetime
) -> VerifiedAgent:
    """Verify and record the nonce. Raises SignatureError on any problem."""
    h = {k.lower(): v for k, v in headers.items()}
    try:
        sig_input, sig_header, digest_header = h["signature-input"], h["signature"], h["content-digest"]
    except KeyError as exc:
        raise SignatureError(f"missing header {exc.args[0]}") from exc
    m = _INPUT_RE.match(sig_input.strip())
    if m is None:
        raise SignatureError("Signature-Input outside the accepted profile")
    s = _SIG_RE.match(sig_header.strip())
    if s is None:
        raise SignatureError("Signature malformed")
    if _DIGEST_RE.match(digest_header.strip()) is None or digest_header.strip() != content_digest(body):
        raise SignatureError("Content-Digest does not match the body")
    created = int(m["created"])
    if abs(now.timestamp() - created) > MAX_SKEW_S:
        raise SignatureError("signature outside the time window")
    keyid = m["keyid"]
    agent = session.query(Agent).filter(Agent.key_id == keyid).one_or_none()
    if agent is None or not agent.active:
        raise SignatureError("unknown or inactive key")
    params = _params(created, keyid, m["nonce"])
    try:
        Ed25519PublicKey.from_public_bytes(agent.public_key).verify(
            base64.b64decode(s["sig"]), signature_base(method, target_uri, digest_header.strip(), params)
        )
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature does not verify") from exc
    inserted = session.execute(
        insert(AgentNonce)
        .values(agent_id=agent.id, nonce=m["nonce"], seen_at=now)
        .on_conflict_do_nothing()
        .returning(AgentNonce.nonce)
    ).first()
    if inserted is None:
        raise SignatureError("nonce replayed")
    return VerifiedAgent(agent.id, keyid, m["nonce"])
