"""Software WebAuthn authenticator for tests and the evaluation harness ONLY.

Produces real ES256 registration and assertion responses, so the server's real
py_webauthn verification path runs end to end. Never wired into the app.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class SoftAuthenticator:
    rp_id: str = "localhost"
    origin: str = "http://localhost:3000"
    user_verified: bool = True
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0

    @property
    def credential_id_b64(self) -> str:
        return b64u(self.credential_id)

    def _flags(self, attested: bool) -> int:
        f = 0x01  # user present
        if self.user_verified:
            f |= 0x04
        if attested:
            f |= 0x40
        return f

    def _cose_public_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def register(self, options_json: str, *, origin: str | None = None) -> dict[str, Any]:
        opts = json.loads(options_json)
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": opts["challenge"],
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + self.sign_count.to_bytes(4, "big")
            + b"\x00" * 16
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_public_key()
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att)},
            "clientExtensionResults": {},
        }

    def get_assertion(
        self,
        options_json: str,
        *,
        origin: str | None = None,
        user_handle: str | None = None,
        tamper_challenge: bool = False,
    ) -> dict[str, Any]:
        opts = json.loads(options_json)
        challenge = opts["challenge"]
        if tamper_challenge:
            challenge = b64u(secrets.token_bytes(32))
        self.sign_count += 1
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(attested=False)])
            + self.sign_count.to_bytes(4, "big")
        )
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        resp: dict[str, Any] = {
            "clientDataJSON": b64u(client_data),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(sig),
        }
        if user_handle:
            resp["userHandle"] = b64u(user_handle.encode())
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": resp,
            "clientExtensionResults": {},
        }
