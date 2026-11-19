"""WebAuthn (passkeys) via py_webauthn. Origin and RP id checks are never disabled.

Approval challenges are server issued and commit to the canonical payment digest:

  challenge = SHA-256(RFC 8785({purpose, payment_id, version, digest, challenge_id, nonce}))

so the authenticator's signature covers exactly the record the server will
execute (ADR-005: server-bound approval, not trusted display).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from paylineage.canonical import canonical_bytes, sha256_hex
from paylineage.db.models import User, WebAuthnChallenge, WebAuthnCredential
from paylineage.domain.context import ConflictError, Ctx, ForbiddenError, NotFoundError
from paylineage.settings import Settings, get_settings

CHALLENGE_TTL = timedelta(minutes=5)


def approval_challenge_bytes(
    *, payment_id: str, version: int, digest: str, challenge_id: str, nonce: str
) -> bytes:
    body = {
        "purpose": "approve",
        "payment_id": payment_id,
        "version": version,
        "digest": digest,
        "challenge_id": challenge_id,
        "nonce": nonce,
    }
    return bytes.fromhex(sha256_hex(canonical_bytes(body)))


@dataclass(frozen=True)
class IssuedChallenge:
    challenge_id: str
    options_json: str


def _rp(settings: Settings | None) -> Settings:
    return settings or get_settings()


def begin_registration(ctx: Ctx, user: User, settings: Settings | None = None) -> IssuedChallenge:
    s = _rp(settings)
    challenge = secrets.token_bytes(32)
    row = WebAuthnChallenge(
        purpose="register",
        user_id=user.id,
        challenge=challenge,
        nonce=secrets.token_hex(8),
        expires_at=ctx.now() + CHALLENGE_TTL,
    )
    ctx.session.add(row)
    ctx.session.flush()
    existing = ctx.session.execute(
        select(WebAuthnCredential.id).where(WebAuthnCredential.user_id == user.id)
    ).scalars()
    opts = generate_registration_options(
        rp_id=s.webauthn_rp_id,
        rp_name=s.webauthn_rp_name,
        user_name=user.email,
        user_id=user.id.encode(),
        user_display_name=user.display_name,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_b64d(c)) for c in existing],
    )
    return IssuedChallenge(row.id, options_to_json(opts))


def _b64d(s: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(s)


def _consume_challenge(ctx: Ctx, challenge_id: str, purpose: str) -> WebAuthnChallenge:
    """Single use: conditional update, so a replayed challenge finds zero rows."""
    now = ctx.now()
    res = ctx.session.execute(
        update(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.id == challenge_id,
            WebAuthnChallenge.purpose == purpose,
            WebAuthnChallenge.used_at.is_(None),
            WebAuthnChallenge.expires_at > now,
        )
        .values(used_at=now)
        .returning(WebAuthnChallenge.id)
    ).first()
    if res is None:
        raise ForbiddenError("CHALLENGE_INVALID", "challenge unknown, expired or already used")
    row = ctx.session.get(WebAuthnChallenge, challenge_id)
    assert row is not None
    return row


def finish_registration(
    ctx: Ctx, challenge_id: str, credential: dict[str, Any] | str, settings: Settings | None = None
) -> WebAuthnCredential:
    s = _rp(settings)
    ch = _consume_challenge(ctx, challenge_id, "register")
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=ch.challenge,
            expected_rp_id=s.webauthn_rp_id,
            expected_origin=s.webauthn_origin,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as exc:
        raise ForbiddenError("WEBAUTHN_INVALID", f"registration rejected: {exc}") from exc
    cred = WebAuthnCredential(
        id=bytes_to_base64url(v.credential_id),
        user_id=ch.user_id or "",
        public_key=v.credential_public_key,
        sign_count=v.sign_count,
        transports=[],
    )
    ctx.session.add(cred)
    ctx.session.flush()
    return cred


def begin_assertion(
    ctx: Ctx,
    *,
    purpose: str,
    challenge: bytes,
    user_id: str | None,
    nonce: str,
    payment: tuple[str, int, str] | None = None,
    settings: Settings | None = None,
    challenge_id: str | None = None,
) -> IssuedChallenge:
    s = _rp(settings)
    row = WebAuthnChallenge(
        purpose=purpose,
        user_id=user_id,
        challenge=challenge,
        nonce=nonce,
        payment_id=payment[0] if payment else None,
        payment_version=payment[1] if payment else None,
        digest=payment[2] if payment else None,
        expires_at=ctx.now() + CHALLENGE_TTL,
    )
    if challenge_id:
        row.id = challenge_id
    ctx.session.add(row)
    ctx.session.flush()
    allow: list[PublicKeyCredentialDescriptor] | None = None
    if user_id:
        ids = ctx.session.execute(
            select(WebAuthnCredential.id).where(
                WebAuthnCredential.user_id == user_id, WebAuthnCredential.revoked_at.is_(None)
            )
        ).scalars()
        allow = [PublicKeyCredentialDescriptor(id=_b64d(c)) for c in ids]
    opts = generate_authentication_options(
        rp_id=s.webauthn_rp_id,
        challenge=challenge,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return IssuedChallenge(row.id, options_to_json(opts))


@dataclass(frozen=True)
class VerifiedAssertion:
    user: User
    credential_id: str
    challenge: WebAuthnChallenge


def finish_assertion(
    ctx: Ctx,
    challenge_id: str,
    purpose: str,
    credential: dict[str, Any] | str,
    settings: Settings | None = None,
) -> VerifiedAssertion:
    s = _rp(settings)
    ch = _consume_challenge(ctx, challenge_id, purpose)
    cred_id = credential.get("id") if isinstance(credential, dict) else None
    if cred_id is None and isinstance(credential, str):
        import json

        cred_id = json.loads(credential).get("id")
    if not isinstance(cred_id, str):
        raise ForbiddenError("WEBAUTHN_INVALID", "credential id missing")
    stored = ctx.session.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.id == cred_id).with_for_update()
    ).scalar_one_or_none()
    if stored is None or stored.revoked_at is not None:
        raise ForbiddenError("WEBAUTHN_INVALID", "unknown or revoked credential")
    if ch.user_id is not None and stored.user_id != ch.user_id:
        raise ForbiddenError("WEBAUTHN_INVALID", "credential belongs to another user")
    try:
        v = verify_authentication_response(
            credential=credential,
            expected_challenge=ch.challenge,
            expected_rp_id=s.webauthn_rp_id,
            expected_origin=s.webauthn_origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as exc:
        raise ForbiddenError("WEBAUTHN_INVALID", f"assertion rejected: {exc}") from exc
    stored.sign_count = v.new_sign_count
    user = ctx.session.get(User, stored.user_id)
    if user is None:
        raise NotFoundError("NOT_FOUND", "credential owner missing")
    if not user.active:
        raise ForbiddenError("APPROVER_NOT_AUTHORIZED", "user inactive")
    return VerifiedAssertion(user, stored.id, ch)


def assert_not_reused(ch: WebAuthnChallenge) -> None:
    if ch.used_at is None:
        raise ConflictError("CHALLENGE_INVALID", "challenge not consumed")
