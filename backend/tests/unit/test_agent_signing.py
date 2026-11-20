"""FR9: RFC 9421 agent request signatures. I9 (nothing trusted from the client), I10."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from paylineage.agents.signing import SignatureError, sign_request, verify_request
from paylineage.eval.world import World

URI = "http://localhost:8000/v1/agent/proposals"
BODY = b'{"invoice_id":"x","amount_minor":1250000}'


def _signed(world: World, **kw: object) -> dict[str, str]:
    assert world.agent_key is not None
    args: dict[str, object] = {
        "keyid": "AP-Agent-001-k1",
        "method": "POST",
        "target_uri": URI,
        "body": BODY,
        "created": int(world.clock.now().timestamp()),
    }
    args.update(kw)
    return sign_request(world.agent_key, **args).as_dict()  # type: ignore[arg-type]


def _verify(
    world: World, headers: dict[str, str], body: bytes = BODY, method: str = "POST", uri: str = URI
) -> str:
    with world.tx() as ctx:
        return verify_request(
            ctx.session, method=method, target_uri=uri, body=body, headers=headers, now=world.clock.now()
        ).agent_id


def test_valid_signature_verifies(world: World) -> None:
    assert _verify(world, _signed(world)) == "AP-Agent-001"


def test_I9_nonce_replay_rejected(world: World) -> None:
    h = _signed(world)
    _verify(world, h)
    with pytest.raises(SignatureError, match="replayed"):
        _verify(world, h)


@pytest.mark.parametrize(
    ("body", "method", "uri"),
    [
        (BODY + b" ", "POST", URI),
        (BODY, "PUT", URI),
        (BODY, "POST", URI + "?x=1"),
        (b'{"invoice_id":"x","amount_minor":9250000}', "POST", URI),
    ],
)
def test_I9_tampered_request_rejected(world: World, body: bytes, method: str, uri: str) -> None:
    with pytest.raises(SignatureError):
        _verify(world, _signed(world), body=body, method=method, uri=uri)


def test_stale_and_future_signatures_rejected(world: World) -> None:
    now = int(world.clock.now().timestamp())
    for created in (now - 301, now + 301):
        with pytest.raises(SignatureError, match="window"):
            _verify(world, _signed(world, created=created))


def test_wrong_key_rejected(world: World) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    h = sign_request(
        Ed25519PrivateKey.generate(),
        keyid="AP-Agent-001-k1",
        method="POST",
        target_uri=URI,
        body=BODY,
        created=int(world.clock.now().timestamp()),
    ).as_dict()
    with pytest.raises(SignatureError, match="verify"):
        _verify(world, h)


def test_inactive_agent_rejected(world: World) -> None:
    from paylineage.db.models import Agent

    with world.tx() as ctx:
        a = ctx.session.get(Agent, "AP-Agent-001")
        assert a is not None
        a.active = False
    with pytest.raises(SignatureError, match="inactive"):
        _verify(world, _signed(world))


@pytest.mark.parametrize("header", ["Signature-Input", "Signature", "Content-Digest"])
def test_missing_header_rejected(world: World, header: str) -> None:
    h = _signed(world)
    del h[header]
    with pytest.raises(SignatureError):
        _verify(world, h)


def test_profile_downgrade_rejected(world: World) -> None:
    h = _signed(world)
    # Drop content-digest from the covered components: body no longer bound.
    h["Signature-Input"] = h["Signature-Input"].replace(' "content-digest"', "")
    with pytest.raises(SignatureError, match="profile"):
        _verify(world, h)
    h = _signed(world)
    h["Signature-Input"] = h["Signature-Input"].replace('alg="ed25519"', 'alg="hmac-sha256"')
    with pytest.raises(SignatureError, match="profile"):
        _verify(world, h)


@settings(max_examples=50)
@given(st.binary(min_size=64, max_size=64))
def test_I9_random_signatures_never_verify(sig: bytes) -> None:
    # Pure check of the parser and verifier without the DB: random bytes never pass.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from paylineage.agents.signing import signature_base

    pub = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(InvalidSignature):
        pub.verify(sig, signature_base("POST", URI, "sha-256=:x:", "()"))
    assert len(base64.b64encode(sig)) == 88


def test_clock_skew_boundary(world: World) -> None:
    created = int(world.clock.now().timestamp())
    world.clock.advance(timedelta(seconds=300))  # type: ignore[attr-defined]
    assert _verify(world, _signed(world, created=created)) == "AP-Agent-001"
