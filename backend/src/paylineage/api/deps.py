"""API plumbing: transactions, sessions, actors, origin checks, rate limits."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from paylineage.db.base import get_sessionmaker
from paylineage.db.models import User
from paylineage.domain.clock import Clock, SystemClock
from paylineage.domain.context import Actor, Ctx
from paylineage.policy.engine import get_engine
from paylineage.settings import Settings, get_settings

SESSION_COOKIE = "pl_session"
SESSION_MAX_AGE = 8 * 3600
_clock: Clock = SystemClock()


def set_clock(clock: Clock) -> None:
    """Tests only."""
    global _clock  # noqa: PLW0603
    _clock = clock


def get_clock() -> Clock:
    return _clock


def get_ctx() -> Iterator[Ctx]:
    session: Session = get_sessionmaker()()
    try:
        with session.begin():
            yield Ctx(session, _clock, get_engine())
    finally:
        session.close()


def serializer(s: Settings | None = None) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer((s or get_settings()).session_secret.get_secret_value(), salt="pl-session")


def session_user_id(request: Request) -> str | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = serializer().loads(raw, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    uid = data.get("uid") if isinstance(data, dict) else None
    return uid if isinstance(uid, str) else None


@dataclass(frozen=True)
class Me:
    user: User
    actor: Actor


def current_user(request: Request, ctx: Ctx = Depends(get_ctx)) -> Me:
    uid = session_user_id(request)
    if uid is None:
        raise HTTPException(401, {"code": "UNAUTHENTICATED", "message": "sign in first"})
    u = ctx.session.get(User, uid)
    if u is None or not u.active:
        raise HTTPException(401, {"code": "UNAUTHENTICATED", "message": "account inactive"})
    return Me(u, Actor(u.id, "user", frozenset(u.roles), u.active))


def require_role(me: Me, *roles: str) -> None:
    if not any(me.actor.has(r) for r in roles):
        raise HTTPException(403, {"code": "ROLE_REQUIRED", "message": f"needs one of {', '.join(roles)}"})


class RateLimiter:
    """Token bucket per key (agent id, user id or client address)."""

    def __init__(self, rate_per_s: float, burst: int) -> None:
        self.rate, self.burst = rate_per_s, burst
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1, now)
            return True


LIMITER = RateLimiter(rate_per_s=5.0, burst=30)


def check_origin(request: Request) -> None:
    """State changing browser requests must come from our own origin (with SameSite=Strict cookies)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin")
    allowed = {get_settings().webauthn_origin, "http://localhost:3000", "http://127.0.0.1:3000"}
    if origin is not None and origin not in allowed:
        raise HTTPException(403, {"code": "ORIGIN_REJECTED", "message": "cross origin request"})
