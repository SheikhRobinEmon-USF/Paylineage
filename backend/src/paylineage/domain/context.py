"""Service context, actors and domain errors (errors map to explicit reason codes)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy.orm import Session

from paylineage.domain.clock import Clock
from paylineage.policy.engine import PolicyDecision, PolicyEngine


@dataclass(frozen=True)
class Actor:
    id: str
    kind: Literal["user", "agent", "system"]
    roles: frozenset[str] = field(default_factory=frozenset)
    active: bool = True

    def has(self, role: str) -> bool:
        return role in self.roles


SYSTEM = Actor("system", "system", frozenset({"system"}))


@dataclass
class Ctx:
    session: Session
    clock: Clock
    engine: PolicyEngine

    def now(self) -> datetime:
        return self.clock.now()


class DomainError(Exception):
    """A refused request with a reason code. Never swallowed in authorization code."""

    status = 409

    def __init__(self, code: str, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


class NotFoundError(DomainError):
    status = 404


class ForbiddenError(DomainError):
    status = 403


class ConflictError(DomainError):
    status = 409


class PolicyRefusedError(DomainError):
    status = 403

    def __init__(self, decision: PolicyDecision, message: str) -> None:
        super().__init__(
            decision.reasons[0] if decision.reasons else "POLICY_UNDEFINED",
            message,
            detail=decision.as_dict(),
        )
        self.decision = decision
