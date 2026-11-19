"""Payment state machine (docs/STATE_MACHINES.md). Explicit table; anything else is rejected."""

from __future__ import annotations

from enum import StrEnum

from paylineage.domain.enums import PaymentState as S


class PayEvent(StrEnum):
    EVALUATE = "evaluate"  # Proposed -> Evaluated (signature valid, mandate loaded)
    DENY = "deny"  # Evaluated -> Denied ; Held -> Denied
    HOLD = "hold"  # Evaluated -> Held
    READY = (
        "ready"  # Evaluated -> AwaitingApproval ; Held -> AwaitingApproval (after out of band verification)
    )
    APPROVE = "approve"  # AwaitingApproval -> Approved
    ISSUE_PERMIT = "issue_permit"  # Approved -> PermitIssued
    EXECUTE = "execute"  # PermitIssued -> Executed
    MATERIAL_CHANGE = "material_change"  # AwaitingApproval, Approved -> Evaluated (version += 1)
    EXPIRE = "expire"  # Approved -> Expired


TERMINAL = frozenset({S.DENIED, S.EXPIRED, S.EXECUTED})

TRANSITIONS: dict[tuple[S, PayEvent], S] = {
    (S.PROPOSED, PayEvent.EVALUATE): S.EVALUATED,
    (S.EVALUATED, PayEvent.DENY): S.DENIED,
    (S.EVALUATED, PayEvent.HOLD): S.HELD,
    (S.EVALUATED, PayEvent.READY): S.AWAITING_APPROVAL,
    (S.HELD, PayEvent.READY): S.AWAITING_APPROVAL,
    (S.HELD, PayEvent.DENY): S.DENIED,
    (S.AWAITING_APPROVAL, PayEvent.APPROVE): S.APPROVED,
    (S.APPROVED, PayEvent.ISSUE_PERMIT): S.PERMIT_ISSUED,
    (S.PERMIT_ISSUED, PayEvent.EXECUTE): S.EXECUTED,
    (S.AWAITING_APPROVAL, PayEvent.MATERIAL_CHANGE): S.EVALUATED,
    (S.APPROVED, PayEvent.MATERIAL_CHANGE): S.EVALUATED,
    (S.APPROVED, PayEvent.EXPIRE): S.EXPIRED,
}


class IllegalPaymentTransitionError(Exception):
    def __init__(self, state: S, event: PayEvent) -> None:
        super().__init__(f"{event} not allowed from {state}")
        self.state, self.event = state, event


def next_state(state: S, event: PayEvent) -> S:
    to = TRANSITIONS.get((state, event))
    if to is None:
        raise IllegalPaymentTransitionError(state, event)
    return to


def allowed_events(state: S) -> list[PayEvent]:
    return [e for (s, e) in TRANSITIONS if s == state]
