"""Supplier onboarding and bank change state machine (T0.8, docs/STATE_MACHINES.md).

Pure transition table. Any (state, action) pair not listed is rejected. The
policy (onboarding.rego) separately decides whether this actor may act now,
with this evidence; both must agree before the database changes.

Bank changes run as a case on the same machine, starting in `verifying`
(STATE_MACHINES: "Verified to Verifying: anyone recording a claimed bank
change"). The supplier itself stays verified so the old account stays payable
per policy data unless it was reported compromised or closed (ADR-014).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from paylineage.domain.enums import RequestKind


class OnbState(StrEnum):
    REQUESTED = "requested"
    UNVERIFIED = "unverified"
    VERIFYING = "verifying"
    STEWARD_REVIEW = "steward_review"
    VERIFIED = "verified"
    REJECTED = "rejected"


class OnbAction(StrEnum):
    REQUEST_SUPPLIER = "request_supplier"
    OPEN_RECORD = "open_record"
    RECORD_BANK_CHANGE = "record_bank_change"
    ASSIGN_VERIFIER = "assign_verifier"
    RECORD_VERIFICATION = "record_verification"
    STEWARD_APPROVE = "steward_approve"
    REJECT = "reject"


TERMINAL = frozenset({OnbState.VERIFIED, OnbState.REJECTED})

# (kind, from_state, action) -> to_state. `None` as from_state means "creates the case".
TRANSITIONS: dict[tuple[RequestKind, OnbState | None, OnbAction], OnbState] = {
    (RequestKind.NEW_SUPPLIER, None, OnbAction.REQUEST_SUPPLIER): OnbState.REQUESTED,
    (RequestKind.NEW_SUPPLIER, OnbState.REQUESTED, OnbAction.OPEN_RECORD): OnbState.UNVERIFIED,
    (RequestKind.NEW_SUPPLIER, OnbState.UNVERIFIED, OnbAction.ASSIGN_VERIFIER): OnbState.VERIFYING,
    (RequestKind.BANK_CHANGE, None, OnbAction.RECORD_BANK_CHANGE): OnbState.VERIFYING,
}
for _kind in RequestKind:
    TRANSITIONS[(_kind, OnbState.VERIFYING, OnbAction.RECORD_VERIFICATION)] = OnbState.STEWARD_REVIEW
    TRANSITIONS[(_kind, OnbState.STEWARD_REVIEW, OnbAction.STEWARD_APPROVE)] = OnbState.VERIFIED
    TRANSITIONS[(_kind, OnbState.VERIFYING, OnbAction.REJECT)] = OnbState.REJECTED
    TRANSITIONS[(_kind, OnbState.STEWARD_REVIEW, OnbAction.REJECT)] = OnbState.REJECTED

# Attribute updates that do not change state: assigning the verifier of a bank
# change case, which starts in `verifying` with nobody assigned.
ATTRIBUTE_UPDATES: frozenset[tuple[RequestKind, OnbState, OnbAction]] = frozenset(
    {(RequestKind.BANK_CHANGE, OnbState.VERIFYING, OnbAction.ASSIGN_VERIFIER)}
)


class IllegalTransitionError(Exception):
    def __init__(self, kind: RequestKind, state: OnbState | None, action: OnbAction) -> None:
        super().__init__(f"{kind}: {action} not allowed from {state}")
        self.kind, self.state, self.action = kind, state, action


@dataclass(frozen=True)
class Case:
    """The SoD relevant facts of one case."""

    kind: RequestKind
    state: OnbState
    requester_id: str
    verifier_id: str | None = None
    steward_id: str | None = None


def next_state(
    kind: RequestKind, state: OnbState | None, action: OnbAction, *, verifier_assigned: bool
) -> OnbState:
    if state is not None and (kind, state, action) in ATTRIBUTE_UPDATES:
        if verifier_assigned:
            raise IllegalTransitionError(kind, state, action)
        return state
    to = TRANSITIONS.get((kind, state, action))
    if to is None:
        raise IllegalTransitionError(kind, state, action)
    if action is OnbAction.RECORD_VERIFICATION and not verifier_assigned:
        raise IllegalTransitionError(kind, state, action)
    return to


def distinct_people(case: Case) -> bool:
    """I7: requester, verifier and steward are three different people once verified."""
    people = [case.requester_id, case.verifier_id, case.steward_id]
    if any(p is None for p in people):
        return False
    return len(set(people)) == 3
