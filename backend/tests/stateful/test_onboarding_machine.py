"""T0.8: onboarding state machine as a transition table + Hypothesis RuleBasedStateMachine (I7)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from paylineage.domain.enums import RequestKind
from paylineage.onboarding.machine import (
    TRANSITIONS,
    Case,
    IllegalTransitionError,
    OnbAction,
    OnbState,
    distinct_people,
    next_state,
)
from paylineage.policy.engine import build_engine

ENGINE = build_engine()
NOW = 1_800_000_000_000
PEOPLE = ["p1", "p2", "p3", "p4"]
ROLE_SETS = [["ap_specialist"], ["verifier"], ["steward"], ["verifier", "steward"], ["analyst"]]


def policy_allows(
    action: OnbAction,
    kind: RequestKind,
    actor: str,
    roles: list[str],
    case: dict[str, Any],
    assignee: str | None,
    evidence_ok: bool,
) -> bool:
    verification = None
    if action in (OnbAction.RECORD_VERIFICATION, OnbAction.STEWARD_APPROVE):
        verification = {
            "method": "callback_on_file",
            "contact_source": "on_file" if evidence_ok else "invoice",
            "contact_recorded_at_ms": NOW - 10_000,
            "request_created_at_ms": NOW - 1_000,
            "registry_match": True,
            "bank_confirmed": True,
        }
    pol_action = action.value if action is not OnbAction.OPEN_RECORD else "request_supplier"
    d = ENGINE.evaluate(
        {
            "schema_version": "1",
            "request_kind": "onboarding",
            "now_ms": NOW,
            "onboarding": {
                "action": pol_action,
                "kind": kind.value,
                "actor_id": actor,
                "actor_roles": roles,
                "supplier_id": "sup-1",
                "requester_id": case.get("requester"),
                "verifier_id": case.get("verifier"),
                "assignee_id": assignee,
                "verification": verification,
            },
        }
    )
    return d.decision == "allow"


def test_illegal_transitions_rejected() -> None:
    for kind in RequestKind:
        for state in [None, *OnbState]:
            for action in OnbAction:
                key = (kind, state, action)
                if key in TRANSITIONS:
                    continue
                if (
                    action is OnbAction.ASSIGN_VERIFIER
                    and kind is RequestKind.BANK_CHANGE
                    and state is OnbState.VERIFYING
                ):
                    continue  # attribute update, tested below
                with pytest.raises(IllegalTransitionError):
                    next_state(kind, state, action, verifier_assigned=True)


def test_terminal_states_have_no_exits() -> None:
    for _kind, state, _action in TRANSITIONS:
        assert state not in (OnbState.VERIFIED, OnbState.REJECTED)


def test_bank_change_assignment_is_attribute_update_once() -> None:
    k = RequestKind.BANK_CHANGE
    assert (
        next_state(k, OnbState.VERIFYING, OnbAction.ASSIGN_VERIFIER, verifier_assigned=False)
        is OnbState.VERIFYING
    )
    with pytest.raises(IllegalTransitionError):
        next_state(k, OnbState.VERIFYING, OnbAction.ASSIGN_VERIFIER, verifier_assigned=True)


def test_verification_requires_assigned_verifier() -> None:
    with pytest.raises(IllegalTransitionError):
        next_state(
            RequestKind.NEW_SUPPLIER,
            OnbState.VERIFYING,
            OnbAction.RECORD_VERIFICATION,
            verifier_assigned=False,
        )


class OnboardingMachine(RuleBasedStateMachine):
    """Random actors with random roles try random actions. Model = machine + policy."""

    def __init__(self) -> None:
        super().__init__()
        self.case: dict[str, Any] = {}
        self.kind = RequestKind.NEW_SUPPLIER
        self.state: OnbState | None = None
        self.history: list[tuple[str, str]] = []

    @rule(kind=st.sampled_from(list(RequestKind)), actor=st.sampled_from(PEOPLE))
    def start(self, kind: RequestKind, actor: str) -> None:
        if self.state is not None:
            return
        action = (
            OnbAction.REQUEST_SUPPLIER if kind is RequestKind.NEW_SUPPLIER else OnbAction.RECORD_BANK_CHANGE
        )
        self.kind = kind
        self.state = next_state(kind, None, action, verifier_assigned=False)
        self.case = {"requester": actor}

    @rule(
        action=st.sampled_from(list(OnbAction)),
        actor=st.sampled_from(PEOPLE),
        roles=st.sampled_from(ROLE_SETS),
        assignee=st.sampled_from(PEOPLE),
        evidence_ok=st.booleans(),
    )
    def act(self, action: OnbAction, actor: str, roles: list[str], assignee: str, evidence_ok: bool) -> None:
        if self.state is None:
            return
        try:
            to = next_state(self.kind, self.state, action, verifier_assigned="verifier" in self.case)
        except IllegalTransitionError:
            return
        if action is not OnbAction.OPEN_RECORD and not policy_allows(
            action,
            self.kind,
            actor,
            roles,
            self.case,
            assignee if action is OnbAction.ASSIGN_VERIFIER else None,
            evidence_ok,
        ):
            return
        if action is OnbAction.ASSIGN_VERIFIER:
            self.case["verifier"] = assignee
            self.case["assigned_by"] = actor
        if action is OnbAction.STEWARD_APPROVE:
            self.case["steward"] = actor
        if action is OnbAction.RECORD_VERIFICATION:
            self.case["verified_by"] = actor
            self.case["evidence_ok"] = evidence_ok
        self.history.append((action.value, actor))
        self.state = to

    @invariant()
    def test_I7_verified_means_three_distinct_people(self) -> None:
        if self.state is OnbState.VERIFIED:
            case = Case(
                self.kind,
                self.state,
                self.case["requester"],
                self.case.get("verifier"),
                self.case.get("steward"),
            )
            assert distinct_people(case), self.case
            assert self.case.get("verified_by") == self.case.get("verifier")
            assert self.case.get("evidence_ok") is True

    @invariant()
    def test_I7_assigner_is_not_verifier_or_requester(self) -> None:
        if "verifier" in self.case:
            assert self.case["verifier"] != self.case["requester"]
            assert self.case["verifier"] != self.case.get("assigned_by")


TestOnboardingMachine = OnboardingMachine.TestCase
