"""Hypothesis invariants for the pure Policy-v1 evaluator."""

from copy import deepcopy

from hypothesis import given
from hypothesis import strategies as st

from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.policy.aegis_evaluator import evaluate_policy


def policy_for(constraints: tuple[Constraint, ...]) -> Policy:
    """Return a generated policy for evaluator invariants."""
    return Policy("policy-1", "v1", [PolicyRule("rule-1", "locomotion.translation", constraints)])


def move_capability(velocity_mps: object = 0.2) -> Capability:
    """Return a generated movement capability."""
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


@given(
    velocity_mps=st.floats(min_value=0.0, max_value=2.0, allow_nan=False, allow_infinity=False),
    max_mps=st.floats(min_value=0.0, max_value=2.0, allow_nan=False, allow_infinity=False),
)
def test_invariant_policy_evaluator_is_deterministic(
    velocity_mps: float,
    max_mps: float,
) -> None:
    """Repeated evaluator calls with identical inputs return equal results."""
    test_policy = policy_for((Constraint("max_velocity", {"max_mps": max_mps}),))
    capability = move_capability(velocity_mps)

    first = evaluate_policy(policy=test_policy, capability=capability)
    second = evaluate_policy(policy=test_policy, capability=capability)

    assert first == second


@given(
    unknown_type=st.text(min_size=1, max_size=20).filter(
        lambda value: value.strip() != "" and value.strip() != "max_velocity"
    )
)
def test_invariant_unknown_constraint_never_allows(unknown_type: str) -> None:
    """Generated unknown constraint types fail closed and never ALLOW."""
    test_policy = policy_for((Constraint(unknown_type),))

    result = evaluate_policy(policy=test_policy, capability=move_capability())

    assert result.decision is not PolicyDecision.ALLOW


def test_invariant_no_matching_rule_never_allows() -> None:
    """Nonmatching capabilities never produce ALLOW."""
    test_policy = Policy(
        "policy-1",
        "v1",
        [PolicyRule("rule-1", "inspection.observe", [Constraint("requires_world_snapshot")])],
    )

    result = evaluate_policy(policy=test_policy, capability=Capability("locomotion.translation"))

    assert result.decision is not PolicyDecision.ALLOW


@given(
    confidence=st.floats(min_value=0.0, max_value=0.79, allow_nan=False, allow_infinity=False),
    threshold=st.just(0.8),
)
def test_invariant_confidence_below_required_min_never_allows(
    confidence: float,
    threshold: float,
) -> None:
    """Snapshot confidence below the required threshold never allows."""
    result = evaluate_policy(
        policy=policy_for((Constraint("min_sensor_confidence", {"min_confidence": threshold}),)),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 0, 10, "fixture", confidence),
    )

    assert result.decision is PolicyDecision.BLOCK


@given(confidence=st.floats(min_value=0.8, max_value=1.0, allow_nan=False, allow_infinity=False))
def test_invariant_confidence_at_or_above_required_min_may_allow(confidence: float) -> None:
    """Confidence at or above threshold can allow when all constraints pass."""
    result = evaluate_policy(
        policy=policy_for((Constraint("min_sensor_confidence", {"min_confidence": 0.8}),)),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 0, 10, "fixture", confidence),
    )

    assert result.decision is PolicyDecision.ALLOW


@given(
    requested_at_ms=st.one_of(st.integers(max_value=-1), st.integers(min_value=11, max_value=100))
)
def test_invariant_snapshot_time_outside_window_never_allows(requested_at_ms: int) -> None:
    """Request time outside captured/expires bounds never allows."""
    result = evaluate_policy(
        policy=policy_for((Constraint("snapshot_freshness"),)),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 0, 10, "fixture", 1.0),
        context={"requested_at_ms": requested_at_ms},
    )

    assert result.decision is PolicyDecision.BLOCK


@given(requested_at_ms=st.integers(min_value=0, max_value=10))
def test_invariant_snapshot_time_inside_window_may_allow(requested_at_ms: int) -> None:
    """Request time inside captured/expires bounds can allow."""
    result = evaluate_policy(
        policy=policy_for((Constraint("snapshot_freshness"),)),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 0, 10, "fixture", 1.0),
        context={"requested_at_ms": requested_at_ms},
    )

    assert result.decision is PolicyDecision.ALLOW


@given(velocity_mps=st.floats(min_value=0.51, max_value=5.0, allow_nan=False, allow_infinity=False))
def test_invariant_velocity_above_limit_never_allows(velocity_mps: float) -> None:
    """Velocity above max_mps never allows."""
    result = evaluate_policy(
        policy=policy_for((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(velocity_mps),
    )

    assert result.decision is PolicyDecision.BLOCK


@given(velocity_mps=st.floats(min_value=0.0, max_value=0.5, allow_nan=False, allow_infinity=False))
def test_invariant_velocity_at_or_below_limit_may_allow(velocity_mps: float) -> None:
    """Velocity at or below max_mps can allow when all constraints pass."""
    result = evaluate_policy(
        policy=policy_for((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(velocity_mps),
    )

    assert result.decision is PolicyDecision.ALLOW


def test_invariant_failed_required_constraint_dominates_optional_passes() -> None:
    """Any failed required constraint produces BLOCK despite optional passes."""
    result = evaluate_policy(
        policy=policy_for(
            (
                Constraint("max_velocity", {"max_mps": 0.1}),
                Constraint("requires_world_snapshot", required=False),
            )
        ),
        capability=move_capability(0.2),
        world_snapshot=WorldSnapshotStub("snapshot-1", 0, 10, "fixture", 1.0),
    )

    assert result.decision is PolicyDecision.BLOCK


def test_invariant_failed_optional_constraint_is_visible() -> None:
    """Failed optional constraints appear in failed_constraints and reasons."""
    result = evaluate_policy(
        policy=policy_for((Constraint("max_velocity", {"max_mps": 0.1}, required=False),)),
        capability=move_capability(0.2),
    )

    assert result.decision is PolicyDecision.REQUIRE_REVIEW
    assert result.failed_constraints == ("rule-1:0:max_velocity",)
    assert "VELOCITY_LIMIT_EXCEEDED" in result.reasons


def test_invariant_any_matching_rule_required_failure_blocks() -> None:
    """Multiple matching rules are aggregated strictly across all required failures."""
    test_policy = Policy(
        "policy-1",
        "v1",
        [
            PolicyRule(
                "rule-pass",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 1.0})],
            ),
            PolicyRule(
                "rule-fail",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 0.1})],
            ),
        ],
    )

    result = evaluate_policy(policy=test_policy, capability=move_capability(0.2))

    assert result.decision is PolicyDecision.BLOCK


@given(authorisations=st.lists(st.text(min_size=1, max_size=10), max_size=3))
def test_invariant_caller_context_mutation_cannot_change_prior_results(
    authorisations: list[str],
) -> None:
    """Mutating caller-owned context after evaluation cannot change prior results."""
    context = {"authorisations": deepcopy(authorisations)}
    test_policy = policy_for((Constraint("requires_authorisation", {"authorisation": "operator"}),))

    first = evaluate_policy(policy=test_policy, capability=move_capability(), context=context)
    context["authorisations"].append("operator")
    second = evaluate_policy(
        policy=test_policy,
        capability=move_capability(),
        context={"authorisations": deepcopy(authorisations)},
    )

    assert first == second
