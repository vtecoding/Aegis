"""Hypothesis invariants for pipeline policy admission wiring."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyDecision, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline

_VALID_COMMANDS = ("move", "stop", "inspect", "wait")


def _context() -> ExecutionContext:
    return ExecutionContext("policy-invariant-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(command: str, priority: int, context: ExecutionContext) -> RawIntent:
    parameters: dict[str, object] = {}
    if command == "move":
        parameters = {"target": {"x": 0, "y": 0, "metadata": {"force_allow": True}}}
    elif command == "wait":
        parameters = {"duration_ms": 200}
    elif command == "inspect":
        parameters = {"target": "front_sensor"}
    return RawIntent(command, parameters, "policy-invariant", priority, context)


def _capability(velocity_mps: object = 0.2) -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def _policy(constraint: Constraint, policy_id: str = "policy-invariant") -> Policy:
    return Policy(
        policy_id,
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", [constraint])],
    )


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=30)
def test_invariant_enforce_missing_policy_never_approves(command: str, priority: int) -> None:
    context = _context()
    result = run_pipeline(
        _intent(command, priority, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            capability=_capability(),
        ),
    )

    assert result.outcome is not PipelineOutcome.ALLOWED
    assert result.gate_decision is None


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=30)
def test_invariant_enforce_missing_capability_never_approves(command: str, priority: int) -> None:
    context = _context()
    result = run_pipeline(
        _intent(command, priority, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(Constraint("max_velocity", {"max_mps": 0.5})),
        ),
    )

    assert result.outcome is not PipelineOutcome.ALLOWED
    assert result.gate_decision is None


@given(
    st.sampled_from(_VALID_COMMANDS),
    st.floats(min_value=0.2, max_value=2.0, allow_nan=False, allow_infinity=False),
)
@settings(max_examples=30)
def test_invariant_policy_block_dominates_gate(command: str, velocity_mps: float) -> None:
    context = _context()
    snapshot = fresh_world_snapshot()
    result = run_pipeline(
        _intent(command, 5, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(Constraint("max_velocity", {"max_mps": 0.1})),
            capability=_capability(velocity_mps),
            world_snapshot=snapshot,
            context=fresh_policy_context(),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is not PipelineOutcome.ALLOWED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


@given(
    st.sampled_from(_VALID_COMMANDS),
    st.floats(min_value=0.2, max_value=2.0, allow_nan=False, allow_infinity=False),
)
@settings(max_examples=30)
def test_invariant_policy_review_dominates_gate(command: str, velocity_mps: float) -> None:
    context = _context()
    snapshot = fresh_world_snapshot()
    result = run_pipeline(
        _intent(command, 5, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(Constraint("max_velocity", {"max_mps": 0.1}, required=False)),
            capability=_capability(velocity_mps),
            world_snapshot=snapshot,
            context=fresh_policy_context(),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is not PipelineOutcome.ALLOWED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.REQUIRE_REVIEW


def test_invariant_disabled_mode_never_creates_policy_allow_result() -> None:
    context = _context()
    result = run_pipeline(_intent("move", 5, context), context)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.mode is PolicyAdmissionMode.DISABLED
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.admission_allowed is False


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=30)
def test_invariant_safety_case_binds_actual_audited_plan(command: str, priority: int) -> None:
    context = _context()
    snapshot = fresh_world_snapshot()
    result = run_pipeline(
        _intent(command, priority, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(Constraint("max_velocity", {"max_mps": 0.5})),
            capability=_capability(0.2),
            world_snapshot=snapshot,
            context=fresh_policy_context(),
            evidence={"audited_plan_id": "forged"},
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.audited_plan is not None
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.audited_plan_id == result.audited_plan.audit_id


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=30)
def test_invariant_policy_admission_is_deterministic(command: str, priority: int) -> None:
    context = _context()
    intent = _intent(command, priority, context)
    snapshot = fresh_world_snapshot()
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(Constraint("max_velocity", {"max_mps": 0.5})),
        capability=_capability(0.2),
        world_snapshot=snapshot,
        context=fresh_policy_context({"authorisations": ["operator"]}),
    )

    result_a = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )
    result_b = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result_a == result_b


def test_invariant_source_context_mutation_cannot_change_constructed_admission() -> None:
    context = _context()
    source_context = {"authorisations": ["operator"]}
    snapshot = fresh_world_snapshot()
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(Constraint("requires_authorisation", {"authorisation": "admin"})),
        capability=_capability(0.2),
        world_snapshot=snapshot,
        context=fresh_policy_context(source_context),
    )
    result_a = run_pipeline(
        _intent("move", 5, context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    source_context["authorisations"].append("admin")
    result_b = run_pipeline(
        _intent("move", 5, context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result_a == result_b
    assert result_b.outcome is PipelineOutcome.BLOCKED
