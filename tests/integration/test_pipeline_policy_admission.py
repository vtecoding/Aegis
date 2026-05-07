"""Integration test for policy-enforced pipeline admission."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
)
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.errors import PolicyAdmissionIntegrityError
from aegis.pipeline import run_pipeline


def _context(request_id: str = "policy-integration-001") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _capability(velocity_mps: object = 0.2) -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def _policy(constraint: Constraint, policy_id: str = "policy-integration") -> Policy:
    return Policy(
        policy_id,
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", [constraint])],
    )


def _admission(policy: Policy, capability: Capability | None = None) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=capability or _capability(),
        world_snapshot=fresh_world_snapshot(),
        context=fresh_policy_context(),
    )


def test_policy_enforced_pipeline_with_world_snapshot_allows_then_gates() -> None:
    context = ExecutionContext(
        "policy-integration-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1"
    )
    intent = RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)
    policy = Policy(
        "policy-integration",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [
                    Constraint("requires_world_snapshot"),
                    Constraint("snapshot_freshness"),
                    Constraint("min_sensor_confidence", {"min_confidence": 0.8}),
                    Constraint("max_velocity", {"max_mps": 0.5}),
                ],
            )
        ],
    )
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=fresh_world_snapshot("snapshot-1", confidence=0.9),
        context=fresh_policy_context(),
    )

    result = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ALLOW
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.world_snapshot_id == "snapshot-1"


def test_policy_block_returns_blocked_without_gate() -> None:
    context = _context("policy-integration-block")
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(_policy(Constraint("max_velocity", {"max_mps": 0.1}))),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


def test_policy_require_review_returns_non_approved_without_gate() -> None:
    context = _context("policy-integration-review")
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(
            _policy(Constraint("max_velocity", {"max_mps": 0.1}, required=False))
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.REQUIRE_REVIEW


def test_policy_invalid_returns_invalid_without_gate() -> None:
    context = _context("policy-integration-invalid")
    invalid_result = PolicyEvaluationResult(
        PolicyDecision.INVALID,
        "policy-integration",
        [],
        [],
        [],
        ["POLICY_EVALUATION_CONTEXT_INVALID"],
    )

    with patch("aegis.pipeline.orchestrator.evaluate_policy", return_value=invalid_result):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(_policy(Constraint("max_velocity", {"max_mps": 1.0}))),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    assert result.outcome is PipelineOutcome.INVALID
    assert result.gate_decision is None


def test_policy_evaluator_exception_returns_error_without_approval() -> None:
    context = _context("policy-integration-evaluator-error")
    with patch("aegis.pipeline.orchestrator.evaluate_policy", side_effect=RuntimeError("boom")):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(_policy(Constraint("max_velocity", {"max_mps": 1.0}))),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False


def test_safety_case_exception_returns_error_without_approval() -> None:
    context = _context("policy-integration-safety-case-error")
    with patch("aegis.pipeline.orchestrator.build_safety_case", side_effect=RuntimeError("boom")):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(_policy(Constraint("max_velocity", {"max_mps": 1.0}))),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False


def test_admission_integrity_exception_returns_error_without_approval() -> None:
    context = _context("policy-integration-integrity-error")
    error = PolicyAdmissionIntegrityError("forced", "policy", {"reason": "test"})
    with patch("aegis.pipeline.orchestrator.assert_policy_admission_integrity", side_effect=error):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(_policy(Constraint("max_velocity", {"max_mps": 1.0}))),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False


def test_disabled_policy_mode_is_non_approved_and_not_policy_backed() -> None:
    context = _context("policy-integration-disabled")
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.safety_case is None
    assert result.policy_admission.admission_allowed is False
