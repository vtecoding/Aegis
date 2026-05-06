"""Pipeline tests for policy admission wiring after audit and before gate."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

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
from aegis.pipeline import run_pipeline


def _context() -> ExecutionContext:
    return ExecutionContext("policy-wire-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _capability(velocity_mps: object = 0.2) -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def _policy(constraint: Constraint, policy_id: str = "policy-1") -> Policy:
    return Policy(
        policy_id,
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", [constraint])],
    )


def _allow_policy() -> Policy:
    return _policy(Constraint("max_velocity", {"max_mps": 0.5}), "policy-allow")


def _block_policy() -> Policy:
    return _policy(Constraint("max_velocity", {"max_mps": 0.1}), "policy-block")


def _review_policy() -> Policy:
    return _policy(
        Constraint("max_velocity", {"max_mps": 0.1}, required=False),
        "policy-review",
    )


def test_policy_admission_none_normalises_to_disabled_mode() -> None:
    context = _context()
    result = run_pipeline(_intent(context), context)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.mode is PolicyAdmissionMode.DISABLED
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.safety_case is None
    assert result.policy_admission.admission_allowed is False
    assert result.gate_decision is None


def test_disabled_mode_is_explicit_non_approval() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.reasons == ("POLICY_ADMISSION_DISABLED",)


def test_enforce_missing_policy_blocks_before_gate() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False
    assert "POLICY_REQUIRED" in result.policy_admission.reasons


def test_enforce_missing_capability_blocks_before_gate() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_allow_policy(),
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert "CAPABILITY_REQUIRED" in result.policy_admission.reasons


def test_invalid_intent_with_enforce_marks_policy_admission_not_run() -> None:
    context = _context()
    intent = RawIntent("unsupported", {}, "operator", 5, context)
    result = run_pipeline(
        intent,
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_allow_policy(),
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.INVALID
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False
    assert result.policy_admission.reasons == ("POLICY_ADMISSION_NOT_RUN",)


def test_policy_allow_continues_to_existing_gate() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_allow_policy(),
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.gate_decision.status == "allowed"
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ALLOW
    assert result.policy_admission.safety_case is not None
    assert result.audited_plan is not None
    assert result.policy_admission.safety_case.audited_plan_id == result.audited_plan.audit_id


def test_policy_block_prevents_gate_approval() -> None:
    context = _context()
    with patch("aegis.pipeline.orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_block_policy(),
                capability=_capability(),
            ),
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK
    assert "POLICY_BLOCKED" in result.policy_admission.reasons


def test_policy_require_review_prevents_gate_approval() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_review_policy(),
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.REQUIRE_REVIEW
    assert "POLICY_REQUIRES_REVIEW" in result.policy_admission.reasons


def test_policy_invalid_prevents_gate_approval() -> None:
    context = _context()
    invalid_result = PolicyEvaluationResult(
        PolicyDecision.INVALID,
        "policy-invalid",
        [],
        [],
        [],
        ["POLICY_EVALUATION_CONTEXT_INVALID"],
    )

    with patch("aegis.pipeline.orchestrator.evaluate_policy", return_value=invalid_result):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allow_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.INVALID
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.INVALID
    assert "POLICY_INVALID" in result.policy_admission.reasons


def test_policy_error_prevents_gate_approval() -> None:
    context = _context()
    error_result = PolicyEvaluationResult(
        PolicyDecision.ERROR,
        "policy-error",
        [],
        [],
        [],
        ["POLICY_EVALUATOR_INTERNAL_ERROR"],
    )

    with patch("aegis.pipeline.orchestrator.evaluate_policy", return_value=error_result):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allow_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ERROR
    assert "POLICY_ERROR" in result.policy_admission.reasons


def test_policy_evaluator_exception_returns_error_without_gate_approval() -> None:
    context = _context()

    with patch("aegis.pipeline.orchestrator.evaluate_policy", side_effect=RuntimeError("boom")):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allow_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.reasons == ("POLICY_EVALUATION_FAILED",)


def test_safety_case_exception_returns_error_without_gate_approval() -> None:
    context = _context()

    with patch("aegis.pipeline.orchestrator.build_safety_case", side_effect=RuntimeError("boom")):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allow_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert "SAFETY_CASE_BUILD_FAILED" in result.policy_admission.reasons


def test_disabled_mode_is_not_represented_as_policy_allow() -> None:
    context = _context()
    result = run_pipeline(_intent(context), context)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.mode is PolicyAdmissionMode.DISABLED
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.safety_case is None
    assert result.policy_admission.admission_allowed is False
