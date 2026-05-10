"""Pipeline tests for policy admission wiring after audit and before gate."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
)
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
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


def _admission(policy: Policy, capability: Capability | None = None) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=capability or _capability(),
        world_snapshot=fresh_world_snapshot(),
        context=fresh_policy_context(),
    )


def _trusted_kwargs(admission: PolicyAdmissionInput) -> dict[str, object]:
    assert admission.world_snapshot is not None
    return trusted_pipeline_kwargs(admission.world_snapshot)


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
    admission = _admission(_allow_policy())
    result = run_pipeline(
        intent,
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
    )

    assert result.outcome is PipelineOutcome.INVALID
    assert result.gate_decision is None
    assert result.policy_admission.admission_allowed is False
    assert result.policy_admission.reasons == ("POLICY_ADMISSION_NOT_RUN",)


def test_policy_allow_continues_to_existing_gate() -> None:
    context = _context()
    admission = _admission(_allow_policy())
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
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
    admission = _admission(_block_policy())
    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK
    assert "POLICY_BLOCKED" in result.policy_admission.reasons


def test_policy_require_review_prevents_gate_approval() -> None:
    context = _context()
    admission = _admission(_review_policy())
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
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

    admission = _admission(_allow_policy())
    with patch("aegis.pipeline.aegis_orchestrator.evaluate_policy", return_value=invalid_result):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
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

    admission = _admission(_allow_policy())
    with patch("aegis.pipeline.aegis_orchestrator.evaluate_policy", return_value=error_result):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ERROR
    assert "POLICY_ERROR" in result.policy_admission.reasons


def test_policy_evaluator_exception_returns_error_without_gate_approval() -> None:
    context = _context()
    admission = _admission(_allow_policy())

    with patch(
        "aegis.pipeline.aegis_orchestrator.evaluate_policy", side_effect=RuntimeError("boom")
    ):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.reasons == ("POLICY_EVALUATION_FAILED",)


def test_safety_case_exception_returns_error_without_gate_approval() -> None:
    context = _context()
    admission = _admission(_allow_policy())

    with patch(
        "aegis.pipeline.aegis_orchestrator.build_safety_case", side_effect=RuntimeError("boom")
    ):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
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
