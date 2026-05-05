"""Contract tests: PipelineResult and PipelineOutcome conform to their typed contracts."""

from __future__ import annotations

import pytest

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.planning import CommandPlan
from aegis.contracts.validation import ValidationResult, Violation

# ---------------------------------------------------------------------------
# PipelineOutcome
# ---------------------------------------------------------------------------


def test_pipeline_outcome_values_are_stable() -> None:
    assert PipelineOutcome.ALLOWED == "allowed"
    assert PipelineOutcome.BLOCKED == "blocked"
    assert PipelineOutcome.INVALID == "invalid"
    assert PipelineOutcome.ERROR == "error"


def test_pipeline_outcome_is_str_enum() -> None:
    assert isinstance(PipelineOutcome.ALLOWED, str)


# ---------------------------------------------------------------------------
# PipelineResult — ALLOWED
# ---------------------------------------------------------------------------


def _make_allowed_result(
    validation_result: ValidationResult,
    plan: CommandPlan,
    audited_plan: AuditedPlan,
    gate_decision: GateDecision,
) -> PipelineResult:
    return PipelineResult(
        outcome=PipelineOutcome.ALLOWED,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=gate_decision,
    )


def test_pipeline_result_allowed_requires_allowed_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    result = _make_allowed_result(
        make_validation_result, make_command_plan, make_audited_plan, make_allowed_gate_decision
    )
    assert result.outcome == PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.gate_decision.status == GateDecisionStatus.ALLOWED


def test_pipeline_result_allowed_rejects_missing_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=None,
        )


def test_pipeline_result_allowed_rejects_blocked_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_blocked_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_blocked_gate_decision,
        )


# ---------------------------------------------------------------------------
# PipelineResult — BLOCKED
# ---------------------------------------------------------------------------


def test_pipeline_result_blocked_requires_blocked_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_blocked_gate_decision: GateDecision,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.BLOCKED,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=make_blocked_gate_decision,
    )
    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.gate_decision is not None
    assert result.gate_decision.status == GateDecisionStatus.BLOCKED


def test_pipeline_result_blocked_rejects_missing_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.BLOCKED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=None,
        )


def test_pipeline_result_blocked_rejects_allowed_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.BLOCKED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_allowed_gate_decision,
        )


# ---------------------------------------------------------------------------
# PipelineResult — INVALID
# ---------------------------------------------------------------------------


def test_pipeline_result_invalid_accepts_none_fields() -> None:
    from datetime import UTC, datetime

    from aegis.contracts.context import ExecutionContext
    from aegis.contracts.intent import RawIntent

    ctx = ExecutionContext("test", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    intent = RawIntent(
        command="launch_missiles",
        parameters={},
        source_id="test",
        priority=5,
        context=ctx,
    )
    vr = ValidationResult(
        is_valid=False,
        intent=intent,
        violations=(
            Violation(
                code="UNSUPPORTED_COMMAND",
                field="command",
                reason="not a supported command",
                layer="validation",
            ),
        ),
    )
    result = PipelineResult(
        outcome=PipelineOutcome.INVALID,
        validation_result=vr,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.INVALID
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_pipeline_result_invalid_rejects_non_none_plan(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
) -> None:
    with pytest.raises(ValueError, match="plan=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=None,
            gate_decision=None,
        )


def test_pipeline_result_invalid_rejects_non_none_audited_plan(
    make_validation_result: ValidationResult,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="audited_plan=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=None,
            audited_plan=make_audited_plan,
            gate_decision=None,
        )


def test_pipeline_result_invalid_rejects_non_none_gate_decision(
    make_validation_result: ValidationResult,
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=make_allowed_gate_decision,
        )


# ---------------------------------------------------------------------------
# PipelineResult — ERROR
# ---------------------------------------------------------------------------


def test_pipeline_result_error_accepts_all_none_fields() -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.ERROR,
        validation_result=None,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.ERROR


def test_pipeline_result_error_accepts_partial_fields(
    make_validation_result: ValidationResult,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.ERROR,
        validation_result=make_validation_result,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is not None


# ---------------------------------------------------------------------------
# PipelineResult — immutability
# ---------------------------------------------------------------------------


def test_pipeline_result_is_frozen(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.ALLOWED,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=make_allowed_gate_decision,
    )
    with pytest.raises((AttributeError, TypeError)):
        result.outcome = PipelineOutcome.BLOCKED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Fixtures (scoped to this module via conftest below — defined inline here)
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_validation_result() -> ValidationResult:
    from datetime import UTC, datetime

    from aegis.contracts.context import ExecutionContext
    from aegis.contracts.intent import RawIntent

    ctx = ExecutionContext("test-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    intent = RawIntent(
        command="stop",
        parameters={},
        source_id="test",
        priority=5,
        context=ctx,
    )
    return ValidationResult(is_valid=True, intent=intent, violations=())


@pytest.fixture()
def make_command_plan(make_validation_result: ValidationResult) -> CommandPlan:
    from aegis.planning import plan_validated_intent

    return plan_validated_intent(make_validation_result)


@pytest.fixture()
def make_audited_plan(make_command_plan: CommandPlan) -> AuditedPlan:
    from aegis.audit import build_audited_plan

    return build_audited_plan(make_command_plan)


@pytest.fixture()
def make_allowed_gate_decision(make_audited_plan: AuditedPlan) -> GateDecision:
    from aegis.gate import gate_audited_plan

    decision = gate_audited_plan(make_audited_plan)
    assert decision.status == GateDecisionStatus.ALLOWED
    return decision


@pytest.fixture()
def make_blocked_gate_decision() -> GateDecision:
    return GateDecision(
        status=GateDecisionStatus.BLOCKED,
        audit_id="aaa",
        plan_id="bbb",
        reasons=(GateBlockReason.CHECKSUM_MISMATCH,),
        checksum_verified=False,
        audit_id_verified=False,
    )
