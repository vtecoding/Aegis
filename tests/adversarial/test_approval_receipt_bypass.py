"""Adversarial tests for approval receipt bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.audit import build_audited_plan
from aegis.contracts.approval_receipt import (
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    validate_approval_receipt,
)
from aegis.contracts.context import ExecutionContext
from aegis.contracts.decision_trace import DecisionTrace, DecisionTraceStep
from aegis.contracts.gate import GateDecision
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.gate import gate_audited_plan
from aegis.pipeline import run_pipeline
from aegis.planning import plan_validated_intent
from aegis.validation import validate_intent


def _context(request_id: str) -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext, *, target_x: int = 1) -> RawIntent:
    return RawIntent("move", {"target": {"x": target_x, "y": 2}}, "operator", 5, context)


def _policy() -> Policy:
    return Policy(
        "approval-receipt-adversarial-policy",
        "v1",
        [
            PolicyRule(
                "rule-1", "locomotion.translation", [Constraint("max_velocity", {"max_mps": 1.0})]
            )
        ],
    )


def _allowed_result(request_id: str = "approval-receipt-adversarial"):
    context = _context(request_id)
    snapshot = fresh_world_snapshot()
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )
    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.decision_trace is not None
    assert result.approval_receipt is not None
    return result


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    [
        ("gate_decision_checksum", "forged-gate"),
        ("policy_result_checksum", "forged-policy"),
        ("safety_case_checksum", "forged-safety-case"),
        ("trust_result_checksum", "forged-trust"),
        ("freshness_checksum", "forged-freshness"),
        ("admissibility_checksum", "forged-admissibility"),
        ("approval_receipt_checksum", "forged-receipt"),
    ],
)
def test_forged_approval_receipt_field_fails_closed(field_name: str, forged_value: str) -> None:
    result = _allowed_result(f"receipt-forgery-{field_name}")
    object.__setattr__(result.approval_receipt, field_name, forged_value)

    validation = validate_approval_receipt(result.approval_receipt, result.decision_trace)

    assert validation.status is ApprovalReceiptStatus.INVALID


def test_reordered_decision_trace_fails_closed() -> None:
    result = _allowed_result("receipt-reordered-trace")
    trace = result.decision_trace
    reordered_steps = (trace.steps[1], trace.steps[0], *trace.steps[2:])
    object.__setattr__(trace, "steps", reordered_steps)

    validation = validate_approval_receipt(result.approval_receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.DECISION_TRACE_INVALID


def test_broken_predecessor_checksum_fails_closed() -> None:
    result = _allowed_result("receipt-broken-predecessor")
    object.__setattr__(result.decision_trace.steps[3], "predecessor_checksum", "forged-link")

    validation = validate_approval_receipt(result.approval_receipt, result.decision_trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.DECISION_TRACE_INVALID


def test_duplicate_stage_name_fails_closed() -> None:
    result = _allowed_result("receipt-duplicate-stage")
    object.__setattr__(result.decision_trace.steps[9], "stage_name", "policy_admission")

    validation = validate_approval_receipt(result.approval_receipt, result.decision_trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.DECISION_TRACE_INVALID


def test_direct_gate_decision_cannot_be_misrepresented_as_pipeline_approval() -> None:
    context = _context("direct-gate-not-full-approval")
    validation_result = validate_intent(_intent(context))
    plan = plan_validated_intent(validation_result)
    audited_plan = build_audited_plan(plan)
    gate_decision = gate_audited_plan(audited_plan)
    assert isinstance(gate_decision, GateDecision)

    with pytest.raises(ValueError, match="policy-backed"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=gate_decision,
        )


def test_old_receipt_replayed_against_new_plan_is_rejected_by_pipeline_result() -> None:
    original = _allowed_result("receipt-replay-original")
    context = _context("receipt-replay-new-plan")
    validation_result = validate_intent(_intent(context, target_x=9))
    plan = plan_validated_intent(validation_result)
    audited_plan = build_audited_plan(plan)
    gate_decision = gate_audited_plan(audited_plan)

    with pytest.raises(ValueError, match="policy-backed|approval receipt bindings"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=gate_decision,
            policy_admission=original.policy_admission,
            decision_trace=original.decision_trace,
            approval_receipt=original.approval_receipt,
            receipt_validation=original.receipt_validation,
        )


def test_extra_unknown_stage_fails_closed() -> None:
    raw = DecisionTraceStep(
        stage_name="raw_intent",
        stage_status="OK",
        stage_reason="RAW_INTENT_OK",
        input_checksum="context",
        output_checksum="raw",
        predecessor_checksum=None,
    )
    unknown = DecisionTraceStep(
        stage_name="validation",
        stage_status="OK",
        stage_reason="VALIDATION_OK",
        input_checksum=raw.output_checksum,
        output_checksum="validation",
        predecessor_checksum=raw.stage_checksum,
    )
    object.__setattr__(unknown, "stage_name", "approval_shadow")

    with pytest.raises(ValueError, match="UNKNOWN_STAGE"):
        DecisionTrace((raw, unknown))
