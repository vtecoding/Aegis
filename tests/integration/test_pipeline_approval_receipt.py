"""Integration tests for pipeline approval receipt construction."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.approval_receipt import (
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    ApprovalReceiptValidationResult,
)
from aegis.contracts.context import ExecutionContext
from aegis.contracts.decision_trace import ALLOW_REQUIRED_STAGE_CHAIN
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def _context(request_id: str = "approval-receipt") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext, command: str = "move") -> RawIntent:
    return RawIntent(command, {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy(max_mps: float = 1.0) -> Policy:
    return Policy(
        "approval-receipt-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps})],
            )
        ],
    )


def _admission(snapshot) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def test_allowed_pipeline_result_contains_valid_full_approval_receipt() -> None:
    context = _context("approval-receipt-allowed")
    snapshot = fresh_world_snapshot()

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.decision_trace is not None
    assert result.approval_receipt is not None
    assert result.receipt_validation is not None
    assert result.approval_receipt.status is ApprovalReceiptStatus.VALID
    assert result.receipt_validation.status is ApprovalReceiptStatus.VALID
    assert (
        tuple(step.stage_name for step in result.decision_trace.steps) == ALLOW_REQUIRED_STAGE_CHAIN
    )
    assert result.audited_plan is not None
    assert result.approval_receipt.audit_id == result.audited_plan.audit_id
    assert result.approval_receipt.policy_result_checksum == (
        result.policy_admission.policy_result_checksum
    )
    assert result.approval_receipt.gate_decision_checksum is not None


def test_blocked_before_policy_does_not_claim_fake_policy_or_trust_receipt() -> None:
    context = _context("approval-receipt-disabled")

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.decision_trace is not None
    assert result.approval_receipt is not None
    assert result.receipt_validation is not None
    assert result.receipt_validation.status is ApprovalReceiptStatus.VALID
    assert result.approval_receipt.policy_result_checksum is None
    assert result.approval_receipt.trust_result_checksum is None
    assert result.approval_receipt.gate_decision_checksum is None
    assert tuple(step.stage_name for step in result.decision_trace.steps) == (
        "raw_intent",
        "validation",
        "planning",
        "audit",
        "policy_admission",
    )


def test_invalid_pipeline_result_receipt_proves_validation_failed_before_plan() -> None:
    context = _context("approval-receipt-invalid")

    result = run_pipeline(_intent(context, command="launch"), context)

    assert result.outcome is PipelineOutcome.INVALID
    assert result.decision_trace is not None
    assert result.approval_receipt is not None
    assert result.receipt_validation is not None
    assert result.receipt_validation.status is ApprovalReceiptStatus.VALID
    assert result.approval_receipt.plan_checksum is None
    assert result.approval_receipt.gate_decision_checksum is None
    assert tuple(step.stage_name for step in result.decision_trace.steps) == (
        "raw_intent",
        "validation",
    )


def test_allowed_chain_with_invalid_receipt_validation_returns_error() -> None:
    context = _context("approval-receipt-forced-invalid")
    snapshot = fresh_world_snapshot()
    forced_validation = ApprovalReceiptValidationResult(
        status=ApprovalReceiptStatus.INVALID,
        reason=ApprovalReceiptReason.APPROVAL_RECEIPT_CHECKSUM_MISMATCH,
        approval_receipt_checksum="forced-receipt-checksum",
        decision_trace_checksum="forced-trace-checksum",
        failed_fields=("approval_receipt_checksum",),
    )

    with patch(
        "aegis.pipeline.orchestrator.validate_approval_receipt", return_value=forced_validation
    ):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **trusted_pipeline_kwargs(snapshot),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.receipt_validation is forced_validation
    assert result.policy_admission.exception_reason == "APPROVAL_RECEIPT_INTEGRITY_FAILED"
