"""Adversarial tests for ADR-0014 authority drift bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_approval_receipt import (
    ApprovalReceipt,
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    validate_approval_receipt,
)
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.governance.aegis_context_authority import ContextAuthority
from aegis.pipeline import run_pipeline


def _context(request_id: str) -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _admission(snapshot) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=Policy(
            "authority-drift-policy",
            "v1",
            (
                PolicyRule(
                    "rule-max-velocity",
                    "locomotion.translation",
                    (Constraint("max_velocity", {"max_mps": 1.0}),),
                ),
            ),
        ),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def _authority(evaluation_time_ms: int = FRESH_EVALUATION_TIME_MS) -> ContextAuthority:
    return ContextAuthority(
        context_id="authority-drift-context",
        request_id="authority-drift-request",
        evaluation_time_ms=evaluation_time_ms,
        caller_authority="pytest",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )


def test_enforced_pipeline_blocks_when_context_authority_is_missing() -> None:
    context = _context("authority-missing")
    snapshot = fresh_world_snapshot()
    kwargs = trusted_pipeline_kwargs(snapshot)
    kwargs.pop("context_authority")

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **kwargs,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "CONTEXT_AUTHORITY_REQUIRED" in result.policy_admission.reasons
    assert result.gate_decision is None


def test_enforced_pipeline_blocks_context_authority_time_mismatch() -> None:
    context = _context("authority-time-mismatch")
    snapshot = fresh_world_snapshot()
    kwargs = trusted_pipeline_kwargs(snapshot)
    kwargs["context_authority"] = _authority(FRESH_EVALUATION_TIME_MS + 1)

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **kwargs,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "CONTEXT_AUTHORITY_EVALUATION_TIME_MISMATCH" in result.policy_admission.reasons
    assert result.gate_decision is None


def test_allowed_receipt_cannot_omit_context_authority_binding() -> None:
    context = _context("authority-receipt-forgery")
    snapshot = fresh_world_snapshot()

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.approval_receipt is not None
    assert result.decision_trace is not None
    receipt = result.approval_receipt
    forged = ApprovalReceipt(
        status=receipt.status,
        reason=receipt.reason,
        pipeline_result_id=receipt.pipeline_result_id,
        pipeline_outcome=receipt.pipeline_outcome,
        raw_intent_checksum=receipt.raw_intent_checksum,
        validation_checksum=receipt.validation_checksum,
        plan_checksum=receipt.plan_checksum,
        audit_id=receipt.audit_id,
        audited_plan_checksum=receipt.audited_plan_checksum,
        world_snapshot_checksum=receipt.world_snapshot_checksum,
        admissibility_checksum=receipt.admissibility_checksum,
        freshness_checksum=receipt.freshness_checksum,
        verifier_certification_checksum=receipt.verifier_certification_checksum,
        trust_policy_config_checksum=receipt.trust_policy_config_checksum,
        trust_result_checksum=receipt.trust_result_checksum,
        policy_checksum=receipt.policy_checksum,
        context_authority_checksum=None,
        policy_result_checksum=receipt.policy_result_checksum,
        safety_case_checksum=receipt.safety_case_checksum,
        policy_admission_checksum=receipt.policy_admission_checksum,
        gate_decision_checksum=receipt.gate_decision_checksum,
        decision_trace_checksum=receipt.decision_trace_checksum,
    )

    forged_validation = validate_approval_receipt(forged, result.decision_trace)

    assert forged_validation.status is ApprovalReceiptStatus.INVALID
    assert forged_validation.reason is ApprovalReceiptReason.APPROVAL_RECEIPT_REQUIRED_FIELD_MISSING
    assert "context_authority_checksum" in forged_validation.failed_fields
