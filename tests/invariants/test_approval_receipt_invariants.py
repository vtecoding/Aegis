"""Invariant tests for approval receipt integrity."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.audit import build_audited_plan
from aegis.contracts.approval_receipt import ApprovalReceiptStatus, validate_approval_receipt
from aegis.contracts.context import ExecutionContext
from aegis.contracts.decision_trace import ALLOW_REQUIRED_STAGE_CHAIN, decision_trace_step_checksum
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


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _admission(snapshot) -> PolicyAdmissionInput:
    policy = Policy(
        "approval-receipt-invariant-policy",
        "v1",
        [
            PolicyRule(
                "rule-1", "locomotion.translation", [Constraint("max_velocity", {"max_mps": 1.0})]
            )
        ],
    )
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


@given(st.integers(min_value=1, max_value=50))
@settings(max_examples=10)
def test_invariant_allowed_implies_valid_approval_receipt(request_number: int) -> None:
    context = _context(f"approval-receipt-invariant-{request_number}")
    snapshot = fresh_world_snapshot(snapshot_id=f"snapshot-{request_number}")

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
    assert result.receipt_validation.status is ApprovalReceiptStatus.VALID
    assert validate_approval_receipt(result.approval_receipt, result.decision_trace).status is (
        ApprovalReceiptStatus.VALID
    )


@given(st.integers(min_value=1, max_value=50))
@settings(max_examples=10)
def test_invariant_allowed_stage_chain_and_checksums_recompute(request_number: int) -> None:
    context = _context(f"approval-receipt-chain-{request_number}")
    snapshot = fresh_world_snapshot(snapshot_id=f"snapshot-chain-{request_number}")

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.decision_trace is not None
    assert (
        tuple(step.stage_name for step in result.decision_trace.steps) == ALLOW_REQUIRED_STAGE_CHAIN
    )
    previous_stage_checksum: str | None = None
    previous_output_checksum: str | None = None
    for step in result.decision_trace.steps:
        assert step.predecessor_checksum == previous_stage_checksum
        if previous_output_checksum is not None:
            assert step.input_checksum == previous_output_checksum
        assert step.stage_checksum == decision_trace_step_checksum(
            stage_name=step.stage_name,
            stage_status=step.stage_status,
            stage_reason=step.stage_reason,
            input_checksum=step.input_checksum,
            output_checksum=step.output_checksum,
            predecessor_checksum=step.predecessor_checksum,
            metadata=step.metadata,
        )
        previous_stage_checksum = step.stage_checksum
        previous_output_checksum = step.output_checksum


def test_invariant_direct_gate_allow_is_not_full_pipeline_approval() -> None:
    context = _context("direct-gate-invariant")
    validation_result = validate_intent(_intent(context))
    plan = plan_validated_intent(validation_result)
    audited_plan = build_audited_plan(plan)
    gate_decision = gate_audited_plan(audited_plan)

    with pytest.raises(ValueError):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=gate_decision,
        )
