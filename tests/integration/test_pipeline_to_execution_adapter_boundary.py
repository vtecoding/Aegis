"""Integration tests for the pipeline-to-adapter boundary."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import (
    adapter_context,
    adapter_intent,
    adapter_mapping,
    allowed_pipeline_result,
    blocked_pipeline_result,
    ros2_stop_mapping,
    runtime_target,
)

from aegis.audit import build_audited_plan
from aegis.contracts.execution_adapter import ExecutionAdapterEnvelopeStatus, ExecutionAdapterReason
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.execution import build_execution_adapter_envelope
from aegis.gate import gate_audited_plan
from aegis.planning import plan_validated_intent
from aegis.validation import validate_intent


def test_full_allowed_pipeline_result_builds_ready_adapter_envelope() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-integration-ready")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert result.outcome is PipelineOutcome.ALLOWED
    assert envelope.status is ExecutionAdapterEnvelopeStatus.READY
    assert envelope.policy_checksum == result.policy_admission.policy_checksum
    assert envelope.context_authority_checksum == result.policy_admission.context_authority_checksum
    assert envelope.safety_case_id == result.policy_admission.safety_case_id


def test_full_stop_pipeline_result_builds_ready_adapter_envelope() -> None:
    target = runtime_target()
    mapping = adapter_mapping(target=target, ros2_mapping=ros2_stop_mapping())
    result = allowed_pipeline_result(command="stop", request_id="adapter-integration-stop")

    envelope = build_execution_adapter_envelope(result, mapping, target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.READY
    assert envelope.command_payload == {"command": "stop"}


def test_blocked_pipeline_result_builds_blocked_adapter_envelope() -> None:
    mapping = adapter_mapping()
    result = blocked_pipeline_result()

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.command_payload == {}
    assert ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED.value in envelope.blocked_reasons


def test_policy_allow_with_invalid_adapter_mapping_does_not_build_ready_envelope() -> None:
    target = runtime_target(namespace="robot_arm")
    mapping = adapter_mapping(target=target, ros2_mapping=adapter_mapping().ros2_mapping)
    object.__setattr__(mapping.ros2_mapping, "namespace", "other_arm")
    result = allowed_pipeline_result(request_id="adapter-integration-invalid-mapping")

    envelope = build_execution_adapter_envelope(result, mapping, target)

    assert result.outcome is PipelineOutcome.ALLOWED
    assert envelope.status is not ExecutionAdapterEnvelopeStatus.READY
    assert envelope.command_payload == {}


def test_direct_gate_allow_is_not_adapter_authority() -> None:
    context = adapter_context("adapter-direct-gate")
    validation_result = validate_intent(adapter_intent(context))
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
