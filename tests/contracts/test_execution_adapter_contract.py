"""Contract tests for ADR-0015 execution adapter contracts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import (
    adapter_mapping,
    allowed_pipeline_result,
    runtime_target,
)

from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterMapping,
    ExecutionAdapterReason,
    ExecutionAdapterValidationResult,
    execution_adapter_envelope_checksum,
    make_ready_envelope_authorization,
    recompute_execution_adapter_envelope_checksum,
    recompute_execution_adapter_mapping_checksum,
)
from aegis.execution import build_execution_adapter_envelope


def test_execution_adapter_mapping_binds_runtime_and_ros2_checksums() -> None:
    mapping = adapter_mapping()

    assert mapping.adapter_mapping_checksum == recompute_execution_adapter_mapping_checksum(mapping)
    assert mapping.accepted_pipeline_version == "pipeline-v1"
    assert mapping.accepted_gate_version == "gate-v1"


def test_execution_adapter_mapping_rejects_invalid_effective_time() -> None:
    with pytest.raises(ValueError, match="effective_from_ms"):
        adapter_mapping(effective_from_ms=-1)


def test_execution_adapter_mapping_rejects_wrong_contract_types() -> None:
    mapping = adapter_mapping()

    with pytest.raises(ValueError, match="runtime_target"):
        ExecutionAdapterMapping(
            adapter_mapping_id="adapter-mapping-ros2-move",
            adapter_mapping_version="v1",
            runtime_target=object(),
            ros2_mapping=mapping.ros2_mapping,
            accepted_policy_schema_version=mapping.accepted_policy_schema_version,
            adapter_authority=mapping.adapter_authority,
            effective_from_ms=0,
        )
    with pytest.raises(ValueError, match="ros2_mapping"):
        ExecutionAdapterMapping(
            adapter_mapping_id="adapter-mapping-ros2-move",
            adapter_mapping_version="v1",
            runtime_target=mapping.runtime_target,
            ros2_mapping=object(),
            accepted_policy_schema_version=mapping.accepted_policy_schema_version,
            adapter_authority=mapping.adapter_authority,
            effective_from_ms=0,
        )


def test_execution_adapter_mapping_rejects_forged_checksum() -> None:
    target = runtime_target()
    mapping = adapter_mapping(target=target)

    with pytest.raises(ValueError, match="checksum"):
        ExecutionAdapterMapping(
            adapter_mapping_id=mapping.adapter_mapping_id,
            adapter_mapping_version=mapping.adapter_mapping_version,
            runtime_target=mapping.runtime_target,
            ros2_mapping=mapping.ros2_mapping,
            accepted_policy_schema_version=mapping.accepted_policy_schema_version,
            adapter_authority=mapping.adapter_authority,
            effective_from_ms=mapping.effective_from_ms,
            adapter_mapping_checksum="0" * 64,
        )


def test_execution_adapter_envelope_rejects_ready_without_pipeline_authorization() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result()
    assert result.approval_receipt is not None
    assert result.decision_trace is not None
    assert result.audited_plan is not None

    with pytest.raises(ValueError, match=ExecutionAdapterReason.DIRECT_ADAPTER_BYPASS.value):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.READY,
            pipeline_receipt_checksum=result.approval_receipt.approval_receipt_checksum,
            decision_trace_checksum=result.decision_trace.trace_checksum,
            audited_plan_id=result.audited_plan.audit_id,
            plan_checksum=result.audited_plan.checksum,
            policy_checksum=result.policy_admission.policy_checksum,
            context_authority_checksum=result.policy_admission.context_authority_checksum,
            safety_case_id=result.policy_admission.safety_case_id,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={"target.x": 1, "target.y": 2},
            blocked_reasons=(),
            terminal_adapter_stage="adapter_envelope",
            payload_field_count=2,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
        )


def test_execution_adapter_envelope_rejects_non_ready_payload() -> None:
    mapping = adapter_mapping()

    with pytest.raises(ValueError, match="command_payload"):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            pipeline_receipt_checksum=None,
            decision_trace_checksum=None,
            audited_plan_id=None,
            plan_checksum=None,
            policy_checksum=None,
            context_authority_checksum=None,
            safety_case_id=None,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={"target.x": 1},
            blocked_reasons=(ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED.value,),
            terminal_adapter_stage="pipeline_receipt",
            payload_field_count=1,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
        )


def test_execution_adapter_envelope_rejects_non_ready_without_reasons() -> None:
    mapping = adapter_mapping()

    with pytest.raises(ValueError, match="blocked_reasons"):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            pipeline_receipt_checksum=None,
            decision_trace_checksum=None,
            audited_plan_id=None,
            plan_checksum=None,
            policy_checksum=None,
            context_authority_checksum=None,
            safety_case_id=None,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={},
            blocked_reasons=(),
            terminal_adapter_stage="pipeline_receipt",
            payload_field_count=0,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
        )


def test_execution_adapter_envelope_rejects_invalid_reason_and_payload_count() -> None:
    mapping = adapter_mapping()

    with pytest.raises(ValueError, match="blocked_reasons"):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            pipeline_receipt_checksum=None,
            decision_trace_checksum=None,
            audited_plan_id=None,
            plan_checksum=None,
            policy_checksum=None,
            context_authority_checksum=None,
            safety_case_id=None,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={},
            blocked_reasons=("not_uppercase",),
            terminal_adapter_stage="pipeline_receipt",
            payload_field_count=0,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
        )
    with pytest.raises(ValueError, match="payload_field_count"):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            pipeline_receipt_checksum=None,
            decision_trace_checksum=None,
            audited_plan_id=None,
            plan_checksum=None,
            policy_checksum=None,
            context_authority_checksum=None,
            safety_case_id=None,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={},
            blocked_reasons=(ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED.value,),
            terminal_adapter_stage="pipeline_receipt",
            payload_field_count=1,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
        )


def test_ready_envelope_authorization_rejects_mismatched_evidence() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-ready-mismatch")
    assert result.approval_receipt is not None
    assert result.decision_trace is not None
    assert result.audited_plan is not None

    with pytest.raises(ValueError, match="evidence"):
        ExecutionAdapterEnvelope(
            status=ExecutionAdapterEnvelopeStatus.READY,
            pipeline_receipt_checksum=result.approval_receipt.approval_receipt_checksum,
            decision_trace_checksum=result.decision_trace.trace_checksum,
            audited_plan_id=result.audited_plan.audit_id,
            plan_checksum="0" * 64,
            policy_checksum=result.policy_admission.policy_checksum,
            context_authority_checksum=result.policy_admission.context_authority_checksum,
            safety_case_id=result.policy_admission.safety_case_id,
            adapter_mapping_checksum=mapping.adapter_mapping_checksum,
            runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
            command_payload={"target.x": 1, "target.y": 2},
            blocked_reasons=(),
            terminal_adapter_stage="adapter_envelope",
            payload_field_count=2,
            forbidden_field_detected=False,
            qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
            adapter_authority=mapping.adapter_authority,
            authorization=make_ready_envelope_authorization(
                pipeline_result=result,
                adapter_mapping=mapping,
                target_runtime=mapping.runtime_target,
            ),
        )


def test_execution_adapter_validation_result_rejects_inconsistent_status() -> None:
    with pytest.raises(ValueError, match="READY validation"):
        ExecutionAdapterValidationResult(
            status=ExecutionAdapterEnvelopeStatus.READY,
            reasons=(ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED,),
            command_payload={},
            terminal_adapter_stage="payload_mapper",
        )
    with pytest.raises(ValueError, match="non-ready validation"):
        ExecutionAdapterValidationResult(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            reasons=(),
            command_payload={},
            terminal_adapter_stage="payload_mapper",
        )


def test_execution_adapter_validation_result_rejects_invalid_reason_values() -> None:
    with pytest.raises(ValueError, match="reasons"):
        ExecutionAdapterValidationResult(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            reasons=("PIPELINE_RESULT_NOT_ALLOWED",),
            command_payload={},
            terminal_adapter_stage="payload_mapper",
        )
    with pytest.raises(ValueError, match="forbidden_field_detected"):
        ExecutionAdapterValidationResult(
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            reasons=(ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED,),
            command_payload={},
            terminal_adapter_stage="payload_mapper",
            forbidden_field_detected="false",
        )


def test_ready_envelope_checksum_recomputes() -> None:
    result = allowed_pipeline_result()
    mapping = adapter_mapping()
    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.READY
    assert envelope.envelope_checksum == recompute_execution_adapter_envelope_checksum(envelope)
    assert envelope.envelope_checksum == execution_adapter_envelope_checksum(
        status=envelope.status,
        pipeline_receipt_checksum=envelope.pipeline_receipt_checksum,
        decision_trace_checksum=envelope.decision_trace_checksum,
        audited_plan_id=envelope.audited_plan_id,
        plan_checksum=envelope.plan_checksum,
        policy_checksum=envelope.policy_checksum,
        context_authority_checksum=envelope.context_authority_checksum,
        safety_case_id=envelope.safety_case_id,
        adapter_mapping_checksum=envelope.adapter_mapping_checksum,
        runtime_target_checksum=envelope.runtime_target_checksum,
        ros2_mapping_checksum=envelope.ros2_mapping_checksum,
        command_payload=envelope.command_payload,
        blocked_reasons=envelope.blocked_reasons,
        terminal_adapter_stage=envelope.terminal_adapter_stage,
        payload_field_count=envelope.payload_field_count,
        forbidden_field_detected=envelope.forbidden_field_detected,
        qos_profile_checksum=envelope.qos_profile_checksum,
        adapter_authority=envelope.adapter_authority,
    )
