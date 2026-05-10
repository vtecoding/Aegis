"""Adversarial tests for ADR-0015 execution adapter bypass attempts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_mapping, allowed_pipeline_result

from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterReason,
)
from aegis.execution import build_execution_adapter_envelope


def test_direct_ready_envelope_construction_from_fragments_is_rejected() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-bypass-fragments")
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


def test_forged_mapping_checksum_prevents_ready_envelope() -> None:
    mapping = adapter_mapping()
    object.__setattr__(mapping, "adapter_mapping_checksum", "0" * 64)
    result = allowed_pipeline_result(request_id="adapter-bypass-forged-mapping")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert (
        ExecutionAdapterReason.ADAPTER_MAPPING_CHECKSUM_MISMATCH.value in envelope.blocked_reasons
    )


def test_fake_policy_checksum_prevents_ready_envelope() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-bypass-fake-policy")
    object.__setattr__(result.policy_admission, "policy_checksum", "0" * 64)

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.blocked_reasons == (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID.value,)


def test_fake_context_authority_checksum_prevents_ready_envelope() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-bypass-fake-context")
    object.__setattr__(result.policy_admission, "context_authority_checksum", "0" * 64)

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.blocked_reasons == (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID.value,)


def test_fake_decision_trace_checksum_prevents_ready_envelope() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-bypass-fake-trace")
    assert result.decision_trace is not None
    object.__setattr__(result.decision_trace, "trace_checksum", "0" * 64)

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.blocked_reasons == (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID.value,)
