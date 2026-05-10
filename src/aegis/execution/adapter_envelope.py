"""Build non-executing adapter envelopes from allowed pipeline results."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from aegis.contracts.approval_receipt import (
    ApprovalReceiptStatus,
    approval_receipt_matches_pipeline_fields,
    validate_approval_receipt,
)
from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterMapping,
    ExecutionAdapterReason,
    make_ready_envelope_authorization,
)
from aegis.contracts.json_types import JsonValue
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.policy_admission import is_policy_backed_approval
from aegis.contracts.ros2_mapping import RuntimeTarget
from aegis.execution.mapping_validator import validate_execution_adapter_mapping


def build_execution_adapter_envelope(
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
) -> ExecutionAdapterEnvelope:
    """Build a deterministic, non-executing adapter envelope.

    Args:
        pipeline_result: The only allowed source of adapter authority. READY
            envelopes require this result to be ALLOWED and receipt-valid.
        adapter_mapping: Explicit runtime and ROS 2 mapping contract.
        target_runtime: Caller-selected target runtime identity evidence.

    Returns:
        An immutable adapter envelope. Non-ready envelopes never carry command
        payload data.
    """
    pipeline_reasons = _pipeline_readiness_reasons(pipeline_result)
    if pipeline_reasons:
        return _envelope_from_failure(
            pipeline_result=pipeline_result,
            adapter_mapping=adapter_mapping,
            target_runtime=target_runtime,
            status=ExecutionAdapterEnvelopeStatus.BLOCKED,
            reasons=pipeline_reasons,
            terminal_adapter_stage="pipeline_receipt",
            forbidden_field_detected=False,
        )

    validation = validate_execution_adapter_mapping(
        pipeline_result, adapter_mapping, target_runtime
    )
    if validation.status is not ExecutionAdapterEnvelopeStatus.READY:
        return _envelope_from_failure(
            pipeline_result=pipeline_result,
            adapter_mapping=adapter_mapping,
            target_runtime=target_runtime,
            status=validation.status,
            reasons=validation.reasons,
            terminal_adapter_stage=validation.terminal_adapter_stage,
            forbidden_field_detected=validation.forbidden_field_detected,
        )

    return ExecutionAdapterEnvelope(
        status=ExecutionAdapterEnvelopeStatus.READY,
        pipeline_receipt_checksum=_pipeline_receipt_checksum(pipeline_result),
        decision_trace_checksum=_decision_trace_checksum(pipeline_result),
        audited_plan_id=_audited_plan_id(pipeline_result),
        plan_checksum=_plan_checksum(pipeline_result),
        policy_checksum=pipeline_result.policy_admission.policy_checksum,
        context_authority_checksum=pipeline_result.policy_admission.context_authority_checksum,
        safety_case_id=pipeline_result.policy_admission.safety_case_id,
        adapter_mapping_checksum=adapter_mapping.adapter_mapping_checksum,
        runtime_target_checksum=target_runtime.runtime_target_checksum,
        ros2_mapping_checksum=adapter_mapping.ros2_mapping.mapping_checksum,
        command_payload=cast("Mapping[str, JsonValue]", validation.command_payload),
        blocked_reasons=(),
        terminal_adapter_stage="adapter_envelope",
        payload_field_count=len(validation.command_payload),
        forbidden_field_detected=False,
        qos_profile_checksum=adapter_mapping.ros2_mapping.qos.qos_checksum,
        adapter_authority=adapter_mapping.adapter_authority,
        adapter_mapping=adapter_mapping,
        target_runtime=target_runtime,
        authorization=make_ready_envelope_authorization(
            pipeline_result=pipeline_result,
            adapter_mapping=adapter_mapping,
            target_runtime=target_runtime,
        ),
    )


def _pipeline_readiness_reasons(
    pipeline_result: PipelineResult,
) -> tuple[ExecutionAdapterReason, ...]:
    if pipeline_result.outcome is not PipelineOutcome.ALLOWED:
        return (ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED,)
    if (
        pipeline_result.validation_result is None
        or pipeline_result.plan is None
        or pipeline_result.audited_plan is None
        or pipeline_result.gate_decision is None
        or pipeline_result.decision_trace is None
        or pipeline_result.approval_receipt is None
        or pipeline_result.receipt_validation is None
    ):
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if pipeline_result.approval_receipt.status is not ApprovalReceiptStatus.VALID:
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if pipeline_result.receipt_validation.status is not ApprovalReceiptStatus.VALID:
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if (
        validate_approval_receipt(
            pipeline_result.approval_receipt,
            pipeline_result.decision_trace,
        ).status
        is not ApprovalReceiptStatus.VALID
    ):
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if not approval_receipt_matches_pipeline_fields(
        receipt=pipeline_result.approval_receipt,
        decision_trace=pipeline_result.decision_trace,
        receipt_validation=pipeline_result.receipt_validation,
        pipeline_outcome=pipeline_result.outcome.value,
        validation_result=pipeline_result.validation_result,
        plan=pipeline_result.plan,
        audited_plan=pipeline_result.audited_plan,
        gate_decision=pipeline_result.gate_decision,
        policy_admission=pipeline_result.policy_admission,
    ):
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if not is_policy_backed_approval(
        pipeline_result.audited_plan,
        pipeline_result.policy_admission,
        pipeline_result.gate_decision,
    ):
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    if (
        pipeline_result.policy_admission.policy_checksum is None
        or pipeline_result.policy_admission.context_authority_checksum is None
        or pipeline_result.policy_admission.safety_case_id is None
    ):
        return (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID,)
    return ()


def _envelope_from_failure(
    *,
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
    status: ExecutionAdapterEnvelopeStatus,
    reasons: tuple[ExecutionAdapterReason, ...],
    terminal_adapter_stage: str,
    forbidden_field_detected: bool,
) -> ExecutionAdapterEnvelope:
    return ExecutionAdapterEnvelope(
        status=status,
        pipeline_receipt_checksum=_pipeline_receipt_checksum(pipeline_result),
        decision_trace_checksum=_decision_trace_checksum(pipeline_result),
        audited_plan_id=_audited_plan_id(pipeline_result),
        plan_checksum=_plan_checksum(pipeline_result),
        policy_checksum=pipeline_result.policy_admission.policy_checksum,
        context_authority_checksum=pipeline_result.policy_admission.context_authority_checksum,
        safety_case_id=pipeline_result.policy_admission.safety_case_id,
        adapter_mapping_checksum=adapter_mapping.adapter_mapping_checksum,
        runtime_target_checksum=target_runtime.runtime_target_checksum,
        ros2_mapping_checksum=adapter_mapping.ros2_mapping.mapping_checksum,
        command_payload={},
        blocked_reasons=tuple(reason.value for reason in reasons),
        terminal_adapter_stage=terminal_adapter_stage,
        payload_field_count=0,
        forbidden_field_detected=forbidden_field_detected,
        qos_profile_checksum=adapter_mapping.ros2_mapping.qos.qos_checksum,
        adapter_authority=adapter_mapping.adapter_authority,
        adapter_mapping=adapter_mapping,
        target_runtime=target_runtime,
    )


def _pipeline_receipt_checksum(pipeline_result: PipelineResult) -> str | None:
    if pipeline_result.approval_receipt is None:
        return None
    return pipeline_result.approval_receipt.approval_receipt_checksum


def _decision_trace_checksum(pipeline_result: PipelineResult) -> str | None:
    if pipeline_result.decision_trace is None:
        return None
    return pipeline_result.decision_trace.trace_checksum


def _audited_plan_id(pipeline_result: PipelineResult) -> str | None:
    if pipeline_result.audited_plan is None:
        return None
    return pipeline_result.audited_plan.audit_id


def _plan_checksum(pipeline_result: PipelineResult) -> str | None:
    if pipeline_result.audited_plan is None:
        return None
    return pipeline_result.audited_plan.checksum


__all__ = ["build_execution_adapter_envelope"]
