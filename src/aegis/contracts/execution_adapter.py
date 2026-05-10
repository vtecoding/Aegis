"""Execution adapter boundary contracts for non-executing runtime envelopes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import cast

from aegis.constants import (
    ADAPTER_CONTRACT_VERSION,
    GATE_VERSION,
    MAX_ADAPTER_CANONICAL_JSON_BYTES,
    MAX_ADAPTER_PAYLOAD_FIELD_COUNT,
    MAX_ADAPTER_STRING_LENGTH,
    PIPELINE_VERSION,
)
from aegis.contracts.approval_receipt import ApprovalReceiptStatus
from aegis.contracts.json_types import FrozenJsonValue, JsonValue, freeze_json_mapping
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.ros2_mapping import Ros2MessageMapping, RuntimeTarget
from aegis.governance.resource_bounds import ResourceBounds, validate_resource_bounds

type CanonicalAdapterValue = (
    str | int | float | bool | None | list[CanonicalAdapterValue] | dict[str, CanonicalAdapterValue]
)

_ADAPTER_RESOURCE_BOUNDS = ResourceBounds(
    max_string_length=MAX_ADAPTER_STRING_LENGTH,
    max_metadata_depth=16,
    max_mapping_width=MAX_ADAPTER_PAYLOAD_FIELD_COUNT,
    max_sequence_length=MAX_ADAPTER_PAYLOAD_FIELD_COUNT,
    max_total_nodes=2_048,
    max_canonical_json_bytes=MAX_ADAPTER_CANONICAL_JSON_BYTES,
    max_trace_stage_count=32,
    max_scenario_count=256,
)


class ExecutionAdapterEnvelopeStatus(StrEnum):
    """Terminal status for a non-executing execution adapter envelope."""

    READY = "ready"
    BLOCKED = "blocked"
    INVALID = "invalid"
    ERROR = "error"


class ExecutionAdapterReason(StrEnum):
    """Stable reason codes emitted by the adapter boundary."""

    EXECUTION_ADAPTER_READY = "EXECUTION_ADAPTER_READY"
    PIPELINE_RESULT_NOT_ALLOWED = "PIPELINE_RESULT_NOT_ALLOWED"
    PIPELINE_RECEIPT_INVALID = "PIPELINE_RECEIPT_INVALID"
    ADAPTER_CAPABILITY_MISMATCH = "ADAPTER_CAPABILITY_MISMATCH"
    ROS2_MAPPING_COMMAND_MISMATCH = "ROS2_MAPPING_COMMAND_MISMATCH"
    ROS2_NAMESPACE_MISMATCH = "ROS2_NAMESPACE_MISMATCH"
    ROS2_QOS_INVALID = "ROS2_QOS_INVALID"
    FORBIDDEN_RUNTIME_FIELD = "FORBIDDEN_RUNTIME_FIELD"
    ADAPTER_REQUIRED_FIELD_MISSING = "ADAPTER_REQUIRED_FIELD_MISSING"
    ADAPTER_FIELD_MAP_INVALID = "ADAPTER_FIELD_MAP_INVALID"
    ADAPTER_MAPPING_CHECKSUM_MISMATCH = "ADAPTER_MAPPING_CHECKSUM_MISMATCH"
    RUNTIME_TARGET_CHECKSUM_MISMATCH = "RUNTIME_TARGET_CHECKSUM_MISMATCH"
    ROS2_MAPPING_CHECKSUM_MISMATCH = "ROS2_MAPPING_CHECKSUM_MISMATCH"
    DIRECT_ADAPTER_BYPASS = "DIRECT_ADAPTER_BYPASS"
    CONFUSABLE_RUNTIME_STRING = "CONFUSABLE_RUNTIME_STRING"
    ADAPTER_PAYLOAD_RESOURCE_EXCEEDED = "ADAPTER_PAYLOAD_RESOURCE_EXCEEDED"
    ADAPTER_RUNTIME_TARGET_MISMATCH = "ADAPTER_RUNTIME_TARGET_MISMATCH"
    ADAPTER_PIPELINE_VERSION_MISMATCH = "ADAPTER_PIPELINE_VERSION_MISMATCH"
    ADAPTER_GATE_VERSION_MISMATCH = "ADAPTER_GATE_VERSION_MISMATCH"
    ADAPTER_POLICY_SCHEMA_MISMATCH = "ADAPTER_POLICY_SCHEMA_MISMATCH"
    ADAPTER_MAPPING_NOT_EFFECTIVE = "ADAPTER_MAPPING_NOT_EFFECTIVE"


@dataclass(frozen=True, slots=True, init=False)
class ExecutionAdapterMapping:
    """Immutable contract binding a runtime target to one ROS 2 mapping."""

    adapter_mapping_id: str
    adapter_mapping_version: str
    runtime_target: RuntimeTarget
    ros2_mapping: Ros2MessageMapping
    accepted_pipeline_version: str
    accepted_gate_version: str
    accepted_policy_schema_version: str
    adapter_authority: str
    effective_from_ms: int
    supersedes_mapping_checksum: str | None
    adapter_mapping_checksum: str

    def __init__(
        self,
        *,
        adapter_mapping_id: str,
        adapter_mapping_version: str,
        runtime_target: object,
        ros2_mapping: object,
        accepted_pipeline_version: str = PIPELINE_VERSION,
        accepted_gate_version: str = GATE_VERSION,
        accepted_policy_schema_version: str = "policy-v1",
        adapter_authority: str,
        effective_from_ms: object,
        supersedes_mapping_checksum: str | None = None,
        adapter_mapping_checksum: str | None = None,
    ) -> None:
        if not isinstance(runtime_target, RuntimeTarget):
            raise ValueError("runtime_target must be a RuntimeTarget")
        if not isinstance(ros2_mapping, Ros2MessageMapping):
            raise ValueError("ros2_mapping must be a Ros2MessageMapping")
        normalized_mapping_id = _normalize_identifier(adapter_mapping_id, "adapter_mapping_id")
        normalized_mapping_version = _normalize_identifier(
            adapter_mapping_version, "adapter_mapping_version"
        )
        normalized_pipeline_version = _normalize_identifier(
            accepted_pipeline_version, "accepted_pipeline_version"
        )
        normalized_gate_version = _normalize_identifier(
            accepted_gate_version, "accepted_gate_version"
        )
        normalized_policy_schema = _normalize_identifier(
            accepted_policy_schema_version, "accepted_policy_schema_version"
        )
        normalized_authority = _normalize_identifier(adapter_authority, "adapter_authority")
        normalized_effective_from_ms = _normalize_non_negative_int(
            effective_from_ms, "effective_from_ms"
        )
        normalized_supersedes = _normalize_optional_checksum(
            supersedes_mapping_checksum, "supersedes_mapping_checksum"
        )
        computed_checksum = execution_adapter_mapping_checksum(
            adapter_mapping_id=normalized_mapping_id,
            adapter_mapping_version=normalized_mapping_version,
            runtime_target_checksum=runtime_target.runtime_target_checksum,
            ros2_mapping_checksum=ros2_mapping.mapping_checksum,
            accepted_pipeline_version=normalized_pipeline_version,
            accepted_gate_version=normalized_gate_version,
            accepted_policy_schema_version=normalized_policy_schema,
            adapter_authority=normalized_authority,
            effective_from_ms=normalized_effective_from_ms,
            supersedes_mapping_checksum=normalized_supersedes,
        )
        normalized_checksum = _normalize_supplied_checksum(
            adapter_mapping_checksum,
            computed_checksum,
            "adapter_mapping_checksum",
        )

        object.__setattr__(self, "adapter_mapping_id", normalized_mapping_id)
        object.__setattr__(self, "adapter_mapping_version", normalized_mapping_version)
        object.__setattr__(self, "runtime_target", runtime_target)
        object.__setattr__(self, "ros2_mapping", ros2_mapping)
        object.__setattr__(self, "accepted_pipeline_version", normalized_pipeline_version)
        object.__setattr__(self, "accepted_gate_version", normalized_gate_version)
        object.__setattr__(self, "accepted_policy_schema_version", normalized_policy_schema)
        object.__setattr__(self, "adapter_authority", normalized_authority)
        object.__setattr__(self, "effective_from_ms", normalized_effective_from_ms)
        object.__setattr__(self, "supersedes_mapping_checksum", normalized_supersedes)
        object.__setattr__(self, "adapter_mapping_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class ExecutionAdapterValidationResult:
    """Pure validation result for adapter mapping and payload construction."""

    status: ExecutionAdapterEnvelopeStatus
    reasons: tuple[ExecutionAdapterReason, ...]
    command_payload: Mapping[str, FrozenJsonValue]
    terminal_adapter_stage: str
    forbidden_field_detected: bool

    def __init__(
        self,
        *,
        status: object,
        reasons: Iterable[ExecutionAdapterReason],
        command_payload: Mapping[str, JsonValue] | None = None,
        terminal_adapter_stage: str,
        forbidden_field_detected: object = False,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reasons = _normalize_reason_tuple(reasons)
        if not isinstance(forbidden_field_detected, bool):
            raise ValueError("forbidden_field_detected must be a bool")
        frozen_payload = freeze_json_mapping(command_payload or {})
        validate_resource_bounds(
            frozen_payload,
            bounds=_ADAPTER_RESOURCE_BOUNDS,
            label="adapter validation payload",
        )
        if normalized_status is ExecutionAdapterEnvelopeStatus.READY and normalized_reasons:
            raise ValueError("READY validation results must not include failure reasons")
        if normalized_status is not ExecutionAdapterEnvelopeStatus.READY and not normalized_reasons:
            raise ValueError("non-ready validation results must include failure reasons")
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reasons", normalized_reasons)
        object.__setattr__(self, "command_payload", frozen_payload)
        object.__setattr__(
            self,
            "terminal_adapter_stage",
            _normalize_stage_name(terminal_adapter_stage, "terminal_adapter_stage"),
        )
        object.__setattr__(self, "forbidden_field_detected", forbidden_field_detected)


@dataclass(frozen=True, slots=True)
class _ReadyEnvelopeAuthorization:
    """Internal proof object required to create a READY adapter envelope."""

    pipeline_result: PipelineResult
    adapter_mapping: ExecutionAdapterMapping
    target_runtime: RuntimeTarget


@dataclass(frozen=True, slots=True, init=False)
class ExecutionAdapterEnvelope:
    """Immutable non-executing envelope handed to a future runtime adapter."""

    status: ExecutionAdapterEnvelopeStatus
    pipeline_receipt_checksum: str | None
    decision_trace_checksum: str | None
    audited_plan_id: str | None
    plan_checksum: str | None
    policy_checksum: str | None
    context_authority_checksum: str | None
    safety_case_id: str | None
    adapter_mapping_checksum: str
    runtime_target_checksum: str
    ros2_mapping_checksum: str
    command_payload: Mapping[str, FrozenJsonValue]
    blocked_reasons: tuple[str, ...]
    terminal_adapter_stage: str
    payload_field_count: int
    forbidden_field_detected: bool
    qos_profile_checksum: str
    adapter_authority: str
    adapter_mapping: ExecutionAdapterMapping | None
    target_runtime: RuntimeTarget | None
    envelope_checksum: str

    def __init__(
        self,
        *,
        status: object,
        pipeline_receipt_checksum: str | None,
        decision_trace_checksum: str | None,
        audited_plan_id: str | None,
        plan_checksum: str | None,
        policy_checksum: str | None,
        context_authority_checksum: str | None,
        safety_case_id: str | None,
        adapter_mapping_checksum: str,
        runtime_target_checksum: str,
        ros2_mapping_checksum: str,
        command_payload: Mapping[str, JsonValue] | None,
        blocked_reasons: Iterable[str],
        terminal_adapter_stage: str,
        payload_field_count: object | None,
        forbidden_field_detected: object,
        qos_profile_checksum: str,
        adapter_authority: str,
        adapter_mapping: object = None,
        target_runtime: object = None,
        envelope_checksum: str | None = None,
        authorization: object = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        frozen_payload = freeze_json_mapping(command_payload or {})
        validate_resource_bounds(
            frozen_payload,
            bounds=_ADAPTER_RESOURCE_BOUNDS,
            label="adapter command payload",
        )
        normalized_payload_count = _normalize_payload_field_count(
            payload_field_count, len(frozen_payload)
        )
        if not isinstance(forbidden_field_detected, bool):
            raise ValueError("forbidden_field_detected must be a bool")
        normalized_reasons = _normalize_blocked_reasons(blocked_reasons)
        normalized_stage = _normalize_stage_name(terminal_adapter_stage, "terminal_adapter_stage")
        normalized_fields = {
            "pipeline_receipt_checksum": _normalize_optional_checksum(
                pipeline_receipt_checksum, "pipeline_receipt_checksum"
            ),
            "decision_trace_checksum": _normalize_optional_checksum(
                decision_trace_checksum, "decision_trace_checksum"
            ),
            "audited_plan_id": _normalize_optional_text(audited_plan_id, "audited_plan_id"),
            "plan_checksum": _normalize_optional_checksum(plan_checksum, "plan_checksum"),
            "policy_checksum": _normalize_optional_checksum(policy_checksum, "policy_checksum"),
            "context_authority_checksum": _normalize_optional_checksum(
                context_authority_checksum, "context_authority_checksum"
            ),
            "safety_case_id": _normalize_optional_text(safety_case_id, "safety_case_id"),
        }
        normalized_adapter_mapping_checksum = _normalize_required_checksum(
            adapter_mapping_checksum, "adapter_mapping_checksum"
        )
        normalized_runtime_target_checksum = _normalize_required_checksum(
            runtime_target_checksum, "runtime_target_checksum"
        )
        normalized_ros2_mapping_checksum = _normalize_required_checksum(
            ros2_mapping_checksum, "ros2_mapping_checksum"
        )
        normalized_qos_checksum = _normalize_required_checksum(
            qos_profile_checksum, "qos_profile_checksum"
        )
        normalized_authority = _normalize_identifier(adapter_authority, "adapter_authority")
        resolved_adapter_mapping = _normalize_optional_adapter_mapping(adapter_mapping)
        resolved_target_runtime = _normalize_optional_runtime_target(target_runtime)

        if normalized_status is ExecutionAdapterEnvelopeStatus.READY:
            if isinstance(authorization, _ReadyEnvelopeAuthorization):
                if resolved_adapter_mapping is None:
                    resolved_adapter_mapping = authorization.adapter_mapping
                if resolved_target_runtime is None:
                    resolved_target_runtime = authorization.target_runtime
            _validate_ready_envelope_authorization(
                authorization=authorization,
                pipeline_receipt_checksum=normalized_fields["pipeline_receipt_checksum"],
                decision_trace_checksum=normalized_fields["decision_trace_checksum"],
                audited_plan_id=normalized_fields["audited_plan_id"],
                plan_checksum=normalized_fields["plan_checksum"],
                policy_checksum=normalized_fields["policy_checksum"],
                context_authority_checksum=normalized_fields["context_authority_checksum"],
                safety_case_id=normalized_fields["safety_case_id"],
                adapter_mapping_checksum=normalized_adapter_mapping_checksum,
                runtime_target_checksum=normalized_runtime_target_checksum,
                ros2_mapping_checksum=normalized_ros2_mapping_checksum,
                qos_profile_checksum=normalized_qos_checksum,
                adapter_authority=normalized_authority,
            )
            if normalized_reasons:
                raise ValueError("READY adapter envelopes must not include blocked_reasons")
            if forbidden_field_detected:
                raise ValueError("READY adapter envelopes must not include forbidden fields")
            if resolved_adapter_mapping is None or resolved_target_runtime is None:
                raise ValueError("READY adapter envelopes require replay evidence")
        else:
            if frozen_payload:
                raise ValueError("non-ready adapter envelopes must not carry command_payload")
            if not normalized_reasons:
                raise ValueError("non-ready adapter envelopes must include blocked_reasons")

        _validate_replay_evidence_bindings(
            adapter_mapping=resolved_adapter_mapping,
            target_runtime=resolved_target_runtime,
            adapter_mapping_checksum=normalized_adapter_mapping_checksum,
            runtime_target_checksum=normalized_runtime_target_checksum,
            ros2_mapping_checksum=normalized_ros2_mapping_checksum,
            qos_profile_checksum=normalized_qos_checksum,
            adapter_authority=normalized_authority,
        )

        computed_checksum = execution_adapter_envelope_checksum(
            status=normalized_status,
            pipeline_receipt_checksum=normalized_fields["pipeline_receipt_checksum"],
            decision_trace_checksum=normalized_fields["decision_trace_checksum"],
            audited_plan_id=normalized_fields["audited_plan_id"],
            plan_checksum=normalized_fields["plan_checksum"],
            policy_checksum=normalized_fields["policy_checksum"],
            context_authority_checksum=normalized_fields["context_authority_checksum"],
            safety_case_id=normalized_fields["safety_case_id"],
            adapter_mapping_checksum=normalized_adapter_mapping_checksum,
            runtime_target_checksum=normalized_runtime_target_checksum,
            ros2_mapping_checksum=normalized_ros2_mapping_checksum,
            command_payload=frozen_payload,
            blocked_reasons=normalized_reasons,
            terminal_adapter_stage=normalized_stage,
            payload_field_count=normalized_payload_count,
            forbidden_field_detected=forbidden_field_detected,
            qos_profile_checksum=normalized_qos_checksum,
            adapter_authority=normalized_authority,
        )
        normalized_checksum = _normalize_supplied_checksum(
            envelope_checksum, computed_checksum, "envelope_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        for field_name, field_value in normalized_fields.items():
            object.__setattr__(self, field_name, field_value)
        object.__setattr__(self, "adapter_mapping_checksum", normalized_adapter_mapping_checksum)
        object.__setattr__(self, "runtime_target_checksum", normalized_runtime_target_checksum)
        object.__setattr__(self, "ros2_mapping_checksum", normalized_ros2_mapping_checksum)
        object.__setattr__(self, "command_payload", frozen_payload)
        object.__setattr__(self, "blocked_reasons", normalized_reasons)
        object.__setattr__(self, "terminal_adapter_stage", normalized_stage)
        object.__setattr__(self, "payload_field_count", normalized_payload_count)
        object.__setattr__(self, "forbidden_field_detected", forbidden_field_detected)
        object.__setattr__(self, "qos_profile_checksum", normalized_qos_checksum)
        object.__setattr__(self, "adapter_authority", normalized_authority)
        object.__setattr__(self, "adapter_mapping", resolved_adapter_mapping)
        object.__setattr__(self, "target_runtime", resolved_target_runtime)
        object.__setattr__(self, "envelope_checksum", normalized_checksum)


def execution_adapter_mapping_checksum(
    *,
    adapter_mapping_id: str,
    adapter_mapping_version: str,
    runtime_target_checksum: str,
    ros2_mapping_checksum: str,
    accepted_pipeline_version: str,
    accepted_gate_version: str,
    accepted_policy_schema_version: str,
    adapter_authority: str,
    effective_from_ms: int,
    supersedes_mapping_checksum: str | None,
) -> str:
    """Return the deterministic checksum for an execution adapter mapping."""
    return _sha256(
        {
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "adapter_mapping_id": adapter_mapping_id,
            "adapter_mapping_version": adapter_mapping_version,
            "runtime_target_checksum": runtime_target_checksum,
            "ros2_mapping_checksum": ros2_mapping_checksum,
            "accepted_pipeline_version": accepted_pipeline_version,
            "accepted_gate_version": accepted_gate_version,
            "accepted_policy_schema_version": accepted_policy_schema_version,
            "adapter_authority": adapter_authority,
            "effective_from_ms": effective_from_ms,
            "supersedes_mapping_checksum": supersedes_mapping_checksum,
        }
    )


def execution_adapter_envelope_checksum(
    *,
    status: ExecutionAdapterEnvelopeStatus,
    pipeline_receipt_checksum: str | None,
    decision_trace_checksum: str | None,
    audited_plan_id: str | None,
    plan_checksum: str | None,
    policy_checksum: str | None,
    context_authority_checksum: str | None,
    safety_case_id: str | None,
    adapter_mapping_checksum: str,
    runtime_target_checksum: str,
    ros2_mapping_checksum: str,
    command_payload: Mapping[str, FrozenJsonValue],
    blocked_reasons: Iterable[str],
    terminal_adapter_stage: str,
    payload_field_count: int,
    forbidden_field_detected: bool,
    qos_profile_checksum: str,
    adapter_authority: str,
) -> str:
    """Return the deterministic checksum for an adapter envelope."""
    return _sha256(
        {
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "status": status.value,
            "pipeline_receipt_checksum": pipeline_receipt_checksum,
            "decision_trace_checksum": decision_trace_checksum,
            "audited_plan_id": audited_plan_id,
            "plan_checksum": plan_checksum,
            "policy_checksum": policy_checksum,
            "context_authority_checksum": context_authority_checksum,
            "safety_case_id": safety_case_id,
            "adapter_mapping_checksum": adapter_mapping_checksum,
            "runtime_target_checksum": runtime_target_checksum,
            "ros2_mapping_checksum": ros2_mapping_checksum,
            "command_payload": _canonical_json_mapping(command_payload),
            "blocked_reasons": list(blocked_reasons),
            "terminal_adapter_stage": terminal_adapter_stage,
            "payload_field_count": payload_field_count,
            "forbidden_field_detected": forbidden_field_detected,
            "qos_profile_checksum": qos_profile_checksum,
            "adapter_authority": adapter_authority,
        }
    )


def recompute_execution_adapter_mapping_checksum(mapping: ExecutionAdapterMapping) -> str:
    """Recompute an ExecutionAdapterMapping checksum from its authoritative fields."""
    return execution_adapter_mapping_checksum(
        adapter_mapping_id=mapping.adapter_mapping_id,
        adapter_mapping_version=mapping.adapter_mapping_version,
        runtime_target_checksum=mapping.runtime_target.runtime_target_checksum,
        ros2_mapping_checksum=mapping.ros2_mapping.mapping_checksum,
        accepted_pipeline_version=mapping.accepted_pipeline_version,
        accepted_gate_version=mapping.accepted_gate_version,
        accepted_policy_schema_version=mapping.accepted_policy_schema_version,
        adapter_authority=mapping.adapter_authority,
        effective_from_ms=mapping.effective_from_ms,
        supersedes_mapping_checksum=mapping.supersedes_mapping_checksum,
    )


def recompute_execution_adapter_envelope_checksum(envelope: ExecutionAdapterEnvelope) -> str:
    """Recompute an ExecutionAdapterEnvelope checksum from its authoritative fields."""
    return execution_adapter_envelope_checksum(
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


def make_ready_envelope_authorization(
    *,
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
) -> _ReadyEnvelopeAuthorization:
    """Return the internal authorization required for a READY envelope."""
    return _ReadyEnvelopeAuthorization(
        pipeline_result=pipeline_result,
        adapter_mapping=adapter_mapping,
        target_runtime=target_runtime,
    )


def _validate_ready_envelope_authorization(
    *,
    authorization: object,
    pipeline_receipt_checksum: str | None,
    decision_trace_checksum: str | None,
    audited_plan_id: str | None,
    plan_checksum: str | None,
    policy_checksum: str | None,
    context_authority_checksum: str | None,
    safety_case_id: str | None,
    adapter_mapping_checksum: str,
    runtime_target_checksum: str,
    ros2_mapping_checksum: str,
    qos_profile_checksum: str,
    adapter_authority: str,
) -> None:
    if not isinstance(authorization, _ReadyEnvelopeAuthorization):
        raise ValueError(ExecutionAdapterReason.DIRECT_ADAPTER_BYPASS.value)
    pipeline_result = authorization.pipeline_result
    if pipeline_result.outcome is not PipelineOutcome.ALLOWED:
        raise ValueError("READY adapter envelopes require an allowed PipelineResult")
    if (
        pipeline_result.approval_receipt is None
        or pipeline_result.decision_trace is None
        or pipeline_result.receipt_validation is None
        or pipeline_result.audited_plan is None
    ):
        raise ValueError("READY adapter envelopes require complete pipeline evidence")
    if pipeline_result.approval_receipt.status is not ApprovalReceiptStatus.VALID:
        raise ValueError("READY adapter envelopes require a valid approval receipt")
    if pipeline_result.receipt_validation.status is not ApprovalReceiptStatus.VALID:
        raise ValueError("READY adapter envelopes require valid receipt validation")
    expected_values = {
        "pipeline_receipt_checksum": pipeline_result.approval_receipt.approval_receipt_checksum,
        "decision_trace_checksum": pipeline_result.decision_trace.trace_checksum,
        "audited_plan_id": pipeline_result.audited_plan.audit_id,
        "plan_checksum": pipeline_result.audited_plan.checksum,
        "policy_checksum": pipeline_result.policy_admission.policy_checksum,
        "context_authority_checksum": pipeline_result.policy_admission.context_authority_checksum,
        "safety_case_id": pipeline_result.policy_admission.safety_case_id,
        "adapter_mapping_checksum": authorization.adapter_mapping.adapter_mapping_checksum,
        "runtime_target_checksum": authorization.target_runtime.runtime_target_checksum,
        "ros2_mapping_checksum": authorization.adapter_mapping.ros2_mapping.mapping_checksum,
        "qos_profile_checksum": authorization.adapter_mapping.ros2_mapping.qos.qos_checksum,
        "adapter_authority": authorization.adapter_mapping.adapter_authority,
    }
    observed_values = {
        "pipeline_receipt_checksum": pipeline_receipt_checksum,
        "decision_trace_checksum": decision_trace_checksum,
        "audited_plan_id": audited_plan_id,
        "plan_checksum": plan_checksum,
        "policy_checksum": policy_checksum,
        "context_authority_checksum": context_authority_checksum,
        "safety_case_id": safety_case_id,
        "adapter_mapping_checksum": adapter_mapping_checksum,
        "runtime_target_checksum": runtime_target_checksum,
        "ros2_mapping_checksum": ros2_mapping_checksum,
        "qos_profile_checksum": qos_profile_checksum,
        "adapter_authority": adapter_authority,
    }
    if any(
        observed_values[field_name] != expected_values[field_name] for field_name in observed_values
    ):
        raise ValueError("READY adapter envelope evidence must match authorization")


def _normalize_status(value: object) -> ExecutionAdapterEnvelopeStatus:
    if isinstance(value, ExecutionAdapterEnvelopeStatus):
        return value
    if not isinstance(value, str):
        raise ValueError("status must be an ExecutionAdapterEnvelopeStatus")
    if value != value.strip():
        raise ValueError("status must not contain leading or trailing whitespace")
    try:
        return ExecutionAdapterEnvelopeStatus(value)
    except ValueError:
        raise ValueError("status must be a valid ExecutionAdapterEnvelopeStatus") from None


def _normalize_reason_tuple(
    values: Iterable[object],
) -> tuple[ExecutionAdapterReason, ...]:
    if isinstance(values, str):
        raise ValueError("reasons must be an iterable of ExecutionAdapterReason values")
    normalized: list[ExecutionAdapterReason] = []
    for value in values:
        if not isinstance(value, ExecutionAdapterReason):
            raise ValueError("reasons must contain ExecutionAdapterReason values")
        normalized.append(value)
    return tuple(dict.fromkeys(normalized))


def _normalize_blocked_reasons(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError("blocked_reasons must be an iterable of reason strings")
    normalized: list[str] = []
    for value in values:
        text = _normalize_required_text(value, "blocked_reasons")
        if fullmatch(r"[A-Z][A-Z0-9_]*", text) is None:
            raise ValueError("blocked_reasons must be uppercase machine reason codes")
        normalized.append(text)
    return tuple(dict.fromkeys(normalized))


def _normalize_identifier(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical adapter identifier")
    return normalized


def _normalize_optional_adapter_mapping(value: object) -> ExecutionAdapterMapping | None:
    if value is None:
        return None
    if not isinstance(value, ExecutionAdapterMapping):
        raise ValueError("adapter_mapping must be an ExecutionAdapterMapping")
    return value


def _normalize_optional_runtime_target(value: object) -> RuntimeTarget | None:
    if value is None:
        return None
    if not isinstance(value, RuntimeTarget):
        raise ValueError("target_runtime must be a RuntimeTarget")
    return value


def _validate_replay_evidence_bindings(
    *,
    adapter_mapping: ExecutionAdapterMapping | None,
    target_runtime: RuntimeTarget | None,
    adapter_mapping_checksum: str,
    runtime_target_checksum: str,
    ros2_mapping_checksum: str,
    qos_profile_checksum: str,
    adapter_authority: str,
) -> None:
    if adapter_mapping is not None:
        if adapter_mapping.adapter_mapping_checksum != adapter_mapping_checksum:
            raise ValueError("adapter_mapping must match adapter_mapping_checksum")
        if adapter_mapping.ros2_mapping.mapping_checksum != ros2_mapping_checksum:
            raise ValueError("adapter_mapping must match ros2_mapping_checksum")
        if adapter_mapping.ros2_mapping.qos.qos_checksum != qos_profile_checksum:
            raise ValueError("adapter_mapping must match qos_profile_checksum")
        if adapter_mapping.adapter_authority != adapter_authority:
            raise ValueError("adapter_mapping must match adapter_authority")
    if (
        target_runtime is not None
        and target_runtime.runtime_target_checksum != runtime_target_checksum
    ):
        raise ValueError("target_runtime must match runtime_target_checksum")


def _normalize_stage_name(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[a-z][a-z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical adapter stage name")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    if len(normalized) > MAX_ADAPTER_STRING_LENGTH:
        raise ValueError(f"{field_name} exceeds max adapter string length")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must be ASCII") from exc
    if any(character.isspace() for character in normalized):
        raise ValueError(f"{field_name} must not contain whitespace")
    return normalized


def _normalize_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_payload_field_count(value: object | None, expected_count: int) -> int:
    if value is None:
        return expected_count
    normalized = _normalize_non_negative_int(value, "payload_field_count")
    if normalized != expected_count:
        raise ValueError("payload_field_count must equal len(command_payload)")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if len(normalized) != 64 or not all(
        character in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied_checksum, field_name)
    if normalized is None:
        return computed_checksum
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _canonical_json_mapping(
    values: Mapping[str, FrozenJsonValue],
) -> dict[str, CanonicalAdapterValue]:
    return {key: _canonical_json_value(values[key]) for key in sorted(values)}


def _canonical_json_value(value: FrozenJsonValue) -> CanonicalAdapterValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, Mapping):
        return _canonical_json_mapping(cast(Mapping[str, FrozenJsonValue], value))
    tuple_value = cast(tuple[FrozenJsonValue, ...], value)
    return [_canonical_json_value(item) for item in tuple_value]


def _sha256(payload: Mapping[str, CanonicalAdapterValue]) -> str:
    canonical = json.dumps(
        _canonical_adapter_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_adapter_mapping(
    values: Mapping[str, CanonicalAdapterValue],
) -> dict[str, CanonicalAdapterValue]:
    return {key: _canonical_adapter_value(values[key]) for key in sorted(values)}


def _canonical_adapter_value(value: CanonicalAdapterValue) -> CanonicalAdapterValue:
    if isinstance(value, Mapping):
        return _canonical_adapter_mapping(cast(Mapping[str, CanonicalAdapterValue], value))
    if isinstance(value, list):
        return [_canonical_adapter_value(item) for item in value]
    return value


__all__ = [
    "ExecutionAdapterEnvelope",
    "ExecutionAdapterEnvelopeStatus",
    "ExecutionAdapterMapping",
    "ExecutionAdapterReason",
    "ExecutionAdapterValidationResult",
    "execution_adapter_envelope_checksum",
    "execution_adapter_mapping_checksum",
    "make_ready_envelope_authorization",
    "recompute_execution_adapter_envelope_checksum",
    "recompute_execution_adapter_mapping_checksum",
]
