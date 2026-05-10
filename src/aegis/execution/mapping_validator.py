"""Pure execution adapter mapping validation and payload construction."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from aegis.constants import GATE_VERSION, MAX_ADAPTER_PAYLOAD_FIELD_COUNT, PIPELINE_VERSION
from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterMapping,
    ExecutionAdapterReason,
    ExecutionAdapterValidationResult,
    recompute_execution_adapter_mapping_checksum,
)
from aegis.contracts.json_types import FrozenJsonValue, JsonValue
from aegis.contracts.pipeline import PipelineResult
from aegis.contracts.planning import CommandStep
from aegis.contracts.ros2_mapping import (
    DANGEROUS_RUNTIME_OVERRIDE_FIELDS,
    RuntimeTarget,
)
from aegis.execution.ros2_mapping_validator import validate_ros2_message_mapping
from aegis.governance.resource_bounds import validate_resource_bounds


def validate_execution_adapter_mapping(
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
) -> ExecutionAdapterValidationResult:
    """Validate adapter mapping evidence and construct the mapped payload.

    Args:
        pipeline_result: Already allowed and receipt-valid pipeline result.
        adapter_mapping: Explicit adapter mapping contract to validate.
        target_runtime: Runtime target selected by the caller.

    Returns:
        A deterministic validation result. READY results carry a frozen command
        payload; non-ready results carry no payload.
    """
    reasons = list(_mapping_identity_reasons(pipeline_result, adapter_mapping, target_runtime))
    reasons.extend(validate_ros2_message_mapping(adapter_mapping.ros2_mapping, target_runtime))
    if reasons:
        return _failure_result(reasons, "mapping_validator")

    payload_result = _mapped_payload(pipeline_result, adapter_mapping)
    if payload_result.reasons:
        return payload_result
    return payload_result


def _mapping_identity_reasons(
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
) -> tuple[ExecutionAdapterReason, ...]:
    reasons: list[ExecutionAdapterReason] = []
    if adapter_mapping.adapter_mapping_checksum != recompute_execution_adapter_mapping_checksum(
        adapter_mapping
    ):
        reasons.append(ExecutionAdapterReason.ADAPTER_MAPPING_CHECKSUM_MISMATCH)
    if (
        adapter_mapping.runtime_target.runtime_target_checksum
        != target_runtime.runtime_target_checksum
    ):
        reasons.append(ExecutionAdapterReason.ADAPTER_RUNTIME_TARGET_MISMATCH)
    if adapter_mapping.accepted_pipeline_version != PIPELINE_VERSION:
        reasons.append(ExecutionAdapterReason.ADAPTER_PIPELINE_VERSION_MISMATCH)
    if adapter_mapping.accepted_gate_version != GATE_VERSION:
        reasons.append(ExecutionAdapterReason.ADAPTER_GATE_VERSION_MISMATCH)
    if (
        pipeline_result.policy_admission.policy_schema_version is None
        or adapter_mapping.accepted_policy_schema_version
        != pipeline_result.policy_admission.policy_schema_version
    ):
        reasons.append(ExecutionAdapterReason.ADAPTER_POLICY_SCHEMA_MISMATCH)
    evaluation_time_ms = pipeline_result.policy_admission.context_evaluation_time_ms
    if evaluation_time_ms is not None and adapter_mapping.effective_from_ms > evaluation_time_ms:
        reasons.append(ExecutionAdapterReason.ADAPTER_MAPPING_NOT_EFFECTIVE)
    if pipeline_result.audited_plan is None or not pipeline_result.audited_plan.plan.steps:
        reasons.append(ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID)
        return tuple(dict.fromkeys(reasons))
    step = pipeline_result.audited_plan.plan.steps[0]
    if adapter_mapping.ros2_mapping.source_command != step.step_type.value:
        reasons.append(ExecutionAdapterReason.ROS2_MAPPING_COMMAND_MISMATCH)
    if (
        pipeline_result.policy_admission.capability_name is None
        or adapter_mapping.ros2_mapping.source_capability
        != pipeline_result.policy_admission.capability_name
    ):
        reasons.append(ExecutionAdapterReason.ADAPTER_CAPABILITY_MISMATCH)
    return tuple(dict.fromkeys(reasons))


def _mapped_payload(
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
) -> ExecutionAdapterValidationResult:
    if pipeline_result.audited_plan is None:
        return _failure_result(
            [ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID],
            "payload_mapper",
        )
    step = pipeline_result.audited_plan.plan.steps[0]
    forbidden_fields = frozenset(adapter_mapping.ros2_mapping.forbidden_fields).union(
        DANGEROUS_RUNTIME_OVERRIDE_FIELDS
    )
    if _contains_forbidden_field(step.parameters, forbidden_fields):
        return _failure_result(
            [ExecutionAdapterReason.FORBIDDEN_RUNTIME_FIELD],
            "payload_mapper",
            forbidden_field_detected=True,
        )

    payload: dict[str, JsonValue] = {}
    missing_required: list[str] = []
    invalid_sources: list[str] = []
    for required_source in adapter_mapping.ros2_mapping.required_fields:
        if not _source_path_exists(step, required_source):
            missing_required.append(required_source)
    for source_path, target_field in adapter_mapping.ros2_mapping.field_map.items():
        source_value = _extract_source_value(step, source_path)
        if source_value is None:
            invalid_sources.append(source_path)
            continue
        if _field_is_forbidden(target_field, forbidden_fields):
            return _failure_result(
                [ExecutionAdapterReason.FORBIDDEN_RUNTIME_FIELD],
                "payload_mapper",
                forbidden_field_detected=True,
            )
        payload[target_field] = _json_value_from_frozen(source_value)

    if missing_required:
        return _failure_result(
            [ExecutionAdapterReason.ADAPTER_REQUIRED_FIELD_MISSING],
            "payload_mapper",
        )
    if invalid_sources:
        return _failure_result(
            [ExecutionAdapterReason.ADAPTER_FIELD_MAP_INVALID],
            "payload_mapper",
            status=ExecutionAdapterEnvelopeStatus.INVALID,
        )
    if len(payload) > MAX_ADAPTER_PAYLOAD_FIELD_COUNT:
        return _failure_result(
            [ExecutionAdapterReason.ADAPTER_PAYLOAD_RESOURCE_EXCEEDED],
            "payload_mapper",
            status=ExecutionAdapterEnvelopeStatus.INVALID,
        )
    try:
        validate_resource_bounds(payload, label="adapter command payload")
    except ValueError:
        return _failure_result(
            [ExecutionAdapterReason.ADAPTER_PAYLOAD_RESOURCE_EXCEEDED],
            "payload_mapper",
            status=ExecutionAdapterEnvelopeStatus.INVALID,
        )
    return ExecutionAdapterValidationResult(
        status=ExecutionAdapterEnvelopeStatus.READY,
        reasons=(),
        command_payload=payload,
        terminal_adapter_stage="payload_mapper",
        forbidden_field_detected=False,
    )


def _failure_result(
    reasons: list[ExecutionAdapterReason],
    terminal_stage: str,
    *,
    status: ExecutionAdapterEnvelopeStatus | None = None,
    forbidden_field_detected: bool = False,
) -> ExecutionAdapterValidationResult:
    resolved_status = status or _status_for_reasons(reasons)
    return ExecutionAdapterValidationResult(
        status=resolved_status,
        reasons=tuple(dict.fromkeys(reasons)),
        command_payload={},
        terminal_adapter_stage=terminal_stage,
        forbidden_field_detected=forbidden_field_detected,
    )


def _status_for_reasons(
    reasons: list[ExecutionAdapterReason],
) -> ExecutionAdapterEnvelopeStatus:
    invalid_reasons = {
        ExecutionAdapterReason.ADAPTER_MAPPING_CHECKSUM_MISMATCH,
        ExecutionAdapterReason.RUNTIME_TARGET_CHECKSUM_MISMATCH,
        ExecutionAdapterReason.ROS2_MAPPING_CHECKSUM_MISMATCH,
        ExecutionAdapterReason.ROS2_QOS_INVALID,
        ExecutionAdapterReason.ADAPTER_FIELD_MAP_INVALID,
        ExecutionAdapterReason.ADAPTER_PAYLOAD_RESOURCE_EXCEEDED,
    }
    if any(reason in invalid_reasons for reason in reasons):
        return ExecutionAdapterEnvelopeStatus.INVALID
    return ExecutionAdapterEnvelopeStatus.BLOCKED


def _source_path_exists(step: CommandStep, source_path: str) -> bool:
    return _extract_source_value(step, source_path) is not None


def _extract_source_value(step: CommandStep, source_path: str) -> FrozenJsonValue | None:
    if source_path == "step_type":
        return step.step_type.value
    if source_path == "sequence":
        return step.sequence
    if not source_path.startswith("parameters."):
        return None
    current: FrozenJsonValue = step.parameters
    for path_part in source_path.removeprefix("parameters.").split("."):
        if not isinstance(current, Mapping):
            return None
        current_mapping = cast(Mapping[str, FrozenJsonValue], current)
        if path_part not in current_mapping:
            return None
        current = current_mapping[path_part]
    return current


def _contains_forbidden_field(
    value: FrozenJsonValue,
    forbidden_fields: frozenset[str],
    *,
    path: str | None = None,
) -> bool:
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, FrozenJsonValue], value)
        for key, item in mapping.items():
            current_path = key if path is None else f"{path}.{key}"
            if _field_is_forbidden(current_path, forbidden_fields):
                return True
            if _contains_forbidden_field(item, forbidden_fields, path=current_path):
                return True
    if isinstance(value, tuple):
        return any(_contains_forbidden_field(item, forbidden_fields, path=path) for item in value)
    return False


def _field_is_forbidden(field_path: str, forbidden_fields: frozenset[str]) -> bool:
    field_parts = field_path.split(".")
    return field_path in forbidden_fields or any(part in forbidden_fields for part in field_parts)


def _json_value_from_frozen(value: FrozenJsonValue) -> JsonValue:
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
        mapping = cast(Mapping[str, FrozenJsonValue], value)
        return {key: _json_value_from_frozen(mapping[key]) for key in sorted(mapping)}
    tuple_value = cast(tuple[FrozenJsonValue, ...], value)
    return [_json_value_from_frozen(item) for item in tuple_value]


__all__ = ["validate_execution_adapter_mapping"]
