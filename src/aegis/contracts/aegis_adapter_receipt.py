"""Adapter receipt contracts for non-executing execution envelopes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from aegis.aegis_constants import ADAPTER_CONTRACT_VERSION
from aegis.contracts.aegis_execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
)

type CanonicalAdapterReceiptValue = str | bool | None | dict[str, str | bool | None]


@dataclass(frozen=True, slots=True, init=False)
class AdapterReceipt:
    """Checksum-bound receipt for one execution adapter envelope."""

    status: ExecutionAdapterEnvelopeStatus
    reason: str
    pipeline_receipt_checksum: str | None
    decision_trace_checksum: str | None
    adapter_mapping_checksum: str
    runtime_target_checksum: str
    ros2_mapping_checksum: str
    envelope_checksum: str
    adapter_receipt_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason: str,
        pipeline_receipt_checksum: str | None,
        decision_trace_checksum: str | None,
        adapter_mapping_checksum: str,
        runtime_target_checksum: str,
        ros2_mapping_checksum: str,
        envelope_checksum: str,
        adapter_receipt_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason)
        normalized_pipeline_receipt = _normalize_optional_checksum(
            pipeline_receipt_checksum, "pipeline_receipt_checksum"
        )
        normalized_decision_trace = _normalize_optional_checksum(
            decision_trace_checksum, "decision_trace_checksum"
        )
        normalized_adapter_mapping = _normalize_required_checksum(
            adapter_mapping_checksum, "adapter_mapping_checksum"
        )
        normalized_runtime_target = _normalize_required_checksum(
            runtime_target_checksum, "runtime_target_checksum"
        )
        normalized_ros2_mapping = _normalize_required_checksum(
            ros2_mapping_checksum, "ros2_mapping_checksum"
        )
        normalized_envelope = _normalize_required_checksum(envelope_checksum, "envelope_checksum")
        computed_checksum = adapter_receipt_checksum_value(
            status=normalized_status,
            reason=normalized_reason,
            pipeline_receipt_checksum=normalized_pipeline_receipt,
            decision_trace_checksum=normalized_decision_trace,
            adapter_mapping_checksum=normalized_adapter_mapping,
            runtime_target_checksum=normalized_runtime_target,
            ros2_mapping_checksum=normalized_ros2_mapping,
            envelope_checksum=normalized_envelope,
        )
        normalized_checksum = _normalize_supplied_checksum(
            adapter_receipt_checksum,
            computed_checksum,
            "adapter_receipt_checksum",
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "pipeline_receipt_checksum", normalized_pipeline_receipt)
        object.__setattr__(self, "decision_trace_checksum", normalized_decision_trace)
        object.__setattr__(self, "adapter_mapping_checksum", normalized_adapter_mapping)
        object.__setattr__(self, "runtime_target_checksum", normalized_runtime_target)
        object.__setattr__(self, "ros2_mapping_checksum", normalized_ros2_mapping)
        object.__setattr__(self, "envelope_checksum", normalized_envelope)
        object.__setattr__(self, "adapter_receipt_checksum", normalized_checksum)


def build_adapter_receipt(envelope: ExecutionAdapterEnvelope) -> AdapterReceipt:
    """Build an AdapterReceipt for a constructed adapter envelope."""
    reason = (
        "EXECUTION_ADAPTER_READY"
        if envelope.status is ExecutionAdapterEnvelopeStatus.READY
        else envelope.blocked_reasons[0]
    )
    return AdapterReceipt(
        status=envelope.status,
        reason=reason,
        pipeline_receipt_checksum=envelope.pipeline_receipt_checksum,
        decision_trace_checksum=envelope.decision_trace_checksum,
        adapter_mapping_checksum=envelope.adapter_mapping_checksum,
        runtime_target_checksum=envelope.runtime_target_checksum,
        ros2_mapping_checksum=envelope.ros2_mapping_checksum,
        envelope_checksum=envelope.envelope_checksum,
    )


def adapter_receipt_checksum_value(
    *,
    status: ExecutionAdapterEnvelopeStatus,
    reason: str,
    pipeline_receipt_checksum: str | None,
    decision_trace_checksum: str | None,
    adapter_mapping_checksum: str,
    runtime_target_checksum: str,
    ros2_mapping_checksum: str,
    envelope_checksum: str,
) -> str:
    """Return the deterministic checksum for an adapter receipt."""
    return _sha256(
        {
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
            "status": status.value,
            "reason": reason,
            "pipeline_receipt_checksum": pipeline_receipt_checksum,
            "decision_trace_checksum": decision_trace_checksum,
            "adapter_mapping_checksum": adapter_mapping_checksum,
            "runtime_target_checksum": runtime_target_checksum,
            "ros2_mapping_checksum": ros2_mapping_checksum,
            "envelope_checksum": envelope_checksum,
        }
    )


def recompute_adapter_receipt_checksum(receipt: AdapterReceipt) -> str:
    """Recompute an AdapterReceipt checksum from its authoritative fields."""
    return adapter_receipt_checksum_value(
        status=receipt.status,
        reason=receipt.reason,
        pipeline_receipt_checksum=receipt.pipeline_receipt_checksum,
        decision_trace_checksum=receipt.decision_trace_checksum,
        adapter_mapping_checksum=receipt.adapter_mapping_checksum,
        runtime_target_checksum=receipt.runtime_target_checksum,
        ros2_mapping_checksum=receipt.ros2_mapping_checksum,
        envelope_checksum=receipt.envelope_checksum,
    )


def _normalize_status(value: object) -> ExecutionAdapterEnvelopeStatus:
    if isinstance(value, ExecutionAdapterEnvelopeStatus):
        return value
    if not isinstance(value, str):
        raise ValueError("status must be an ExecutionAdapterEnvelopeStatus")
    try:
        return ExecutionAdapterEnvelopeStatus(value)
    except ValueError:
        raise ValueError("status must be a valid ExecutionAdapterEnvelopeStatus") from None


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason must be an uppercase machine reason code")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
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


def _sha256(payload: Mapping[str, CanonicalAdapterReceiptValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "AdapterReceipt",
    "adapter_receipt_checksum_value",
    "build_adapter_receipt",
    "recompute_adapter_receipt_checksum",
]
