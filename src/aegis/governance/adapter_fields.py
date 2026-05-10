"""Execution adapter authority manifests for ADR-0015 drift checks."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.adapter_receipt import AdapterReceipt
from aegis.contracts.execution_adapter import ExecutionAdapterEnvelope, ExecutionAdapterMapping
from aegis.contracts.ros2_mapping import Ros2MessageMapping, Ros2QoSProfileSpec, RuntimeTarget


@dataclass(frozen=True, slots=True)
class AdapterAuthorityFieldManifest:
    """Static classification for one adapter boundary contract."""

    contract_name: str
    authoritative_fields: tuple[str, ...]
    checksum_function: str
    reason: str


@dataclass(frozen=True, slots=True)
class AdapterAuthorityContract:
    """Adapter contract type paired with its static authority manifest."""

    contract_type: type[object]
    manifest: AdapterAuthorityFieldManifest


def adapter_manifest_for(
    *,
    contract_type: type[object],
    authoritative_fields: tuple[str, ...],
    checksum_function: str,
    reason: str,
) -> AdapterAuthorityContract:
    """Return an adapter authority manifest without mutating global state."""
    return AdapterAuthorityContract(
        contract_type=contract_type,
        manifest=AdapterAuthorityFieldManifest(
            contract_name=contract_type.__name__,
            authoritative_fields=authoritative_fields,
            checksum_function=checksum_function,
            reason=reason,
        ),
    )


ADAPTER_AUTHORITY_CONTRACTS = (
    adapter_manifest_for(
        contract_type=RuntimeTarget,
        authoritative_fields=(
            "runtime_kind",
            "runtime_id",
            "runtime_version",
            "deployment_domain",
            "target_namespace",
            "target_robot_id",
            "runtime_authority",
            "runtime_target_checksum",
        ),
        checksum_function="runtime_target_checksum_value",
        reason="runtime target identity is adapter evidence, not permission",
    ),
    adapter_manifest_for(
        contract_type=Ros2QoSProfileSpec,
        authoritative_fields=(
            "reliability",
            "durability",
            "history",
            "depth",
            "deadline_ms",
            "lifespan_ms",
            "liveliness",
            "lease_duration_ms",
            "qos_checksum",
        ),
        checksum_function="ros2_qos_profile_checksum",
        reason="QoS is explicit adapter evidence and no middleware defaults are trusted",
    ),
    adapter_manifest_for(
        contract_type=Ros2MessageMapping,
        authoritative_fields=(
            "mapping_id",
            "mapping_version",
            "source_command",
            "source_capability",
            "primitive",
            "package_name",
            "message_type",
            "topic_or_service_name",
            "namespace",
            "frame_id",
            "qos",
            "field_map",
            "required_fields",
            "forbidden_fields",
            "mapping_authority",
            "mapping_checksum",
        ),
        checksum_function="ros2_message_mapping_checksum",
        reason="ROS 2 mapping evidence decides how abstract commands may be represented",
    ),
    adapter_manifest_for(
        contract_type=ExecutionAdapterMapping,
        authoritative_fields=(
            "adapter_mapping_id",
            "adapter_mapping_version",
            "runtime_target",
            "ros2_mapping",
            "accepted_pipeline_version",
            "accepted_gate_version",
            "accepted_policy_schema_version",
            "adapter_authority",
            "effective_from_ms",
            "supersedes_mapping_checksum",
            "adapter_mapping_checksum",
        ),
        checksum_function="execution_adapter_mapping_checksum",
        reason="adapter mappings bind runtime and ROS 2 evidence to Phase 2 authority",
    ),
    adapter_manifest_for(
        contract_type=ExecutionAdapterEnvelope,
        authoritative_fields=(
            "status",
            "pipeline_receipt_checksum",
            "decision_trace_checksum",
            "audited_plan_id",
            "plan_checksum",
            "policy_checksum",
            "context_authority_checksum",
            "safety_case_id",
            "adapter_mapping_checksum",
            "runtime_target_checksum",
            "ros2_mapping_checksum",
            "command_payload",
            "blocked_reasons",
            "terminal_adapter_stage",
            "payload_field_count",
            "forbidden_field_detected",
            "qos_profile_checksum",
            "adapter_authority",
            "envelope_checksum",
        ),
        checksum_function="execution_adapter_envelope_checksum",
        reason="adapter envelopes are the non-executing boundary packet for future runtimes",
    ),
    adapter_manifest_for(
        contract_type=AdapterReceipt,
        authoritative_fields=(
            "status",
            "reason",
            "pipeline_receipt_checksum",
            "decision_trace_checksum",
            "adapter_mapping_checksum",
            "runtime_target_checksum",
            "ros2_mapping_checksum",
            "envelope_checksum",
            "adapter_receipt_checksum",
        ),
        checksum_function="adapter_receipt_checksum_value",
        reason="adapter receipts bind envelope evidence for later observability export",
    ),
)
"""Closed ADR-0015 adapter authority contract manifest registry."""

ADAPTER_AUTHORITY_FIELD_MANIFESTS = tuple(item.manifest for item in ADAPTER_AUTHORITY_CONTRACTS)
"""Static adapter field manifests consumed by ADR-0015 checks."""


__all__ = [
    "ADAPTER_AUTHORITY_CONTRACTS",
    "ADAPTER_AUTHORITY_FIELD_MANIFESTS",
    "AdapterAuthorityContract",
    "AdapterAuthorityFieldManifest",
    "adapter_manifest_for",
]
