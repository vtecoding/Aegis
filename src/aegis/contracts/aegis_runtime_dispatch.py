"""Runtime dispatch dry-run contracts for ADR-0017."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, cast

from aegis.aegis_constants import (
    MAX_ADAPTER_STRING_LENGTH,
    MAX_RUNTIME_DISPATCH_ITEMS,
    MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES,
    RUNTIME_DISPATCH_CONTRACT_VERSION,
)
from aegis.contracts.aegis_adapter_replay import (
    AdapterReplayProofResult,
    recompute_adapter_replay_proof_checksum,
)
from aegis.contracts.aegis_execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    recompute_execution_adapter_envelope_checksum,
)
from aegis.contracts.aegis_json_types import FrozenJsonValue
from aegis.contracts.aegis_ros2_mapping import Ros2CommunicationPrimitive
from aegis.governance.aegis_resource_bounds import ResourceBounds

type DispatchFirewallDecisionStatus = Literal["ALLOWED_DRY_RUN", "BLOCKED"]
type CanonicalRuntimeDispatchValue = (
    str
    | int
    | float
    | bool
    | None
    | list[CanonicalRuntimeDispatchValue]
    | dict[str, CanonicalRuntimeDispatchValue]
)

RUNTIME_DISPATCH_RESOURCE_BOUNDS = ResourceBounds(
    max_string_length=MAX_ADAPTER_STRING_LENGTH,
    max_metadata_depth=8,
    max_mapping_width=MAX_RUNTIME_DISPATCH_ITEMS,
    max_sequence_length=MAX_RUNTIME_DISPATCH_ITEMS,
    max_total_nodes=1_024,
    max_canonical_json_bytes=MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES,
    max_trace_stage_count=32,
    max_scenario_count=256,
)
"""Explicit ADR-0017 bounds for inert runtime dispatch planning."""


class RuntimeDispatchMode(StrEnum):
    """Allowed runtime dispatch modes for ADR-0017."""

    DRY_RUN_ONLY = "DRY_RUN_ONLY"


class RuntimeDispatchKind(StrEnum):
    """Inert runtime communication kinds modelled by ADR-0017."""

    TOPIC = "topic"
    SERVICE = "service"
    ACTION = "action"


class DispatchFirewallReason(StrEnum):
    """Stable reason codes emitted by the runtime dispatch firewall."""

    DISPATCH_FIREWALL_ALLOWED_DRY_RUN = "DISPATCH_FIREWALL_ALLOWED_DRY_RUN"
    RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED = "RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED"
    RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH = (
        "RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH"
    )
    RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH = "RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH"
    RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP = (
        "RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP"
    )
    RUNTIME_DISPATCH_RUNTIME_TARGET_MISMATCH = "RUNTIME_DISPATCH_RUNTIME_TARGET_MISMATCH"
    RUNTIME_DISPATCH_MAPPING_MISMATCH = "RUNTIME_DISPATCH_MAPPING_MISMATCH"
    RUNTIME_DISPATCH_NAMESPACE_MISMATCH = "RUNTIME_DISPATCH_NAMESPACE_MISMATCH"
    RUNTIME_DISPATCH_QOS_MISMATCH = "RUNTIME_DISPATCH_QOS_MISMATCH"
    RUNTIME_DISPATCH_MESSAGE_TYPE_MISMATCH = "RUNTIME_DISPATCH_MESSAGE_TYPE_MISMATCH"
    RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED = "RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED"
    RUNTIME_DISPATCH_PAYLOAD_MISMATCH = "RUNTIME_DISPATCH_PAYLOAD_MISMATCH"
    RUNTIME_DISPATCH_FIELD_MAP_DRIFT = "RUNTIME_DISPATCH_FIELD_MAP_DRIFT"
    RUNTIME_DISPATCH_SEQUENCE_GAP = "RUNTIME_DISPATCH_SEQUENCE_GAP"
    RUNTIME_DISPATCH_DUPLICATE_SEQUENCE = "RUNTIME_DISPATCH_DUPLICATE_SEQUENCE"
    RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND = "RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND"
    RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY = "RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY"
    RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH = "RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH"
    RUNTIME_DISPATCH_OBJECT_INJECTION = "RUNTIME_DISPATCH_OBJECT_INJECTION"
    DIRECT_RUNTIME_DISPATCH_BYPASS = "DIRECT_RUNTIME_DISPATCH_BYPASS"
    DIRECT_DISPATCH_FIREWALL_BYPASS = "DIRECT_DISPATCH_FIREWALL_BYPASS"


@dataclass(frozen=True, slots=True, init=False)
class RuntimeDispatchItem:
    """One inert runtime dispatch description with no backend handle."""

    sequence: int
    capability: str
    runtime_kind: RuntimeDispatchKind
    runtime_name: str
    namespace: str
    message_type: str
    qos_profile_checksum: str
    payload_checksum: str
    payload_size_bytes: int
    field_map_checksum: str

    def __init__(
        self,
        *,
        sequence: object,
        capability: object,
        runtime_kind: object,
        runtime_name: object,
        namespace: object,
        message_type: object,
        qos_profile_checksum: object,
        payload_checksum: object,
        payload_size_bytes: object,
        field_map_checksum: object,
    ) -> None:
        object.__setattr__(self, "sequence", _normalize_non_negative_int(sequence, "sequence"))
        object.__setattr__(self, "capability", _normalize_capability(capability))
        object.__setattr__(self, "runtime_kind", _normalize_runtime_dispatch_kind(runtime_kind))
        object.__setattr__(self, "runtime_name", _normalize_namespace(runtime_name, "runtime_name"))
        object.__setattr__(self, "namespace", _normalize_namespace(namespace, "namespace"))
        object.__setattr__(self, "message_type", _normalize_message_type(message_type))
        object.__setattr__(
            self,
            "qos_profile_checksum",
            _normalize_required_checksum(qos_profile_checksum, "qos_profile_checksum"),
        )
        object.__setattr__(
            self,
            "payload_checksum",
            _normalize_required_checksum(payload_checksum, "payload_checksum"),
        )
        object.__setattr__(
            self,
            "payload_size_bytes",
            _normalize_payload_size(payload_size_bytes, "payload_size_bytes"),
        )
        object.__setattr__(
            self,
            "field_map_checksum",
            _normalize_required_checksum(field_map_checksum, "field_map_checksum"),
        )


@dataclass(frozen=True, slots=True)
class _RuntimeDispatchPlanAuthorization:
    """Internal proof object required to create a RuntimeDispatchPlan."""

    envelope: ExecutionAdapterEnvelope
    replay_proof: AdapterReplayProofResult


@dataclass(frozen=True, slots=True, init=False)
class RuntimeDispatchPlan:
    """Checksum-bound inert dispatch plan produced only from replay proof."""

    plan_id: str
    source_envelope_checksum: str
    source_replay_proof_checksum: str
    runtime_target_checksum: str
    mapping_checksum: str
    dispatch_mode: RuntimeDispatchMode
    dispatch_items: tuple[RuntimeDispatchItem, ...]
    resource_bounds: ResourceBounds
    plan_checksum: str

    def __init__(
        self,
        *,
        plan_id: str,
        source_envelope_checksum: str,
        source_replay_proof_checksum: str,
        runtime_target_checksum: str,
        mapping_checksum: str,
        dispatch_mode: object,
        dispatch_items: Iterable[object],
        resource_bounds: object,
        plan_checksum: str | None = None,
        authorization: object = None,
    ) -> None:
        normalized_plan_id = _normalize_identifier(plan_id, "plan_id")
        normalized_source_envelope = _normalize_required_checksum(
            source_envelope_checksum, "source_envelope_checksum"
        )
        normalized_source_proof = _normalize_required_checksum(
            source_replay_proof_checksum, "source_replay_proof_checksum"
        )
        normalized_runtime_target = _normalize_required_checksum(
            runtime_target_checksum, "runtime_target_checksum"
        )
        normalized_mapping = _normalize_required_checksum(mapping_checksum, "mapping_checksum")
        normalized_mode = _normalize_runtime_dispatch_mode(dispatch_mode)
        normalized_items = _normalize_dispatch_items(dispatch_items)
        normalized_bounds = _normalize_resource_bounds(resource_bounds)

        _validate_plan_authorization(
            authorization=authorization,
            source_envelope_checksum=normalized_source_envelope,
            source_replay_proof_checksum=normalized_source_proof,
            runtime_target_checksum=normalized_runtime_target,
            mapping_checksum=normalized_mapping,
            dispatch_mode=normalized_mode,
            dispatch_items=normalized_items,
        )

        computed_checksum = runtime_dispatch_plan_checksum(
            plan_id=normalized_plan_id,
            source_envelope_checksum=normalized_source_envelope,
            source_replay_proof_checksum=normalized_source_proof,
            runtime_target_checksum=normalized_runtime_target,
            mapping_checksum=normalized_mapping,
            dispatch_mode=normalized_mode,
            dispatch_items=normalized_items,
            resource_bounds=normalized_bounds,
        )
        normalized_checksum = _normalize_supplied_checksum(
            plan_checksum, computed_checksum, "plan_checksum"
        )

        object.__setattr__(self, "plan_id", normalized_plan_id)
        object.__setattr__(self, "source_envelope_checksum", normalized_source_envelope)
        object.__setattr__(self, "source_replay_proof_checksum", normalized_source_proof)
        object.__setattr__(self, "runtime_target_checksum", normalized_runtime_target)
        object.__setattr__(self, "mapping_checksum", normalized_mapping)
        object.__setattr__(self, "dispatch_mode", normalized_mode)
        object.__setattr__(self, "dispatch_items", normalized_items)
        object.__setattr__(self, "resource_bounds", normalized_bounds)
        object.__setattr__(self, "plan_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True)
class _DispatchFirewallAllowAuthorization:
    """Internal proof object required to emit ALLOWED_DRY_RUN decisions."""

    plan: RuntimeDispatchPlan
    replay_proof: AdapterReplayProofResult


@dataclass(frozen=True, slots=True, init=False)
class DispatchFirewallDecision:
    """Checksum-bound ADR-0017 firewall decision for one dispatch plan."""

    status: DispatchFirewallDecisionStatus
    reason_code: str
    plan_checksum: str
    source_replay_proof_checksum: str
    blocked_stage: str | None
    decision_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: str,
        plan_checksum: str,
        source_replay_proof_checksum: str,
        blocked_stage: str | None,
        decision_checksum: str | None = None,
        authorization: object = None,
    ) -> None:
        normalized_status = _normalize_firewall_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_plan_checksum = _normalize_required_checksum(plan_checksum, "plan_checksum")
        normalized_source_proof = _normalize_required_checksum(
            source_replay_proof_checksum, "source_replay_proof_checksum"
        )
        normalized_stage = _normalize_optional_stage(blocked_stage, "blocked_stage")
        _validate_firewall_decision_authorization(
            status=normalized_status,
            reason_code=normalized_reason,
            plan_checksum=normalized_plan_checksum,
            source_replay_proof_checksum=normalized_source_proof,
            blocked_stage=normalized_stage,
            authorization=authorization,
        )
        computed_checksum = dispatch_firewall_decision_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            plan_checksum=normalized_plan_checksum,
            source_replay_proof_checksum=normalized_source_proof,
            blocked_stage=normalized_stage,
        )
        normalized_checksum = _normalize_supplied_checksum(
            decision_checksum, computed_checksum, "decision_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "plan_checksum", normalized_plan_checksum)
        object.__setattr__(self, "source_replay_proof_checksum", normalized_source_proof)
        object.__setattr__(self, "blocked_stage", normalized_stage)
        object.__setattr__(self, "decision_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class RuntimeDispatchReceipt:
    """Dry-run receipt binding a dispatch plan and firewall decision."""

    status: DispatchFirewallDecisionStatus
    reason_code: str
    plan_checksum: str
    source_envelope_checksum: str
    source_replay_proof_checksum: str
    decision_checksum: str
    dispatch_mode: RuntimeDispatchMode
    dry_run_receipt_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: str,
        plan_checksum: str,
        source_envelope_checksum: str,
        source_replay_proof_checksum: str,
        decision_checksum: str,
        dispatch_mode: object,
        dry_run_receipt_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_firewall_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_plan = _normalize_required_checksum(plan_checksum, "plan_checksum")
        normalized_envelope = _normalize_required_checksum(
            source_envelope_checksum, "source_envelope_checksum"
        )
        normalized_proof = _normalize_required_checksum(
            source_replay_proof_checksum, "source_replay_proof_checksum"
        )
        normalized_decision = _normalize_required_checksum(decision_checksum, "decision_checksum")
        normalized_mode = _normalize_runtime_dispatch_mode(dispatch_mode)
        computed_checksum = runtime_dispatch_receipt_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            plan_checksum=normalized_plan,
            source_envelope_checksum=normalized_envelope,
            source_replay_proof_checksum=normalized_proof,
            decision_checksum=normalized_decision,
            dispatch_mode=normalized_mode,
        )
        normalized_checksum = _normalize_supplied_checksum(
            dry_run_receipt_checksum, computed_checksum, "dry_run_receipt_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "plan_checksum", normalized_plan)
        object.__setattr__(self, "source_envelope_checksum", normalized_envelope)
        object.__setattr__(self, "source_replay_proof_checksum", normalized_proof)
        object.__setattr__(self, "decision_checksum", normalized_decision)
        object.__setattr__(self, "dispatch_mode", normalized_mode)
        object.__setattr__(self, "dry_run_receipt_checksum", normalized_checksum)


def runtime_dispatch_plan_id(
    *,
    source_envelope_checksum: str,
    source_replay_proof_checksum: str,
) -> str:
    """Return a deterministic runtime dispatch plan identifier."""
    return _sha256(
        {
            "runtime_dispatch_contract_version": RUNTIME_DISPATCH_CONTRACT_VERSION,
            "source_envelope_checksum": source_envelope_checksum,
            "source_replay_proof_checksum": source_replay_proof_checksum,
        }
    )


def runtime_dispatch_payload_checksum(payload: Mapping[str, FrozenJsonValue]) -> str:
    """Return the deterministic checksum for an inert runtime payload."""
    return _sha256({"payload": _canonical_json_mapping(payload)})


def runtime_dispatch_payload_size_bytes(payload: Mapping[str, FrozenJsonValue]) -> int:
    """Return canonical JSON byte size for an inert runtime payload."""
    return len(_canonical_payload_json(payload).encode("utf-8"))


def runtime_dispatch_field_map_checksum(field_map: Mapping[str, str]) -> str:
    """Return the deterministic checksum for dispatch field-map evidence."""
    return _sha256({"field_map": {key: field_map[key] for key in sorted(field_map)}})


def runtime_dispatch_plan_checksum(
    *,
    plan_id: str,
    source_envelope_checksum: str,
    source_replay_proof_checksum: str,
    runtime_target_checksum: str,
    mapping_checksum: str,
    dispatch_mode: RuntimeDispatchMode,
    dispatch_items: Iterable[RuntimeDispatchItem],
    resource_bounds: ResourceBounds,
) -> str:
    """Return the deterministic checksum for a RuntimeDispatchPlan."""
    return _sha256(
        {
            "runtime_dispatch_contract_version": RUNTIME_DISPATCH_CONTRACT_VERSION,
            "plan_id": plan_id,
            "source_envelope_checksum": source_envelope_checksum,
            "source_replay_proof_checksum": source_replay_proof_checksum,
            "runtime_target_checksum": runtime_target_checksum,
            "mapping_checksum": mapping_checksum,
            "dispatch_mode": dispatch_mode.value,
            "dispatch_items": [_dispatch_item_payload(item) for item in dispatch_items],
            "resource_bounds": _resource_bounds_payload(resource_bounds),
        }
    )


def dispatch_firewall_decision_checksum(
    *,
    status: DispatchFirewallDecisionStatus,
    reason_code: str,
    plan_checksum: str,
    source_replay_proof_checksum: str,
    blocked_stage: str | None,
) -> str:
    """Return the deterministic checksum for a DispatchFirewallDecision."""
    return _sha256(
        {
            "runtime_dispatch_contract_version": RUNTIME_DISPATCH_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "plan_checksum": plan_checksum,
            "source_replay_proof_checksum": source_replay_proof_checksum,
            "blocked_stage": blocked_stage,
        }
    )


def runtime_dispatch_receipt_checksum(
    *,
    status: DispatchFirewallDecisionStatus,
    reason_code: str,
    plan_checksum: str,
    source_envelope_checksum: str,
    source_replay_proof_checksum: str,
    decision_checksum: str,
    dispatch_mode: RuntimeDispatchMode,
) -> str:
    """Return the deterministic checksum for a RuntimeDispatchReceipt."""
    return _sha256(
        {
            "runtime_dispatch_contract_version": RUNTIME_DISPATCH_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "plan_checksum": plan_checksum,
            "source_envelope_checksum": source_envelope_checksum,
            "source_replay_proof_checksum": source_replay_proof_checksum,
            "decision_checksum": decision_checksum,
            "dispatch_mode": dispatch_mode.value,
        }
    )


def recompute_runtime_dispatch_plan_checksum(plan: RuntimeDispatchPlan) -> str:
    """Recompute a RuntimeDispatchPlan checksum from authoritative fields."""
    return runtime_dispatch_plan_checksum(
        plan_id=plan.plan_id,
        source_envelope_checksum=plan.source_envelope_checksum,
        source_replay_proof_checksum=plan.source_replay_proof_checksum,
        runtime_target_checksum=plan.runtime_target_checksum,
        mapping_checksum=plan.mapping_checksum,
        dispatch_mode=plan.dispatch_mode,
        dispatch_items=plan.dispatch_items,
        resource_bounds=plan.resource_bounds,
    )


def recompute_dispatch_firewall_decision_checksum(
    decision: DispatchFirewallDecision,
) -> str:
    """Recompute a DispatchFirewallDecision checksum from authoritative fields."""
    return dispatch_firewall_decision_checksum(
        status=decision.status,
        reason_code=decision.reason_code,
        plan_checksum=decision.plan_checksum,
        source_replay_proof_checksum=decision.source_replay_proof_checksum,
        blocked_stage=decision.blocked_stage,
    )


def recompute_runtime_dispatch_receipt_checksum(receipt: RuntimeDispatchReceipt) -> str:
    """Recompute a RuntimeDispatchReceipt checksum from authoritative fields."""
    return runtime_dispatch_receipt_checksum(
        status=receipt.status,
        reason_code=receipt.reason_code,
        plan_checksum=receipt.plan_checksum,
        source_envelope_checksum=receipt.source_envelope_checksum,
        source_replay_proof_checksum=receipt.source_replay_proof_checksum,
        decision_checksum=receipt.decision_checksum,
        dispatch_mode=receipt.dispatch_mode,
    )


def make_runtime_dispatch_item(envelope: ExecutionAdapterEnvelope) -> RuntimeDispatchItem:
    """Build the one inert dispatch item represented by an adapter envelope."""
    mapping = envelope.adapter_mapping
    if mapping is None:
        raise ValueError("runtime dispatch requires adapter mapping evidence")
    return RuntimeDispatchItem(
        sequence=0,
        capability=mapping.ros2_mapping.source_capability,
        runtime_kind=_dispatch_kind_from_primitive(mapping.ros2_mapping.primitive),
        runtime_name=mapping.ros2_mapping.topic_or_service_name,
        namespace=mapping.ros2_mapping.namespace,
        message_type=mapping.ros2_mapping.message_type,
        qos_profile_checksum=mapping.ros2_mapping.qos.qos_checksum,
        payload_checksum=runtime_dispatch_payload_checksum(envelope.command_payload),
        payload_size_bytes=runtime_dispatch_payload_size_bytes(envelope.command_payload),
        field_map_checksum=runtime_dispatch_field_map_checksum(mapping.ros2_mapping.field_map),
    )


def make_runtime_dispatch_plan_authorization(
    *,
    envelope: ExecutionAdapterEnvelope,
    replay_proof: AdapterReplayProofResult,
) -> _RuntimeDispatchPlanAuthorization:
    """Return the internal authorization required for a RuntimeDispatchPlan."""
    return _RuntimeDispatchPlanAuthorization(envelope=envelope, replay_proof=replay_proof)


def make_dispatch_firewall_allow_authorization(
    *,
    plan: RuntimeDispatchPlan,
    replay_proof: AdapterReplayProofResult,
) -> _DispatchFirewallAllowAuthorization:
    """Return the internal authorization required for ALLOWED_DRY_RUN."""
    return _DispatchFirewallAllowAuthorization(plan=plan, replay_proof=replay_proof)


def _validate_plan_authorization(
    *,
    authorization: object,
    source_envelope_checksum: str,
    source_replay_proof_checksum: str,
    runtime_target_checksum: str,
    mapping_checksum: str,
    dispatch_mode: RuntimeDispatchMode,
    dispatch_items: tuple[RuntimeDispatchItem, ...],
) -> None:
    if not isinstance(authorization, _RuntimeDispatchPlanAuthorization):
        raise ValueError(DispatchFirewallReason.DIRECT_RUNTIME_DISPATCH_BYPASS.value)
    envelope = authorization.envelope
    replay_proof = authorization.replay_proof
    if envelope.status is not ExecutionAdapterEnvelopeStatus.READY:
        raise ValueError("runtime dispatch requires a READY adapter envelope")
    if replay_proof.status != "PASSED":
        raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED.value)
    if replay_proof.proof_checksum != recompute_adapter_replay_proof_checksum(replay_proof):
        raise ValueError(
            DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH.value
        )
    if envelope.envelope_checksum != recompute_execution_adapter_envelope_checksum(envelope):
        raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH.value)
    if (
        replay_proof.expected_envelope_checksum != envelope.envelope_checksum
        or replay_proof.replayed_envelope_checksum != envelope.envelope_checksum
    ):
        raise ValueError(
            DispatchFirewallReason.RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP.value
        )
    expected_item = make_runtime_dispatch_item(envelope)
    if dispatch_items != (expected_item,):
        raise ValueError("runtime dispatch items must match adapter mapping evidence")
    if dispatch_mode is not RuntimeDispatchMode.DRY_RUN_ONLY:
        raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY.value)
    expected_values = {
        "source_envelope_checksum": envelope.envelope_checksum,
        "source_replay_proof_checksum": replay_proof.proof_checksum,
        "runtime_target_checksum": envelope.runtime_target_checksum,
        "mapping_checksum": envelope.adapter_mapping_checksum,
    }
    observed_values = {
        "source_envelope_checksum": source_envelope_checksum,
        "source_replay_proof_checksum": source_replay_proof_checksum,
        "runtime_target_checksum": runtime_target_checksum,
        "mapping_checksum": mapping_checksum,
    }
    if any(
        observed_values[field_name] != expected_values[field_name] for field_name in observed_values
    ):
        raise ValueError("runtime dispatch plan evidence must match replay authorization")


def _validate_firewall_decision_authorization(
    *,
    status: DispatchFirewallDecisionStatus,
    reason_code: str,
    plan_checksum: str,
    source_replay_proof_checksum: str,
    blocked_stage: str | None,
    authorization: object,
) -> None:
    allowed_reason = DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value
    if status == "ALLOWED_DRY_RUN":
        if reason_code != allowed_reason:
            raise ValueError("ALLOWED_DRY_RUN decisions require the allowed reason code")
        if blocked_stage is not None:
            raise ValueError("ALLOWED_DRY_RUN decisions must not include blocked_stage")
        if not isinstance(authorization, _DispatchFirewallAllowAuthorization):
            raise ValueError(DispatchFirewallReason.DIRECT_DISPATCH_FIREWALL_BYPASS.value)
        if authorization.plan.plan_checksum != plan_checksum:
            raise ValueError("firewall decision plan_checksum must match authorization")
        if authorization.replay_proof.proof_checksum != source_replay_proof_checksum:
            raise ValueError("firewall decision proof checksum must match authorization")
    else:
        if reason_code == allowed_reason:
            raise ValueError("blocked decisions must not use the allowed reason code")
        if blocked_stage is None:
            raise ValueError("blocked decisions require blocked_stage")


def _dispatch_kind_from_primitive(primitive: Ros2CommunicationPrimitive) -> RuntimeDispatchKind:
    if primitive is Ros2CommunicationPrimitive.TOPIC:
        return RuntimeDispatchKind.TOPIC
    if primitive is Ros2CommunicationPrimitive.SERVICE:
        return RuntimeDispatchKind.SERVICE
    if primitive is Ros2CommunicationPrimitive.ACTION:
        return RuntimeDispatchKind.ACTION
    raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND.value)


def _dispatch_item_payload(item: RuntimeDispatchItem) -> dict[str, CanonicalRuntimeDispatchValue]:
    return {
        "sequence": item.sequence,
        "capability": item.capability,
        "runtime_kind": item.runtime_kind.value,
        "runtime_name": item.runtime_name,
        "namespace": item.namespace,
        "message_type": item.message_type,
        "qos_profile_checksum": item.qos_profile_checksum,
        "payload_checksum": item.payload_checksum,
        "payload_size_bytes": item.payload_size_bytes,
        "field_map_checksum": item.field_map_checksum,
    }


def _resource_bounds_payload(bounds: ResourceBounds) -> dict[str, CanonicalRuntimeDispatchValue]:
    return {
        "max_string_length": bounds.max_string_length,
        "max_metadata_depth": bounds.max_metadata_depth,
        "max_mapping_width": bounds.max_mapping_width,
        "max_sequence_length": bounds.max_sequence_length,
        "max_total_nodes": bounds.max_total_nodes,
        "max_canonical_json_bytes": bounds.max_canonical_json_bytes,
        "max_trace_stage_count": bounds.max_trace_stage_count,
        "max_scenario_count": bounds.max_scenario_count,
    }


def _normalize_dispatch_items(
    values: Iterable[object],
) -> tuple[RuntimeDispatchItem, ...]:
    if isinstance(values, str):
        raise ValueError("dispatch_items must be an iterable of RuntimeDispatchItem")
    items = tuple(values)
    if not items:
        raise ValueError("dispatch_items must be non-empty")
    if len(items) > MAX_RUNTIME_DISPATCH_ITEMS:
        raise ValueError("dispatch_items exceeds MAX_RUNTIME_DISPATCH_ITEMS")
    runtime_items: list[RuntimeDispatchItem] = []
    for item in items:
        if not isinstance(item, RuntimeDispatchItem):
            raise ValueError("dispatch_items must contain RuntimeDispatchItem values")
        runtime_items.append(item)
    sequences = [item.sequence for item in runtime_items]
    if len(set(sequences)) != len(sequences):
        raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_DUPLICATE_SEQUENCE.value)
    if sequences != list(range(len(runtime_items))):
        raise ValueError(DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP.value)
    return tuple(runtime_items)


def _normalize_runtime_dispatch_mode(value: object) -> RuntimeDispatchMode:
    if isinstance(value, RuntimeDispatchMode):
        return value
    if not isinstance(value, str):
        raise ValueError("dispatch_mode must be a RuntimeDispatchMode")
    if value != value.strip():
        raise ValueError("dispatch_mode must not contain leading or trailing whitespace")
    try:
        return RuntimeDispatchMode(value)
    except ValueError:
        raise ValueError("dispatch_mode must be DRY_RUN_ONLY") from None


def _normalize_runtime_dispatch_kind(value: object) -> RuntimeDispatchKind:
    if isinstance(value, RuntimeDispatchKind):
        return value
    if not isinstance(value, str):
        raise ValueError("runtime_kind must be a RuntimeDispatchKind")
    if value != value.strip():
        raise ValueError("runtime_kind must not contain leading or trailing whitespace")
    try:
        return RuntimeDispatchKind(value)
    except ValueError:
        raise ValueError(
            DispatchFirewallReason.RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND.value
        ) from None


def _normalize_firewall_status(value: object) -> DispatchFirewallDecisionStatus:
    if value in {"ALLOWED_DRY_RUN", "BLOCKED"}:
        return cast(DispatchFirewallDecisionStatus, value)
    raise ValueError("status must be ALLOWED_DRY_RUN or BLOCKED")


def _normalize_resource_bounds(value: object) -> ResourceBounds:
    if not isinstance(value, ResourceBounds):
        raise ValueError("resource_bounds must be a ResourceBounds")
    return value


def _normalize_payload_size(value: object, field_name: str) -> int:
    normalized = _normalize_non_negative_int(value, field_name)
    if normalized > MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES:
        raise ValueError(f"{field_name} exceeds MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_capability(value: object) -> str:
    normalized = _normalize_required_text(value, "capability")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_namespace(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError(f"{field_name} must be namespace-scoped and lowercase")
    return normalized


def _normalize_message_type(value: object) -> str:
    normalized = _normalize_required_text(value, "message_type")
    if fullmatch(r"(?:msg|srv|action)/[A-Za-z][A-Za-z0-9_]*", normalized) is None:
        raise ValueError("message_type must be namespace-scoped as msg|srv|action/Type")
    return normalized


def _normalize_identifier(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical runtime dispatch identifier")
    return normalized


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_optional_stage(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[a-z][a-z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a lowercase machine stage")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(f"{field_name} must not be callable")
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


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if len(normalized) != 64 or not all(
        character in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


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


def _canonical_payload_json(payload: Mapping[str, FrozenJsonValue]) -> str:
    return json.dumps(
        _canonical_json_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _canonical_json_mapping(
    values: Mapping[str, FrozenJsonValue],
) -> dict[str, CanonicalRuntimeDispatchValue]:
    return {key: _canonical_json_value(values[key]) for key in sorted(values)}


def _canonical_json_value(value: FrozenJsonValue) -> CanonicalRuntimeDispatchValue:
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


def _sha256(payload: Mapping[str, CanonicalRuntimeDispatchValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalRuntimeDispatchValue],
) -> dict[str, CanonicalRuntimeDispatchValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalRuntimeDispatchValue) -> CanonicalRuntimeDispatchValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalRuntimeDispatchValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "DispatchFirewallDecision",
    "DispatchFirewallDecisionStatus",
    "DispatchFirewallReason",
    "RuntimeDispatchItem",
    "RuntimeDispatchKind",
    "RuntimeDispatchMode",
    "RuntimeDispatchPlan",
    "RuntimeDispatchReceipt",
    "RUNTIME_DISPATCH_RESOURCE_BOUNDS",
    "dispatch_firewall_decision_checksum",
    "make_dispatch_firewall_allow_authorization",
    "make_runtime_dispatch_item",
    "make_runtime_dispatch_plan_authorization",
    "recompute_dispatch_firewall_decision_checksum",
    "recompute_runtime_dispatch_plan_checksum",
    "recompute_runtime_dispatch_receipt_checksum",
    "runtime_dispatch_field_map_checksum",
    "runtime_dispatch_payload_checksum",
    "runtime_dispatch_payload_size_bytes",
    "runtime_dispatch_plan_checksum",
    "runtime_dispatch_plan_id",
    "runtime_dispatch_receipt_checksum",
]
