"""Deterministic command quarantine envelopes for ADR-0022."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, cast

from aegis.aegis_constants import COMMAND_QUARANTINE_CONTRACT_VERSION
from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
    recompute_backend_certification_checksum,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.aegis_runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchItem,
    RuntimeDispatchKind,
    RuntimeDispatchPlan,
    recompute_runtime_dispatch_plan_checksum,
)
from aegis.execution.aegis_backend_admission import (
    BackendAdmissionDecision,
    recompute_backend_admission_decision_checksum,
)
from aegis.execution.aegis_backend_authority import (
    BackendAuthorityManifest,
    recompute_backend_authority_manifest_checksum,
)
from aegis.execution.aegis_backend_registry import backend_authority_registry_checksum
from aegis.execution.aegis_capability_lease import (
    RuntimeCapabilityLease,
    checksum_or_fallback,
    normalize_lease_epoch,
    recompute_runtime_capability_lease_checksum,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease

type CommandQuarantineStatusValue = Literal["QUARANTINED"]
type CanonicalCommandQuarantineValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalCommandQuarantineValue]
    | dict[str, CanonicalCommandQuarantineValue]
)

_FALLBACK_CHECKSUM = "0" * 64


class CommandQuarantineStatus(StrEnum):
    """Closed ADR-0022 command quarantine statuses."""

    QUARANTINED = "QUARANTINED"


class CommandQuarantineReason(StrEnum):
    """Stable ADR-0022 quarantine and release reason codes."""

    COMMAND_QUARANTINE_CREATED = "COMMAND_QUARANTINE_CREATED"
    COMMAND_QUARANTINE_RELEASED_DRY_RUN = "COMMAND_QUARANTINE_RELEASED_DRY_RUN"
    COMMAND_QUARANTINE_MISSING_APPROVAL = "COMMAND_QUARANTINE_MISSING_APPROVAL"
    COMMAND_QUARANTINE_APPROVAL_REJECTED = "COMMAND_QUARANTINE_APPROVAL_REJECTED"
    COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID = "COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID"
    COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT = "COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT"
    COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH = (
        "COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH"
    )
    COMMAND_QUARANTINE_CHECKSUM_DRIFT = "COMMAND_QUARANTINE_CHECKSUM_DRIFT"
    COMMAND_QUARANTINE_STATUS_INVALID = "COMMAND_QUARANTINE_STATUS_INVALID"
    COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT = "COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT"
    COMMAND_QUARANTINE_LEASE_REVOKED = "COMMAND_QUARANTINE_LEASE_REVOKED"
    COMMAND_QUARANTINE_LEASE_INVALID = "COMMAND_QUARANTINE_LEASE_INVALID"
    COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT = "COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT"
    COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT = "COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT"
    COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT = "COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT"
    COMMAND_QUARANTINE_REGISTRY_DRIFT = "COMMAND_QUARANTINE_REGISTRY_DRIFT"
    COMMAND_QUARANTINE_MANIFEST_DRIFT = "COMMAND_QUARANTINE_MANIFEST_DRIFT"
    COMMAND_QUARANTINE_CERTIFICATION_DRIFT = "COMMAND_QUARANTINE_CERTIFICATION_DRIFT"
    COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT = "COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT"
    COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT = "COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT"
    COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE = "COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE"
    COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE = "COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE"
    COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY = "COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY"
    COMMAND_QUARANTINE_MISSING_APPROVAL_REPLAY_VALIDATION = (
        "COMMAND_QUARANTINE_MISSING_APPROVAL_REPLAY_VALIDATION"
    )
    COMMAND_QUARANTINE_APPROVAL_REPLAY_BLOCKED = "COMMAND_QUARANTINE_APPROVAL_REPLAY_BLOCKED"
    COMMAND_QUARANTINE_APPROVAL_REPLAY_CHECKSUM_DRIFT = (
        "COMMAND_QUARANTINE_APPROVAL_REPLAY_CHECKSUM_DRIFT"
    )
    COMMAND_QUARANTINE_APPROVAL_REPLAY_BINDING_MISMATCH = (
        "COMMAND_QUARANTINE_APPROVAL_REPLAY_BINDING_MISMATCH"
    )
    COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION = "COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION"
    COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH = "COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH"
    COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED = "COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED"
    COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION = "COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION"
    DIRECT_QUARANTINE_RELEASE_CONSTRUCTION = "DIRECT_QUARANTINE_RELEASE_CONSTRUCTION"


@dataclass(frozen=True, slots=True, init=False)
class QuarantinedCommandItem:
    """Inert projection of one dispatch item with no runtime payload handle."""

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
    item_checksum: str

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
        item_checksum: str | None = None,
    ) -> None:
        normalized_sequence = _normalize_non_negative_int(sequence, "sequence")
        normalized_capability = _normalize_capability(capability)
        normalized_runtime_kind = _normalize_runtime_kind(runtime_kind)
        normalized_runtime_name = _normalize_required_text(runtime_name, "runtime_name")
        normalized_namespace = _normalize_required_text(namespace, "namespace")
        normalized_message_type = _normalize_required_text(message_type, "message_type")
        normalized_qos = _normalize_required_checksum(qos_profile_checksum, "qos_profile_checksum")
        normalized_payload = _normalize_required_checksum(payload_checksum, "payload_checksum")
        normalized_payload_size = _normalize_non_negative_int(
            payload_size_bytes, "payload_size_bytes"
        )
        normalized_field_map = _normalize_required_checksum(
            field_map_checksum, "field_map_checksum"
        )
        computed_checksum = quarantined_command_item_checksum(
            sequence=normalized_sequence,
            capability=normalized_capability,
            runtime_kind=normalized_runtime_kind,
            runtime_name=normalized_runtime_name,
            namespace=normalized_namespace,
            message_type=normalized_message_type,
            qos_profile_checksum=normalized_qos,
            payload_checksum=normalized_payload,
            payload_size_bytes=normalized_payload_size,
            field_map_checksum=normalized_field_map,
        )
        normalized_checksum = _normalize_supplied_checksum(
            item_checksum, computed_checksum, "item_checksum"
        )

        object.__setattr__(self, "sequence", normalized_sequence)
        object.__setattr__(self, "capability", normalized_capability)
        object.__setattr__(self, "runtime_kind", normalized_runtime_kind)
        object.__setattr__(self, "runtime_name", normalized_runtime_name)
        object.__setattr__(self, "namespace", normalized_namespace)
        object.__setattr__(self, "message_type", normalized_message_type)
        object.__setattr__(self, "qos_profile_checksum", normalized_qos)
        object.__setattr__(self, "payload_checksum", normalized_payload)
        object.__setattr__(self, "payload_size_bytes", normalized_payload_size)
        object.__setattr__(self, "field_map_checksum", normalized_field_map)
        object.__setattr__(self, "item_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class CommandQuarantineEnvelope:
    """Checksum-bound envelope proving dispatch intent is quarantined by default."""

    quarantine_id: str
    dispatch_plan_checksum: str
    backend_admission_checksum: str
    capability_lease_checksum: str
    backend_descriptor_checksum: str
    authority_manifest_checksum: str
    registry_checksum: str
    certification_checksum: str
    backend_replay_proof_checksum: str
    context_authority_checksum: str
    quarantined_items: tuple[QuarantinedCommandItem, ...]
    quarantine_status: CommandQuarantineStatus
    quarantine_epoch: int
    quarantine_checksum: str

    def __init__(
        self,
        *,
        quarantine_id: object,
        dispatch_plan_checksum: object,
        backend_admission_checksum: object,
        capability_lease_checksum: object,
        backend_descriptor_checksum: object,
        authority_manifest_checksum: object,
        registry_checksum: object,
        certification_checksum: object,
        backend_replay_proof_checksum: object,
        context_authority_checksum: object,
        quarantined_items: Iterable[object],
        quarantine_status: object,
        quarantine_epoch: object,
        quarantine_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_required_checksum(quarantine_id, "quarantine_id")
        normalized_dispatch = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_admission = _normalize_required_checksum(
            backend_admission_checksum, "backend_admission_checksum"
        )
        normalized_lease = _normalize_required_checksum(
            capability_lease_checksum, "capability_lease_checksum"
        )
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            authority_manifest_checksum, "authority_manifest_checksum"
        )
        normalized_registry = _normalize_required_checksum(registry_checksum, "registry_checksum")
        normalized_certification = _normalize_required_checksum(
            certification_checksum, "certification_checksum"
        )
        normalized_replay = _normalize_required_checksum(
            backend_replay_proof_checksum, "backend_replay_proof_checksum"
        )
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        normalized_items = normalize_quarantined_items(quarantined_items)
        normalized_status = _normalize_quarantine_status(quarantine_status)
        normalized_epoch = normalize_quarantine_epoch(quarantine_epoch)
        computed_checksum = command_quarantine_envelope_checksum(
            quarantine_id=normalized_id,
            dispatch_plan_checksum=normalized_dispatch,
            backend_admission_checksum=normalized_admission,
            capability_lease_checksum=normalized_lease,
            backend_descriptor_checksum=normalized_descriptor,
            authority_manifest_checksum=normalized_manifest,
            registry_checksum=normalized_registry,
            certification_checksum=normalized_certification,
            backend_replay_proof_checksum=normalized_replay,
            context_authority_checksum=normalized_context,
            quarantined_items=normalized_items,
            quarantine_status=normalized_status,
            quarantine_epoch=normalized_epoch,
        )
        normalized_checksum = _normalize_supplied_checksum(
            quarantine_checksum, computed_checksum, "quarantine_checksum"
        )

        object.__setattr__(self, "quarantine_id", normalized_id)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_dispatch)
        object.__setattr__(self, "backend_admission_checksum", normalized_admission)
        object.__setattr__(self, "capability_lease_checksum", normalized_lease)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(self, "authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "registry_checksum", normalized_registry)
        object.__setattr__(self, "certification_checksum", normalized_certification)
        object.__setattr__(self, "backend_replay_proof_checksum", normalized_replay)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "quarantined_items", normalized_items)
        object.__setattr__(self, "quarantine_status", normalized_status)
        object.__setattr__(self, "quarantine_epoch", normalized_epoch)
        object.__setattr__(self, "quarantine_checksum", normalized_checksum)


def quarantine_runtime_command(
    *,
    dispatch_plan: object,
    backend_admission_decision: object,
    capability_lease: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    quarantine_epoch: object,
    current_lease_epoch: object,
) -> CommandQuarantineEnvelope:
    """Quarantine every dispatch item for a valid active lease.

    Args:
        dispatch_plan: Current inert runtime dispatch plan.
        backend_admission_decision: Current admitted backend authority decision.
        capability_lease: Active runtime capability lease for the dispatch plan.
        backend_descriptor: Backend descriptor bound by admission and lease evidence.
        authority_manifest: Backend authority manifest bound by admission evidence.
        registry_checksum: Current backend authority registry checksum.
        backend_certification: Backend certification evidence.
        backend_replay_proof: Backend replay proof evidence.
        firewall_decision: Dry-run firewall decision bound into the lease.
        context_authority_checksum: Explicit current context authority checksum.
        quarantine_epoch: Caller-supplied deterministic quarantine epoch.
        current_lease_epoch: Caller-supplied deterministic lease epoch.

    Returns:
        A checksum-bound quarantine envelope containing every dispatch item.

    Raises:
        ValueError: If any lease, evidence-chain, scope, or runtime-object check fails closed.
    """
    epoch = normalize_quarantine_epoch(quarantine_epoch)
    block_reason = command_quarantine_issue_block_reason(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if block_reason is not None:
        raise ValueError(block_reason.value)

    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    decision = cast(BackendAdmissionDecision, backend_admission_decision)
    lease = cast(RuntimeCapabilityLease, capability_lease)
    descriptor = cast(RuntimeBackendDescriptor, backend_descriptor)
    manifest = cast(BackendAuthorityManifest, authority_manifest)
    certification = cast(BackendCertificationResult, backend_certification)
    replay_proof = cast(BackendReplayProofResult, backend_replay_proof)
    normalized_registry = _normalize_required_checksum(registry_checksum, "registry_checksum")
    normalized_context = _normalize_required_checksum(
        context_authority_checksum, "context_authority_checksum"
    )
    quarantined_items = quarantine_items_from_dispatch_plan(plan)
    quarantine_id = command_quarantine_id(
        dispatch_plan_checksum=plan.plan_checksum,
        backend_admission_checksum=decision.decision_checksum,
        capability_lease_checksum=lease.lease_checksum,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        authority_manifest_checksum=manifest.manifest_checksum,
        registry_checksum=normalized_registry,
        certification_checksum=certification.certification_checksum,
        backend_replay_proof_checksum=replay_proof.proof_checksum,
        context_authority_checksum=normalized_context,
        quarantined_items=quarantined_items,
        quarantine_epoch=epoch,
    )
    return CommandQuarantineEnvelope(
        quarantine_id=quarantine_id,
        dispatch_plan_checksum=plan.plan_checksum,
        backend_admission_checksum=decision.decision_checksum,
        capability_lease_checksum=lease.lease_checksum,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        authority_manifest_checksum=manifest.manifest_checksum,
        registry_checksum=normalized_registry,
        certification_checksum=certification.certification_checksum,
        backend_replay_proof_checksum=replay_proof.proof_checksum,
        context_authority_checksum=normalized_context,
        quarantined_items=quarantined_items,
        quarantine_status=CommandQuarantineStatus.QUARANTINED,
        quarantine_epoch=epoch,
    )


def command_quarantine_issue_block_reason(
    *,
    dispatch_plan: object,
    backend_admission_decision: object,
    capability_lease: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> CommandQuarantineReason | None:
    """Return the first deterministic reason dispatch intent cannot enter quarantine."""
    shape_reason = _source_shape_reason(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
    )
    if shape_reason is not None:
        return shape_reason
    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    decision = cast(BackendAdmissionDecision, backend_admission_decision)
    lease = cast(RuntimeCapabilityLease, capability_lease)
    descriptor = cast(RuntimeBackendDescriptor, backend_descriptor)
    manifest = cast(BackendAuthorityManifest, authority_manifest)
    certification = cast(BackendCertificationResult, backend_certification)
    replay_proof = cast(BackendReplayProofResult, backend_replay_proof)
    firewall = cast(DispatchFirewallDecision, firewall_decision)
    evidence_reason = command_quarantine_evidence_drift_reason(
        quarantine=None,
        dispatch_plan=plan,
        backend_admission_decision=decision,
        capability_lease=lease,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        context_authority_checksum=context_authority_checksum,
    )
    if evidence_reason is not None:
        return evidence_reason
    validation = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=firewall,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if validation.status == "VALID":
        return None
    if validation.reason_code == "CAPABILITY_LEASE_CHECKSUM_DRIFT":
        return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT
    if validation.status == "REVOKED":
        return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_REVOKED
    return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_INVALID


def command_quarantine_evidence_drift_reason(
    *,
    quarantine: CommandQuarantineEnvelope | None,
    dispatch_plan: RuntimeDispatchPlan,
    backend_admission_decision: BackendAdmissionDecision,
    capability_lease: RuntimeCapabilityLease,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_manifest: BackendAuthorityManifest,
    registry_checksum: object,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    context_authority_checksum: object,
) -> CommandQuarantineReason | None:
    """Return the first ADR-0022 evidence drift reason for current source evidence."""
    normalized_registry = checksum_or_fallback(registry_checksum)
    normalized_context = checksum_or_fallback(context_authority_checksum)
    if dispatch_plan.plan_checksum != _recompute_dispatch_plan_checksum_or_fallback(dispatch_plan):
        return CommandQuarantineReason.COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT
    if (
        backend_admission_decision.decision_checksum
        != recompute_backend_admission_decision_checksum(backend_admission_decision)
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if capability_lease.lease_checksum != _recompute_lease_checksum_or_fallback(capability_lease):
        return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT
    if backend_descriptor.descriptor_checksum != _recompute_descriptor_checksum_or_fallback(
        backend_descriptor
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT
    if authority_manifest.manifest_checksum != _recompute_manifest_checksum_or_fallback(
        authority_manifest
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_MANIFEST_DRIFT
    expected_registry = backend_authority_registry_checksum((authority_manifest,))
    if normalized_registry != expected_registry:
        return CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT
    if backend_certification.certification_checksum != recompute_backend_certification_checksum(
        backend_certification
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_CERTIFICATION_DRIFT
    if backend_replay_proof.proof_checksum != backend_replay_proof_recompute_or_fallback(
        backend_replay_proof
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT
    bound_reason = _bound_field_drift_reason(
        quarantine=quarantine,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=normalized_registry,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        context_authority_checksum=normalized_context,
    )
    if bound_reason is not None:
        return bound_reason
    if backend_admission_decision.status != "ADMITTED":
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if normalized_context != capability_lease.context_authority_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT
    return None


def command_quarantine_id(
    *,
    dispatch_plan_checksum: str,
    backend_admission_checksum: str,
    capability_lease_checksum: str,
    backend_descriptor_checksum: str,
    authority_manifest_checksum: str,
    registry_checksum: str,
    certification_checksum: str,
    backend_replay_proof_checksum: str,
    context_authority_checksum: str,
    quarantined_items: Iterable[QuarantinedCommandItem],
    quarantine_epoch: int,
) -> str:
    """Return the deterministic identifier for a command quarantine envelope."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "backend_admission_checksum": backend_admission_checksum,
            "capability_lease_checksum": capability_lease_checksum,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "registry_checksum": registry_checksum,
            "certification_checksum": certification_checksum,
            "backend_replay_proof_checksum": backend_replay_proof_checksum,
            "context_authority_checksum": context_authority_checksum,
            "quarantined_items": [_quarantine_item_payload(item) for item in quarantined_items],
            "quarantine_epoch": quarantine_epoch,
        }
    )


def command_quarantine_envelope_checksum(
    *,
    quarantine_id: str,
    dispatch_plan_checksum: str,
    backend_admission_checksum: str,
    capability_lease_checksum: str,
    backend_descriptor_checksum: str,
    authority_manifest_checksum: str,
    registry_checksum: str,
    certification_checksum: str,
    backend_replay_proof_checksum: str,
    context_authority_checksum: str,
    quarantined_items: Iterable[QuarantinedCommandItem],
    quarantine_status: CommandQuarantineStatus | str,
    quarantine_epoch: int,
) -> str:
    """Return the deterministic checksum for a command quarantine envelope."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "quarantine_id": quarantine_id,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "backend_admission_checksum": backend_admission_checksum,
            "capability_lease_checksum": capability_lease_checksum,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "registry_checksum": registry_checksum,
            "certification_checksum": certification_checksum,
            "backend_replay_proof_checksum": backend_replay_proof_checksum,
            "context_authority_checksum": context_authority_checksum,
            "quarantined_items": [_quarantine_item_payload(item) for item in quarantined_items],
            "quarantine_status": _status_checksum_value(quarantine_status),
            "quarantine_epoch": quarantine_epoch,
        }
    )


def quarantined_command_item_checksum(
    *,
    sequence: int,
    capability: str,
    runtime_kind: RuntimeDispatchKind | str,
    runtime_name: str,
    namespace: str,
    message_type: str,
    qos_profile_checksum: str,
    payload_checksum: str,
    payload_size_bytes: int,
    field_map_checksum: str,
) -> str:
    """Return the deterministic checksum for one quarantined dispatch item."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "sequence": sequence,
            "capability": capability,
            "runtime_kind": _runtime_kind_checksum_value(runtime_kind),
            "runtime_name": runtime_name,
            "namespace": namespace,
            "message_type": message_type,
            "qos_profile_checksum": qos_profile_checksum,
            "payload_checksum": payload_checksum,
            "payload_size_bytes": payload_size_bytes,
            "field_map_checksum": field_map_checksum,
        }
    )


def recompute_command_quarantine_checksum(envelope: CommandQuarantineEnvelope) -> str:
    """Recompute a CommandQuarantineEnvelope checksum from authoritative fields."""
    return command_quarantine_envelope_checksum(
        quarantine_id=envelope.quarantine_id,
        dispatch_plan_checksum=envelope.dispatch_plan_checksum,
        backend_admission_checksum=envelope.backend_admission_checksum,
        capability_lease_checksum=envelope.capability_lease_checksum,
        backend_descriptor_checksum=envelope.backend_descriptor_checksum,
        authority_manifest_checksum=envelope.authority_manifest_checksum,
        registry_checksum=envelope.registry_checksum,
        certification_checksum=envelope.certification_checksum,
        backend_replay_proof_checksum=envelope.backend_replay_proof_checksum,
        context_authority_checksum=envelope.context_authority_checksum,
        quarantined_items=envelope.quarantined_items,
        quarantine_status=envelope.quarantine_status,
        quarantine_epoch=envelope.quarantine_epoch,
    )


def recompute_quarantined_command_item_checksum(item: QuarantinedCommandItem) -> str:
    """Recompute a QuarantinedCommandItem checksum from authoritative fields."""
    return quarantined_command_item_checksum(
        sequence=item.sequence,
        capability=item.capability,
        runtime_kind=item.runtime_kind,
        runtime_name=item.runtime_name,
        namespace=item.namespace,
        message_type=item.message_type,
        qos_profile_checksum=item.qos_profile_checksum,
        payload_checksum=item.payload_checksum,
        payload_size_bytes=item.payload_size_bytes,
        field_map_checksum=item.field_map_checksum,
    )


def quarantine_items_from_dispatch_plan(
    plan: RuntimeDispatchPlan,
) -> tuple[QuarantinedCommandItem, ...]:
    """Project every dispatch item into an inert quarantine item."""
    items = tuple(_quarantine_item_from_dispatch_item(item) for item in plan.dispatch_items)
    if len(items) != len(plan.dispatch_items):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value)
    return normalize_quarantined_items(items)


def quarantine_item_checksums(envelope: CommandQuarantineEnvelope) -> frozenset[str]:
    """Return the explicit item-checksum scope in a quarantine envelope."""
    return frozenset(item.item_checksum for item in envelope.quarantined_items)


def normalize_quarantined_items(values: Iterable[object]) -> tuple[QuarantinedCommandItem, ...]:
    """Normalize inert quarantined items and reject mutable or runtime payload escape hatches."""
    if isinstance(values, (str, Mapping)) or callable(values):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    normalized: list[QuarantinedCommandItem] = []
    seen_sequences: set[int] = set()
    seen_checksums: set[str] = set()
    for value in values:
        if type(value) is not QuarantinedCommandItem:
            raise ValueError(
                CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
            )
        if value.sequence in seen_sequences or value.item_checksum in seen_checksums:
            raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value)
        if value.item_checksum != recompute_quarantined_command_item_checksum(value):
            raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_CHECKSUM_DRIFT.value)
        seen_sequences.add(value.sequence)
        seen_checksums.add(value.item_checksum)
        normalized.append(value)
    if not normalized:
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value)
    return tuple(sorted(normalized, key=lambda item: item.sequence))


def normalize_quarantine_epoch(value: object) -> int:
    """Normalize an explicit deterministic quarantine epoch."""
    return normalize_lease_epoch(value)


def backend_replay_proof_recompute_or_fallback(proof: BackendReplayProofResult) -> str:
    """Return recomputed backend replay proof checksum or a closed fallback checksum."""
    from aegis.contracts.aegis_backend_replay import recompute_backend_replay_proof_checksum

    try:
        return recompute_backend_replay_proof_checksum(proof)
    except ValueError:
        return _FALLBACK_CHECKSUM


def _source_shape_reason(
    *,
    dispatch_plan: object,
    backend_admission_decision: object,
    capability_lease: object,
    backend_descriptor: object,
    authority_manifest: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
) -> CommandQuarantineReason | None:
    if not isinstance(dispatch_plan, RuntimeDispatchPlan):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_admission_decision, BackendAdmissionDecision):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if type(capability_lease) is not RuntimeCapabilityLease:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(authority_manifest, BackendAuthorityManifest):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_certification, BackendCertificationResult):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_replay_proof, BackendReplayProofResult):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(firewall_decision, DispatchFirewallDecision):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    return None


def _bound_field_drift_reason(
    *,
    quarantine: CommandQuarantineEnvelope | None,
    dispatch_plan: RuntimeDispatchPlan,
    backend_admission_decision: BackendAdmissionDecision,
    capability_lease: RuntimeCapabilityLease,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_manifest: BackendAuthorityManifest,
    registry_checksum: str,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    context_authority_checksum: str,
) -> CommandQuarantineReason | None:
    if capability_lease.dispatch_plan_checksum != dispatch_plan.plan_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT
    if capability_lease.admission_decision_checksum != backend_admission_decision.decision_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if capability_lease.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT
    if capability_lease.authority_manifest_checksum != authority_manifest.manifest_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_MANIFEST_DRIFT
    if capability_lease.registry_checksum != registry_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT
    if capability_lease.certification_checksum != backend_certification.certification_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_CERTIFICATION_DRIFT
    if capability_lease.replay_proof_checksum != backend_replay_proof.proof_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT
    if capability_lease.context_authority_checksum != context_authority_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT
    if (
        backend_admission_decision.backend_descriptor_checksum
        != backend_descriptor.descriptor_checksum
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if (
        backend_admission_decision.authority_manifest_checksum
        != authority_manifest.manifest_checksum
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if backend_admission_decision.registry_checksum != registry_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if (
        backend_admission_decision.certification_checksum
        != backend_certification.certification_checksum
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if backend_admission_decision.replay_proof_checksum != backend_replay_proof.proof_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if quarantine is None:
        return None
    if quarantine.dispatch_plan_checksum != dispatch_plan.plan_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT
    if quarantine.backend_admission_checksum != backend_admission_decision.decision_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
    if quarantine.capability_lease_checksum != capability_lease.lease_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT
    if quarantine.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT
    if quarantine.authority_manifest_checksum != authority_manifest.manifest_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_MANIFEST_DRIFT
    if quarantine.registry_checksum != registry_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT
    if quarantine.certification_checksum != backend_certification.certification_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_CERTIFICATION_DRIFT
    if quarantine.backend_replay_proof_checksum != backend_replay_proof.proof_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT
    if quarantine.context_authority_checksum != context_authority_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT
    return None


def _quarantine_item_from_dispatch_item(item: RuntimeDispatchItem) -> QuarantinedCommandItem:
    if type(item) is not RuntimeDispatchItem:
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    return QuarantinedCommandItem(
        sequence=item.sequence,
        capability=item.capability,
        runtime_kind=item.runtime_kind,
        runtime_name=item.runtime_name,
        namespace=item.namespace,
        message_type=item.message_type,
        qos_profile_checksum=item.qos_profile_checksum,
        payload_checksum=item.payload_checksum,
        payload_size_bytes=item.payload_size_bytes,
        field_map_checksum=item.field_map_checksum,
    )


def _quarantine_item_payload(
    item: QuarantinedCommandItem,
) -> dict[str, CanonicalCommandQuarantineValue]:
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
        "item_checksum": item.item_checksum,
    }


def _recompute_dispatch_plan_checksum_or_fallback(plan: RuntimeDispatchPlan) -> str:
    try:
        return recompute_runtime_dispatch_plan_checksum(plan)
    except ValueError:
        return _FALLBACK_CHECKSUM


def _recompute_descriptor_checksum_or_fallback(descriptor: RuntimeBackendDescriptor) -> str:
    try:
        return recompute_runtime_backend_descriptor_checksum(descriptor)
    except ValueError:
        return _FALLBACK_CHECKSUM


def _recompute_manifest_checksum_or_fallback(manifest: BackendAuthorityManifest) -> str:
    try:
        return recompute_backend_authority_manifest_checksum(manifest)
    except ValueError:
        return _FALLBACK_CHECKSUM


def _recompute_lease_checksum_or_fallback(lease: RuntimeCapabilityLease) -> str:
    try:
        return recompute_runtime_capability_lease_checksum(lease)
    except ValueError:
        return _FALLBACK_CHECKSUM


def _normalize_quarantine_status(value: object) -> CommandQuarantineStatus:
    if isinstance(value, CommandQuarantineStatus):
        if value is CommandQuarantineStatus.QUARANTINED:
            return value
    elif isinstance(value, str) and value == CommandQuarantineStatus.QUARANTINED.value:
        return CommandQuarantineStatus.QUARANTINED
    raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_STATUS_INVALID.value)


def _normalize_runtime_kind(value: object) -> RuntimeDispatchKind:
    if callable(value):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    if isinstance(value, RuntimeDispatchKind):
        return value
    if isinstance(value, str):
        try:
            return RuntimeDispatchKind(value)
        except ValueError:
            raise ValueError("runtime_kind must be an ADR-0017 runtime dispatch kind") from None
    raise ValueError("runtime_kind must be an ADR-0017 runtime dispatch kind")


def _normalize_capability(value: object) -> str:
    normalized = _normalize_required_text(value, "capability")
    if normalized == "*":
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if checksum_or_fallback(normalized) != normalized:
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


def _status_checksum_value(value: CommandQuarantineStatus | str) -> str:
    if isinstance(value, CommandQuarantineStatus):
        return value.value
    return value


def _runtime_kind_checksum_value(value: RuntimeDispatchKind | str) -> str:
    if isinstance(value, RuntimeDispatchKind):
        return value.value
    return value


def _sha256(payload: Mapping[str, CanonicalCommandQuarantineValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalCommandQuarantineValue],
) -> dict[str, CanonicalCommandQuarantineValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalCommandQuarantineValue,
) -> CanonicalCommandQuarantineValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalCommandQuarantineValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "CommandQuarantineEnvelope",
    "CommandQuarantineReason",
    "CommandQuarantineStatus",
    "CommandQuarantineStatusValue",
    "QuarantinedCommandItem",
    "backend_replay_proof_recompute_or_fallback",
    "command_quarantine_envelope_checksum",
    "command_quarantine_evidence_drift_reason",
    "command_quarantine_id",
    "command_quarantine_issue_block_reason",
    "normalize_quarantine_epoch",
    "normalize_quarantined_items",
    "quarantine_item_checksums",
    "quarantine_items_from_dispatch_plan",
    "quarantine_runtime_command",
    "quarantined_command_item_checksum",
    "recompute_command_quarantine_checksum",
    "recompute_quarantined_command_item_checksum",
]
