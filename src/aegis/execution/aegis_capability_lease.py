"""Checksum-bound runtime capability leases for ADR-0021."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, cast

from aegis.aegis_constants import CAPABILITY_LEASE_CONTRACT_VERSION
from aegis.contracts.aegis_backend_replay import (
    BackendReplayProofResult,
    recompute_backend_replay_proof_checksum,
)
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    BackendCertificationStatus,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    recompute_backend_certification_checksum,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.aegis_runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchKind,
    RuntimeDispatchMode,
    RuntimeDispatchPlan,
    recompute_dispatch_firewall_decision_checksum,
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
from aegis.execution.aegis_runtime_backend import (
    dispatch_plan_capability_scope,
    dispatch_plan_runtime_kind_scope,
)

type RuntimeCapabilityLeaseStatusValue = Literal["ACTIVE_NULL_ONLY"]
type CanonicalCapabilityLeaseValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalCapabilityLeaseValue]
    | dict[str, CanonicalCapabilityLeaseValue]
)

_FALLBACK_CHECKSUM = "0" * 64
_LEASE_CONSTRUCTION_TOKEN = object()


class RuntimeCapabilityLeaseStatus(StrEnum):
    """Closed ADR-0021 runtime capability lease statuses."""

    ACTIVE_NULL_ONLY = "ACTIVE_NULL_ONLY"


class CapabilityLeaseReason(StrEnum):
    """Stable ADR-0021 capability lease reason codes."""

    CAPABILITY_LEASE_ISSUED_NULL_BACKEND = "CAPABILITY_LEASE_ISSUED_NULL_BACKEND"
    CAPABILITY_LEASE_VALID = "CAPABILITY_LEASE_VALID"
    CAPABILITY_LEASE_NOT_REVOKED = "CAPABILITY_LEASE_NOT_REVOKED"
    CAPABILITY_LEASE_REVOKED = "CAPABILITY_LEASE_REVOKED"
    CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND = "CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND"
    CAPABILITY_LEASE_BACKEND_NOT_NULL = "CAPABILITY_LEASE_BACKEND_NOT_NULL"
    CAPABILITY_LEASE_BACKEND_NOT_ADMITTED = "CAPABILITY_LEASE_BACKEND_NOT_ADMITTED"
    CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT = (
        "CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT"
    )
    CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT = "CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT = "CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT = "CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT = "CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT = "CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT = "CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT = (
        "CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT"
    )
    CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT = (
        "CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT"
    )
    CAPABILITY_LEASE_CAPABILITY_OVERCLAIM = "CAPABILITY_LEASE_CAPABILITY_OVERCLAIM"
    CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM = "CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM"
    CAPABILITY_LEASE_WILDCARD_SCOPE = "CAPABILITY_LEASE_WILDCARD_SCOPE"
    CAPABILITY_LEASE_EMPTY_SCOPE = "CAPABILITY_LEASE_EMPTY_SCOPE"
    CAPABILITY_LEASE_STALE_EPOCH = "CAPABILITY_LEASE_STALE_EPOCH"
    CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION = "CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION"
    CAPABILITY_LEASE_CHECKSUM_DRIFT = "CAPABILITY_LEASE_CHECKSUM_DRIFT"
    CAPABILITY_LEASE_STATUS_INVALID = "CAPABILITY_LEASE_STATUS_INVALID"
    DIRECT_CAPABILITY_LEASE_CONSTRUCTION = "DIRECT_CAPABILITY_LEASE_CONSTRUCTION"


@dataclass(frozen=True, slots=True, init=False)
class RuntimeCapabilityLease:
    """Immutable capability lease for an admitted null runtime backend."""

    lease_id: str
    backend_kind: str
    backend_descriptor_checksum: str
    admission_decision_checksum: str
    authority_manifest_checksum: str
    registry_checksum: str
    certification_checksum: str
    replay_proof_checksum: str
    dispatch_plan_checksum: str
    firewall_decision_checksum: str
    context_authority_checksum: str
    leased_capabilities: frozenset[str]
    leased_runtime_kinds: frozenset[RuntimeDispatchKind]
    lease_epoch: int
    lease_status: RuntimeCapabilityLeaseStatus
    lease_checksum: str

    def __init__(
        self,
        *,
        lease_id: object,
        backend_kind: object,
        backend_descriptor_checksum: object,
        admission_decision_checksum: object,
        authority_manifest_checksum: object,
        registry_checksum: object,
        certification_checksum: object,
        replay_proof_checksum: object,
        dispatch_plan_checksum: object,
        firewall_decision_checksum: object,
        context_authority_checksum: object,
        leased_capabilities: Iterable[object],
        leased_runtime_kinds: Iterable[object],
        lease_epoch: object,
        lease_status: object,
        lease_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _LEASE_CONSTRUCTION_TOKEN:
            raise ValueError(CapabilityLeaseReason.DIRECT_CAPABILITY_LEASE_CONSTRUCTION.value)
        normalized_id = _normalize_required_checksum(lease_id, "lease_id")
        normalized_kind = _normalize_backend_kind_label(backend_kind)
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_admission = _normalize_required_checksum(
            admission_decision_checksum, "admission_decision_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            authority_manifest_checksum, "authority_manifest_checksum"
        )
        normalized_registry = _normalize_required_checksum(registry_checksum, "registry_checksum")
        normalized_certification = _normalize_required_checksum(
            certification_checksum, "certification_checksum"
        )
        normalized_replay = _normalize_required_checksum(
            replay_proof_checksum, "replay_proof_checksum"
        )
        normalized_dispatch = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_firewall = _normalize_required_checksum(
            firewall_decision_checksum, "firewall_decision_checksum"
        )
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        normalized_capabilities = normalize_lease_capabilities(leased_capabilities)
        normalized_runtime_kinds = normalize_lease_runtime_kinds(leased_runtime_kinds)
        normalized_epoch = normalize_lease_epoch(lease_epoch)
        normalized_status = _normalize_lease_status(lease_status)
        computed_checksum = runtime_capability_lease_checksum(
            lease_id=normalized_id,
            backend_kind=normalized_kind,
            backend_descriptor_checksum=normalized_descriptor,
            admission_decision_checksum=normalized_admission,
            authority_manifest_checksum=normalized_manifest,
            registry_checksum=normalized_registry,
            certification_checksum=normalized_certification,
            replay_proof_checksum=normalized_replay,
            dispatch_plan_checksum=normalized_dispatch,
            firewall_decision_checksum=normalized_firewall,
            context_authority_checksum=normalized_context,
            leased_capabilities=normalized_capabilities,
            leased_runtime_kinds=normalized_runtime_kinds,
            lease_epoch=normalized_epoch,
            lease_status=normalized_status,
        )
        normalized_checksum = _normalize_supplied_checksum(
            lease_checksum, computed_checksum, "lease_checksum"
        )

        object.__setattr__(self, "lease_id", normalized_id)
        object.__setattr__(self, "backend_kind", normalized_kind)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(self, "admission_decision_checksum", normalized_admission)
        object.__setattr__(self, "authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "registry_checksum", normalized_registry)
        object.__setattr__(self, "certification_checksum", normalized_certification)
        object.__setattr__(self, "replay_proof_checksum", normalized_replay)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_dispatch)
        object.__setattr__(self, "firewall_decision_checksum", normalized_firewall)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "leased_capabilities", normalized_capabilities)
        object.__setattr__(self, "leased_runtime_kinds", normalized_runtime_kinds)
        object.__setattr__(self, "lease_epoch", normalized_epoch)
        object.__setattr__(self, "lease_status", normalized_status)
        object.__setattr__(self, "lease_checksum", normalized_checksum)


def issue_runtime_capability_lease(
    *,
    admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    dispatch_plan: object,
    firewall_decision: object,
    context_authority_checksum: object,
    leased_capabilities: Iterable[object],
    leased_runtime_kinds: Iterable[object],
    lease_epoch: object,
) -> RuntimeCapabilityLease:
    """Issue an active lease only for admitted, checksum-bound NULL_BACKEND_V1 evidence.

    Args:
        admission_decision: Current ADR-0020 admitted backend decision.
        backend_descriptor: Runtime backend descriptor bound by the admission chain.
        authority_manifest: Registry manifest for the backend kind.
        registry_checksum: Current closed registry checksum.
        backend_certification: ADR-0018 backend certification result.
        backend_replay_proof: ADR-0019 backend replay proof result.
        dispatch_plan: Dry-run dispatch plan bound into certification.
        firewall_decision: Dispatch firewall decision bound into certification.
        context_authority_checksum: Explicit caller/context authority checksum.
        leased_capabilities: Non-empty subset of admitted backend capabilities.
        leased_runtime_kinds: Non-empty subset of admitted runtime kinds.
        lease_epoch: Caller-supplied deterministic lease epoch.

    Returns:
        A checksum-bound RuntimeCapabilityLease.

    Raises:
        ValueError: If any admission, evidence, scope, or epoch check fails closed.
    """
    capabilities = normalize_lease_capabilities(leased_capabilities)
    runtime_kinds = normalize_lease_runtime_kinds(leased_runtime_kinds)
    epoch = normalize_lease_epoch(lease_epoch)
    context_checksum = _normalize_required_checksum(
        context_authority_checksum, "context_authority_checksum"
    )
    issue_reason = capability_lease_issue_block_reason(
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        leased_capabilities=capabilities,
        leased_runtime_kinds=runtime_kinds,
    )
    if issue_reason is not None:
        raise ValueError(issue_reason.value)

    decision = cast(BackendAdmissionDecision, admission_decision)
    descriptor = cast(RuntimeBackendDescriptor, backend_descriptor)
    manifest = cast(BackendAuthorityManifest, authority_manifest)
    certification = cast(BackendCertificationResult, backend_certification)
    replay_proof = cast(BackendReplayProofResult, backend_replay_proof)
    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    decision_firewall = cast(DispatchFirewallDecision, firewall_decision)
    normalized_registry = _normalize_required_checksum(registry_checksum, "registry_checksum")
    lease_id = runtime_capability_lease_id(
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1.value,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        admission_decision_checksum=decision.decision_checksum,
        authority_manifest_checksum=manifest.manifest_checksum,
        registry_checksum=normalized_registry,
        certification_checksum=certification.certification_checksum,
        replay_proof_checksum=replay_proof.proof_checksum,
        dispatch_plan_checksum=plan.plan_checksum,
        firewall_decision_checksum=decision_firewall.decision_checksum,
        context_authority_checksum=context_checksum,
        leased_capabilities=capabilities,
        leased_runtime_kinds=runtime_kinds,
        lease_epoch=epoch,
        lease_status=RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY,
    )
    return RuntimeCapabilityLease(
        lease_id=lease_id,
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1.value,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        admission_decision_checksum=decision.decision_checksum,
        authority_manifest_checksum=manifest.manifest_checksum,
        registry_checksum=normalized_registry,
        certification_checksum=certification.certification_checksum,
        replay_proof_checksum=replay_proof.proof_checksum,
        dispatch_plan_checksum=plan.plan_checksum,
        firewall_decision_checksum=decision_firewall.decision_checksum,
        context_authority_checksum=context_checksum,
        leased_capabilities=capabilities,
        leased_runtime_kinds=runtime_kinds,
        lease_epoch=epoch,
        lease_status=RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY,
        _construction_token=_LEASE_CONSTRUCTION_TOKEN,
    )


def capability_lease_issue_block_reason(
    *,
    admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    dispatch_plan: object,
    firewall_decision: object,
    leased_capabilities: frozenset[str],
    leased_runtime_kinds: frozenset[RuntimeDispatchKind],
) -> CapabilityLeaseReason | None:
    """Return the first deterministic reason a lease cannot be issued."""
    if not isinstance(admission_decision, BackendAdmissionDecision):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(authority_manifest, BackendAuthorityManifest):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_certification, BackendCertificationResult):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_replay_proof, BackendReplayProofResult):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(dispatch_plan, RuntimeDispatchPlan):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    if not isinstance(firewall_decision, DispatchFirewallDecision):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    return _evidence_block_reason(
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        leased_capabilities=leased_capabilities,
        leased_runtime_kinds=leased_runtime_kinds,
    )


def runtime_capability_lease_id(
    *,
    backend_kind: str,
    backend_descriptor_checksum: str,
    admission_decision_checksum: str,
    authority_manifest_checksum: str,
    registry_checksum: str,
    certification_checksum: str,
    replay_proof_checksum: str,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    context_authority_checksum: str,
    leased_capabilities: Iterable[str],
    leased_runtime_kinds: Iterable[RuntimeDispatchKind | str],
    lease_epoch: int,
    lease_status: RuntimeCapabilityLeaseStatus | str,
) -> str:
    """Return the deterministic identifier for a runtime capability lease."""
    return _sha256(
        {
            "capability_lease_contract_version": CAPABILITY_LEASE_CONTRACT_VERSION,
            "backend_kind": backend_kind,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "admission_decision_checksum": admission_decision_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "registry_checksum": registry_checksum,
            "certification_checksum": certification_checksum,
            "replay_proof_checksum": replay_proof_checksum,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "context_authority_checksum": context_authority_checksum,
            "leased_capabilities": _canonical_string_sequence(sorted(leased_capabilities)),
            "leased_runtime_kinds": _canonical_string_sequence(
                sorted(
                    _runtime_kind_checksum_value(runtime_kind)
                    for runtime_kind in leased_runtime_kinds
                )
            ),
            "lease_epoch": lease_epoch,
            "lease_status": _lease_status_checksum_value(lease_status),
        }
    )


def runtime_capability_lease_checksum(
    *,
    lease_id: str,
    backend_kind: str,
    backend_descriptor_checksum: str,
    admission_decision_checksum: str,
    authority_manifest_checksum: str,
    registry_checksum: str,
    certification_checksum: str,
    replay_proof_checksum: str,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    context_authority_checksum: str,
    leased_capabilities: Iterable[str],
    leased_runtime_kinds: Iterable[RuntimeDispatchKind | str],
    lease_epoch: int,
    lease_status: RuntimeCapabilityLeaseStatus | str,
) -> str:
    """Return the deterministic checksum for a runtime capability lease."""
    return _sha256(
        {
            "capability_lease_contract_version": CAPABILITY_LEASE_CONTRACT_VERSION,
            "lease_id": lease_id,
            "backend_kind": backend_kind,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "admission_decision_checksum": admission_decision_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "registry_checksum": registry_checksum,
            "certification_checksum": certification_checksum,
            "replay_proof_checksum": replay_proof_checksum,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "context_authority_checksum": context_authority_checksum,
            "leased_capabilities": _canonical_string_sequence(sorted(leased_capabilities)),
            "leased_runtime_kinds": _canonical_string_sequence(
                sorted(
                    _runtime_kind_checksum_value(runtime_kind)
                    for runtime_kind in leased_runtime_kinds
                )
            ),
            "lease_epoch": lease_epoch,
            "lease_status": _lease_status_checksum_value(lease_status),
        }
    )


def recompute_runtime_capability_lease_checksum(lease: RuntimeCapabilityLease) -> str:
    """Recompute a RuntimeCapabilityLease checksum from authoritative fields."""
    return runtime_capability_lease_checksum(
        lease_id=lease.lease_id,
        backend_kind=lease.backend_kind,
        backend_descriptor_checksum=lease.backend_descriptor_checksum,
        admission_decision_checksum=lease.admission_decision_checksum,
        authority_manifest_checksum=lease.authority_manifest_checksum,
        registry_checksum=lease.registry_checksum,
        certification_checksum=lease.certification_checksum,
        replay_proof_checksum=lease.replay_proof_checksum,
        dispatch_plan_checksum=lease.dispatch_plan_checksum,
        firewall_decision_checksum=lease.firewall_decision_checksum,
        context_authority_checksum=lease.context_authority_checksum,
        leased_capabilities=lease.leased_capabilities,
        leased_runtime_kinds=lease.leased_runtime_kinds,
        lease_epoch=lease.lease_epoch,
        lease_status=lease.lease_status,
    )


def normalize_lease_capabilities(values: Iterable[object]) -> frozenset[str]:
    """Normalize explicit leased capabilities into an immutable non-wildcard scope."""
    if isinstance(values, (str, Mapping)):
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value)
    normalized = frozenset(_normalize_capability(value) for value in values)
    if not normalized:
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_EMPTY_SCOPE.value)
    return normalized


def normalize_lease_runtime_kinds(values: Iterable[object]) -> frozenset[RuntimeDispatchKind]:
    """Normalize explicit leased runtime kinds into an immutable non-wildcard scope."""
    if isinstance(values, (str, Mapping)):
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value)
    normalized: set[RuntimeDispatchKind] = set()
    for value in values:
        if callable(value):
            raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value)
        if value == "*":
            raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_WILDCARD_SCOPE.value)
        if isinstance(value, RuntimeDispatchKind):
            normalized.add(value)
            continue
        if isinstance(value, str):
            try:
                normalized.add(RuntimeDispatchKind(value))
            except ValueError:
                raise ValueError("leased_runtime_kinds contains an undeclared kind") from None
            continue
        raise ValueError("leased_runtime_kinds must contain RuntimeDispatchKind values")
    if not normalized:
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_EMPTY_SCOPE.value)
    return frozenset(normalized)


def normalize_lease_epoch(value: object) -> int:
    """Normalize an explicit deterministic lease epoch."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("lease_epoch must be an integer")
    if value < 0:
        raise ValueError("lease_epoch must be >= 0")
    return value


def checksum_or_fallback(value: object) -> str:
    """Return a valid checksum string or the closed fallback checksum."""
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return _FALLBACK_CHECKSUM


def _evidence_block_reason(
    *,
    admission_decision: BackendAdmissionDecision,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_manifest: BackendAuthorityManifest,
    registry_checksum: object,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    dispatch_plan: RuntimeDispatchPlan,
    firewall_decision: DispatchFirewallDecision,
    leased_capabilities: frozenset[str],
    leased_runtime_kinds: frozenset[RuntimeDispatchKind],
) -> CapabilityLeaseReason | None:
    if admission_decision.status != "ADMITTED":
        return CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_ADMITTED
    if admission_decision.backend_kind != RuntimeBackendKind.NULL_BACKEND_V1.value:
        return CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL
    if backend_descriptor.backend_kind is not RuntimeBackendKind.NULL_BACKEND_V1:
        return CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL
    if authority_manifest.backend_kind is not RuntimeBackendKind.NULL_BACKEND_V1:
        return CapabilityLeaseReason.CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND
    if backend_descriptor.descriptor_checksum != _recompute_descriptor_checksum_or_fallback(
        backend_descriptor
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT
    if admission_decision.decision_checksum != recompute_backend_admission_decision_checksum(
        admission_decision
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if authority_manifest.manifest_checksum != _recompute_manifest_checksum_or_fallback(
        authority_manifest
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT
    expected_registry_checksum = backend_authority_registry_checksum((authority_manifest,))
    if registry_checksum != expected_registry_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT
    if backend_certification.certification_checksum != recompute_backend_certification_checksum(
        backend_certification
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if backend_replay_proof.proof_checksum != recompute_backend_replay_proof_checksum(
        backend_replay_proof
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if dispatch_plan.plan_checksum != recompute_runtime_dispatch_plan_checksum(dispatch_plan):
        return CapabilityLeaseReason.CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT
    if firewall_decision.decision_checksum != recompute_dispatch_firewall_decision_checksum(
        firewall_decision
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT
    chain_reason = _chain_binding_reason(
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=cast(str, registry_checksum),
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
    )
    if chain_reason is not None:
        return chain_reason
    if not leased_capabilities.issubset(authority_manifest.allowed_capabilities):
        return CapabilityLeaseReason.CAPABILITY_LEASE_CAPABILITY_OVERCLAIM
    if not leased_runtime_kinds.issubset(authority_manifest.allowed_runtime_kinds):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM
    if not leased_capabilities.issubset(dispatch_plan_capability_scope(dispatch_plan)):
        return CapabilityLeaseReason.CAPABILITY_LEASE_CAPABILITY_OVERCLAIM
    if not leased_runtime_kinds.issubset(dispatch_plan_runtime_kind_scope(dispatch_plan)):
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM
    return None


def _chain_binding_reason(
    *,
    admission_decision: BackendAdmissionDecision,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_manifest: BackendAuthorityManifest,
    registry_checksum: str,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    dispatch_plan: RuntimeDispatchPlan,
    firewall_decision: DispatchFirewallDecision,
) -> CapabilityLeaseReason | None:
    if admission_decision.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if admission_decision.authority_manifest_checksum != authority_manifest.manifest_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if admission_decision.registry_checksum != registry_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if admission_decision.certification_checksum != backend_certification.certification_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if admission_decision.replay_proof_checksum != backend_replay_proof.proof_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if backend_certification.status is not BackendCertificationStatus.CERTIFIED_NULL:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if backend_certification.dispatch_plan_checksum != dispatch_plan.plan_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if backend_certification.firewall_decision_checksum != firewall_decision.decision_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if backend_certification.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if backend_replay_proof.status != "PASSED":
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if backend_replay_proof.dispatch_plan_checksum != dispatch_plan.plan_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if backend_replay_proof.firewall_decision_checksum != firewall_decision.decision_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if backend_replay_proof.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if (
        backend_replay_proof.expected_certification_checksum
        != backend_certification.certification_checksum
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if (
        backend_replay_proof.replayed_certification_checksum
        != backend_certification.certification_checksum
    ):
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if firewall_decision.status != "ALLOWED_DRY_RUN":
        return CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT
    if firewall_decision.plan_checksum != dispatch_plan.plan_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT
    if dispatch_plan.dispatch_mode is not RuntimeDispatchMode.DRY_RUN_ONLY:
        return CapabilityLeaseReason.CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT
    return None


def _normalize_capability(value: object) -> str:
    if callable(value):
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value)
    if not isinstance(value, str):
        raise ValueError("leased_capabilities must contain strings")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_EMPTY_SCOPE.value)
    if normalized != value:
        raise ValueError("leased_capabilities must not contain surrounding whitespace")
    if normalized == "*":
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_WILDCARD_SCOPE.value)
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("leased_capabilities must be canonical dotted lowercase identifiers")
    return normalized


def _normalize_lease_status(value: object) -> RuntimeCapabilityLeaseStatus:
    if isinstance(value, RuntimeCapabilityLeaseStatus):
        if value is RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY:
            return value
    elif isinstance(value, str) and value == RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY.value:
        return RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY
    raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_STATUS_INVALID.value)


def _normalize_backend_kind_label(value: object) -> str:
    if isinstance(value, RuntimeBackendKind):
        value = value.value
    normalized = _normalize_required_text(value, "backend_kind")
    if normalized != RuntimeBackendKind.NULL_BACKEND_V1.value:
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL.value)
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value)
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


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalCapabilityLeaseValue]:
    return [str(value) for value in values]


def _runtime_kind_checksum_value(value: RuntimeDispatchKind | str) -> str:
    if isinstance(value, RuntimeDispatchKind):
        return value.value
    return value


def _lease_status_checksum_value(value: RuntimeCapabilityLeaseStatus | str) -> str:
    if isinstance(value, RuntimeCapabilityLeaseStatus):
        return value.value
    return value


def _sha256(payload: Mapping[str, CanonicalCapabilityLeaseValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalCapabilityLeaseValue],
) -> dict[str, CanonicalCapabilityLeaseValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalCapabilityLeaseValue) -> CanonicalCapabilityLeaseValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalCapabilityLeaseValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "CapabilityLeaseReason",
    "RuntimeCapabilityLease",
    "RuntimeCapabilityLeaseStatus",
    "RuntimeCapabilityLeaseStatusValue",
    "capability_lease_issue_block_reason",
    "checksum_or_fallback",
    "issue_runtime_capability_lease",
    "normalize_lease_capabilities",
    "normalize_lease_epoch",
    "normalize_lease_runtime_kinds",
    "recompute_runtime_capability_lease_checksum",
    "runtime_capability_lease_checksum",
    "runtime_capability_lease_id",
]
