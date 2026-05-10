"""Deterministic runtime capability lease validation for ADR-0021."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import CAPABILITY_LEASE_CONTRACT_VERSION
from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
)
from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution.aegis_backend_admission import BackendAdmissionDecision
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_capability_lease import (
    CapabilityLeaseReason,
    RuntimeCapabilityLease,
    RuntimeCapabilityLeaseStatus,
    capability_lease_issue_block_reason,
    checksum_or_fallback,
    normalize_lease_epoch,
    recompute_runtime_capability_lease_checksum,
)
from aegis.execution.aegis_runtime_backend import (
    dispatch_plan_capability_scope,
    dispatch_plan_runtime_kind_scope,
)

type LeaseValidationStatusValue = Literal["VALID", "INVALID", "REVOKED"]
type CanonicalLeaseValidationValue = (
    str
    | bool
    | None
    | list[CanonicalLeaseValidationValue]
    | dict[str, CanonicalLeaseValidationValue]
)

_REVOCATION_REASON_CODES = frozenset(
    {
        CapabilityLeaseReason.CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_ADMITTED.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT.value,
        CapabilityLeaseReason.CAPABILITY_LEASE_STALE_EPOCH.value,
    }
)


class LeaseValidationStatus(StrEnum):
    """Closed ADR-0021 lease validation statuses."""

    VALID = "VALID"
    INVALID = "INVALID"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True, init=False)
class LeaseValidationResult:
    """Checksum-bound result of deterministic lease validation."""

    status: LeaseValidationStatusValue
    reason_code: str
    lease_checksum: str
    current_registry_checksum: str
    current_manifest_checksum: str
    current_context_authority_checksum: str
    scope_match: bool
    evidence_chain_match: bool
    validation_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        lease_checksum: object,
        current_registry_checksum: object,
        current_manifest_checksum: object,
        current_context_authority_checksum: object,
        scope_match: object,
        evidence_chain_match: object,
        validation_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_lease = _normalize_required_checksum(lease_checksum, "lease_checksum")
        normalized_registry = _normalize_required_checksum(
            current_registry_checksum, "current_registry_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            current_manifest_checksum, "current_manifest_checksum"
        )
        normalized_context = _normalize_required_checksum(
            current_context_authority_checksum, "current_context_authority_checksum"
        )
        normalized_scope = _normalize_bool(scope_match, "scope_match")
        normalized_evidence = _normalize_bool(evidence_chain_match, "evidence_chain_match")
        if normalized_status == "VALID" and (
            normalized_reason != CapabilityLeaseReason.CAPABILITY_LEASE_VALID.value
            or not normalized_scope
            or not normalized_evidence
        ):
            raise ValueError("VALID lease validation requires matching scope and evidence")
        computed_checksum = lease_validation_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            lease_checksum=normalized_lease,
            current_registry_checksum=normalized_registry,
            current_manifest_checksum=normalized_manifest,
            current_context_authority_checksum=normalized_context,
            scope_match=normalized_scope,
            evidence_chain_match=normalized_evidence,
        )
        normalized_checksum = _normalize_supplied_checksum(
            validation_checksum,
            computed_checksum,
            "validation_checksum",
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "lease_checksum", normalized_lease)
        object.__setattr__(self, "current_registry_checksum", normalized_registry)
        object.__setattr__(self, "current_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "current_context_authority_checksum", normalized_context)
        object.__setattr__(self, "scope_match", normalized_scope)
        object.__setattr__(self, "evidence_chain_match", normalized_evidence)
        object.__setattr__(self, "validation_checksum", normalized_checksum)


def validate_runtime_capability_lease(
    *,
    lease: object,
    admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    dispatch_plan: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> LeaseValidationResult:
    """Validate a runtime capability lease against current explicit evidence.

    Args:
        lease: Candidate runtime capability lease.
        admission_decision: Current backend admission decision.
        backend_descriptor: Current backend descriptor evidence.
        authority_manifest: Current backend authority manifest.
        registry_checksum: Current backend authority registry checksum.
        backend_certification: Current backend certification result.
        backend_replay_proof: Current backend replay proof result.
        dispatch_plan: Current dry-run dispatch plan.
        firewall_decision: Current dispatch firewall decision.
        context_authority_checksum: Current explicit context authority checksum.
        current_lease_epoch: Caller-supplied deterministic epoch; no wall clock is read.

    Returns:
        VALID only when scope and every bound evidence checksum match exactly.
    """
    lease_checksum = _lease_checksum_or_fallback(lease)
    current_registry = checksum_or_fallback(registry_checksum)
    current_manifest = _manifest_checksum_or_fallback(authority_manifest)
    current_context = checksum_or_fallback(context_authority_checksum)
    scope_match = _scope_matches(
        lease=lease,
        authority_manifest=authority_manifest,
        dispatch_plan=dispatch_plan,
    )
    evidence_chain_match = _evidence_chain_matches(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    reason = _first_validation_reason(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if reason is None:
        return LeaseValidationResult(
            status="VALID",
            reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_VALID.value,
            lease_checksum=lease_checksum,
            current_registry_checksum=current_registry,
            current_manifest_checksum=current_manifest,
            current_context_authority_checksum=current_context,
            scope_match=True,
            evidence_chain_match=True,
        )
    status = "REVOKED" if reason.value in _REVOCATION_REASON_CODES else "INVALID"
    return LeaseValidationResult(
        status=status,
        reason_code=reason.value,
        lease_checksum=lease_checksum,
        current_registry_checksum=current_registry,
        current_manifest_checksum=current_manifest,
        current_context_authority_checksum=current_context,
        scope_match=scope_match,
        evidence_chain_match=evidence_chain_match,
    )


def lease_validation_result_checksum(
    *,
    status: LeaseValidationStatusValue,
    reason_code: str,
    lease_checksum: str,
    current_registry_checksum: str,
    current_manifest_checksum: str,
    current_context_authority_checksum: str,
    scope_match: bool,
    evidence_chain_match: bool,
) -> str:
    """Return the deterministic checksum for a lease validation result."""
    return _sha256(
        {
            "capability_lease_contract_version": CAPABILITY_LEASE_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "lease_checksum": lease_checksum,
            "current_registry_checksum": current_registry_checksum,
            "current_manifest_checksum": current_manifest_checksum,
            "current_context_authority_checksum": current_context_authority_checksum,
            "scope_match": scope_match,
            "evidence_chain_match": evidence_chain_match,
        }
    )


def recompute_lease_validation_result_checksum(result: LeaseValidationResult) -> str:
    """Recompute a LeaseValidationResult checksum from authoritative fields."""
    return lease_validation_result_checksum(
        status=result.status,
        reason_code=result.reason_code,
        lease_checksum=result.lease_checksum,
        current_registry_checksum=result.current_registry_checksum,
        current_manifest_checksum=result.current_manifest_checksum,
        current_context_authority_checksum=result.current_context_authority_checksum,
        scope_match=result.scope_match,
        evidence_chain_match=result.evidence_chain_match,
    )


def _first_validation_reason(
    *,
    lease: object,
    admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    dispatch_plan: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> CapabilityLeaseReason | None:
    if type(lease) is not RuntimeCapabilityLease:
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION
    current_lease = lease
    if current_lease.lease_status is not RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY:
        return CapabilityLeaseReason.CAPABILITY_LEASE_STATUS_INVALID
    if current_lease.lease_checksum != _recompute_lease_checksum_or_fallback(current_lease):
        return CapabilityLeaseReason.CAPABILITY_LEASE_CHECKSUM_DRIFT
    epoch = _normalize_epoch_or_none(current_lease_epoch)
    if epoch is None or epoch != current_lease.lease_epoch:
        return CapabilityLeaseReason.CAPABILITY_LEASE_STALE_EPOCH
    issue_reason = capability_lease_issue_block_reason(
        admission_decision=admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        leased_capabilities=current_lease.leased_capabilities,
        leased_runtime_kinds=current_lease.leased_runtime_kinds,
    )
    if issue_reason is not None:
        return issue_reason
    return _lease_bound_field_reason(
        lease=current_lease,
        admission_decision=cast(BackendAdmissionDecision, admission_decision),
        backend_descriptor=cast(RuntimeBackendDescriptor, backend_descriptor),
        authority_manifest=cast(BackendAuthorityManifest, authority_manifest),
        registry_checksum=cast(str, registry_checksum),
        backend_certification=cast(BackendCertificationResult, backend_certification),
        backend_replay_proof=cast(BackendReplayProofResult, backend_replay_proof),
        dispatch_plan=cast(RuntimeDispatchPlan, dispatch_plan),
        firewall_decision=cast(DispatchFirewallDecision, firewall_decision),
        context_authority_checksum=cast(str, context_authority_checksum),
    )


def _lease_bound_field_reason(
    *,
    lease: RuntimeCapabilityLease,
    admission_decision: BackendAdmissionDecision,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_manifest: BackendAuthorityManifest,
    registry_checksum: str,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    dispatch_plan: RuntimeDispatchPlan,
    firewall_decision: DispatchFirewallDecision,
    context_authority_checksum: str,
) -> CapabilityLeaseReason | None:
    if lease.backend_kind != RuntimeBackendKind.NULL_BACKEND_V1.value:
        return CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL
    if lease.backend_descriptor_checksum != backend_descriptor.descriptor_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT
    if lease.admission_decision_checksum != admission_decision.decision_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT
    if lease.authority_manifest_checksum != authority_manifest.manifest_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT
    if lease.registry_checksum != registry_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT
    if lease.certification_checksum != backend_certification.certification_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT
    if lease.replay_proof_checksum != backend_replay_proof.proof_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT
    if lease.dispatch_plan_checksum != dispatch_plan.plan_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT
    if lease.firewall_decision_checksum != firewall_decision.decision_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT
    if lease.context_authority_checksum != context_authority_checksum:
        return CapabilityLeaseReason.CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT
    if not _scope_matches(
        lease=lease, authority_manifest=authority_manifest, dispatch_plan=dispatch_plan
    ):
        if not lease.leased_capabilities.issubset(authority_manifest.allowed_capabilities):
            return CapabilityLeaseReason.CAPABILITY_LEASE_CAPABILITY_OVERCLAIM
        return CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM
    return None


def _scope_matches(
    *,
    lease: object,
    authority_manifest: object,
    dispatch_plan: object,
) -> bool:
    if type(lease) is not RuntimeCapabilityLease:
        return False
    if not isinstance(authority_manifest, BackendAuthorityManifest):
        return False
    if not isinstance(dispatch_plan, RuntimeDispatchPlan):
        return False
    current_lease = lease
    if not current_lease.leased_capabilities or not current_lease.leased_runtime_kinds:
        return False
    if "*" in current_lease.leased_capabilities:
        return False
    return (
        current_lease.leased_capabilities.issubset(authority_manifest.allowed_capabilities)
        and current_lease.leased_runtime_kinds.issubset(authority_manifest.allowed_runtime_kinds)
        and current_lease.leased_capabilities.issubset(
            dispatch_plan_capability_scope(dispatch_plan)
        )
        and current_lease.leased_runtime_kinds.issubset(
            dispatch_plan_runtime_kind_scope(dispatch_plan)
        )
    )


def _evidence_chain_matches(
    *,
    lease: object,
    admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    dispatch_plan: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> bool:
    return (
        _first_validation_reason(
            lease=lease,
            admission_decision=admission_decision,
            backend_descriptor=backend_descriptor,
            authority_manifest=authority_manifest,
            registry_checksum=registry_checksum,
            backend_certification=backend_certification,
            backend_replay_proof=backend_replay_proof,
            dispatch_plan=dispatch_plan,
            firewall_decision=firewall_decision,
            context_authority_checksum=context_authority_checksum,
            current_lease_epoch=current_lease_epoch,
        )
        is None
    )


def _lease_checksum_or_fallback(value: object) -> str:
    if type(value) is RuntimeCapabilityLease:
        return checksum_or_fallback(value.lease_checksum)
    return checksum_or_fallback(getattr(value, "lease_checksum", None))


def _manifest_checksum_or_fallback(value: object) -> str:
    if isinstance(value, BackendAuthorityManifest):
        return checksum_or_fallback(value.manifest_checksum)
    return checksum_or_fallback(getattr(value, "manifest_checksum", None))


def _recompute_lease_checksum_or_fallback(lease: RuntimeCapabilityLease) -> str:
    try:
        return recompute_runtime_capability_lease_checksum(lease)
    except ValueError:
        return "0" * 64


def _normalize_epoch_or_none(value: object) -> int | None:
    try:
        return normalize_lease_epoch(value)
    except ValueError:
        return None


def _normalize_status(value: object) -> LeaseValidationStatusValue:
    if value in {"VALID", "INVALID", "REVOKED"}:
        return cast(LeaseValidationStatusValue, value)
    raise ValueError("status must be VALID, INVALID, or REVOKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool")
    return value


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


def _sha256(payload: Mapping[str, CanonicalLeaseValidationValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalLeaseValidationValue],
) -> dict[str, CanonicalLeaseValidationValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalLeaseValidationValue) -> CanonicalLeaseValidationValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalLeaseValidationValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "LeaseValidationResult",
    "LeaseValidationStatus",
    "LeaseValidationStatusValue",
    "lease_validation_result_checksum",
    "recompute_lease_validation_result_checksum",
    "validate_runtime_capability_lease",
]
