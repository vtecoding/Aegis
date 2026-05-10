"""Deterministic runtime capability lease revocation decisions for ADR-0021."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import CAPABILITY_LEASE_CONTRACT_VERSION
from aegis.execution.aegis_capability_lease import CapabilityLeaseReason, checksum_or_fallback
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease

type LeaseRevocationStatusValue = Literal["REVOKED", "NOT_REVOKED"]
type CanonicalLeaseRevocationValue = (
    str | None | list[CanonicalLeaseRevocationValue] | dict[str, CanonicalLeaseRevocationValue]
)


class LeaseRevocationStatus(StrEnum):
    """Closed ADR-0021 lease revocation statuses."""

    REVOKED = "REVOKED"
    NOT_REVOKED = "NOT_REVOKED"


@dataclass(frozen=True, slots=True, init=False)
class LeaseRevocationDecision:
    """Checksum-bound deterministic lease revocation decision."""

    status: LeaseRevocationStatusValue
    reason_code: str
    lease_checksum: str
    revoked_evidence_checksum: str
    revocation_stage: str
    revocation_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        lease_checksum: object,
        revoked_evidence_checksum: object,
        revocation_stage: object,
        revocation_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_lease = _normalize_required_checksum(lease_checksum, "lease_checksum")
        normalized_evidence = _normalize_required_checksum(
            revoked_evidence_checksum, "revoked_evidence_checksum"
        )
        normalized_stage = _normalize_stage(revocation_stage)
        if normalized_status == "NOT_REVOKED" and (
            normalized_reason != CapabilityLeaseReason.CAPABILITY_LEASE_NOT_REVOKED.value
            or normalized_stage != "none"
        ):
            raise ValueError("NOT_REVOKED decisions require not-revoked reason and none stage")
        if normalized_status == "REVOKED" and normalized_stage == "none":
            raise ValueError("REVOKED decisions require a revocation stage")
        computed_checksum = lease_revocation_decision_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            lease_checksum=normalized_lease,
            revoked_evidence_checksum=normalized_evidence,
            revocation_stage=normalized_stage,
        )
        normalized_checksum = _normalize_supplied_checksum(
            revocation_checksum,
            computed_checksum,
            "revocation_checksum",
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "lease_checksum", normalized_lease)
        object.__setattr__(self, "revoked_evidence_checksum", normalized_evidence)
        object.__setattr__(self, "revocation_stage", normalized_stage)
        object.__setattr__(self, "revocation_checksum", normalized_checksum)


def evaluate_runtime_lease_revocation(
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
) -> LeaseRevocationDecision:
    """Return a deterministic revocation decision for current lease evidence.

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
        current_lease_epoch: Caller-supplied deterministic epoch.

    Returns:
        NOT_REVOKED only when validation is VALID; otherwise REVOKED with a reason code.
    """
    validation = validate_runtime_capability_lease(
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
    if validation.status == "VALID":
        return LeaseRevocationDecision(
            status="NOT_REVOKED",
            reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_NOT_REVOKED.value,
            lease_checksum=validation.lease_checksum,
            revoked_evidence_checksum=validation.validation_checksum,
            revocation_stage="none",
        )
    return LeaseRevocationDecision(
        status="REVOKED",
        reason_code=validation.reason_code,
        lease_checksum=validation.lease_checksum,
        revoked_evidence_checksum=validation.validation_checksum,
        revocation_stage=revocation_stage_for_reason(validation.reason_code),
    )


def revocation_stage_for_reason(reason_code: str) -> str:
    """Return the deterministic revocation stage for a validation reason code."""
    stage_by_reason = {
        CapabilityLeaseReason.CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND.value: "backend_kind",
        CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_NULL.value: "backend_kind",
        CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_ADMITTED.value: "admission",
        CapabilityLeaseReason.CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT.value: (
            "admission"
        ),
        CapabilityLeaseReason.CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT.value: "registry",
        CapabilityLeaseReason.CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT.value: "manifest",
        CapabilityLeaseReason.CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT.value: "descriptor",
        CapabilityLeaseReason.CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT.value: (
            "certification"
        ),
        CapabilityLeaseReason.CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT.value: "replay",
        CapabilityLeaseReason.CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT.value: "dispatch",
        CapabilityLeaseReason.CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT.value: ("firewall"),
        CapabilityLeaseReason.CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT.value: (
            "context_authority"
        ),
        CapabilityLeaseReason.CAPABILITY_LEASE_CAPABILITY_OVERCLAIM.value: "scope",
        CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM.value: "scope",
        CapabilityLeaseReason.CAPABILITY_LEASE_WILDCARD_SCOPE.value: "scope",
        CapabilityLeaseReason.CAPABILITY_LEASE_EMPTY_SCOPE.value: "scope",
        CapabilityLeaseReason.CAPABILITY_LEASE_STALE_EPOCH.value: "lease_epoch",
        CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value: "lease_shape",
        CapabilityLeaseReason.CAPABILITY_LEASE_CHECKSUM_DRIFT.value: "lease_checksum",
        CapabilityLeaseReason.CAPABILITY_LEASE_STATUS_INVALID.value: "lease_status",
    }
    return stage_by_reason.get(reason_code, "lease_validation")


def lease_revocation_decision_checksum(
    *,
    status: LeaseRevocationStatusValue,
    reason_code: str,
    lease_checksum: str,
    revoked_evidence_checksum: str,
    revocation_stage: str,
) -> str:
    """Return the deterministic checksum for a lease revocation decision."""
    return _sha256(
        {
            "capability_lease_contract_version": CAPABILITY_LEASE_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "lease_checksum": lease_checksum,
            "revoked_evidence_checksum": revoked_evidence_checksum,
            "revocation_stage": revocation_stage,
        }
    )


def recompute_lease_revocation_decision_checksum(decision: LeaseRevocationDecision) -> str:
    """Recompute a LeaseRevocationDecision checksum from authoritative fields."""
    return lease_revocation_decision_checksum(
        status=decision.status,
        reason_code=decision.reason_code,
        lease_checksum=decision.lease_checksum,
        revoked_evidence_checksum=decision.revoked_evidence_checksum,
        revocation_stage=decision.revocation_stage,
    )


def _normalize_status(value: object) -> LeaseRevocationStatusValue:
    if value in {"REVOKED", "NOT_REVOKED"}:
        return cast(LeaseRevocationStatusValue, value)
    raise ValueError("status must be REVOKED or NOT_REVOKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_stage(value: object) -> str:
    normalized = _normalize_required_text(value, "revocation_stage")
    if not all(
        character.islower() or character.isdigit() or character == "_" for character in normalized
    ):
        raise ValueError("revocation_stage must be a lowercase machine identifier")
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


def _sha256(payload: Mapping[str, CanonicalLeaseRevocationValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalLeaseRevocationValue],
) -> dict[str, CanonicalLeaseRevocationValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalLeaseRevocationValue) -> CanonicalLeaseRevocationValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalLeaseRevocationValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "LeaseRevocationDecision",
    "LeaseRevocationStatus",
    "LeaseRevocationStatusValue",
    "evaluate_runtime_lease_revocation",
    "lease_revocation_decision_checksum",
    "recompute_lease_revocation_decision_checksum",
    "revocation_stage_for_reason",
]
