"""Structural operator identity claims and deterministic approval nonces for ADR-0023."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from aegis.aegis_constants import OPERATOR_AUTHORITY_CONTRACT_VERSION
from aegis.execution.aegis_capability_lease import checksum_or_fallback
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    recompute_command_quarantine_checksum,
)
from aegis.execution.aegis_operator_approval import normalize_operator_id
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityManifest,
    OperatorAuthorityReason,
    normalize_operator_authority_epoch,
    normalize_operator_role,
    recompute_operator_authority_manifest_checksum,
)

type CanonicalOperatorIdentityValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalOperatorIdentityValue]
    | dict[str, CanonicalOperatorIdentityValue]
)


@dataclass(frozen=True, slots=True, init=False)
class OperatorIdentityClaim:
    """Checksum-bound structural operator identity claim."""

    operator_id: str
    operator_role: str
    operator_authority_manifest_checksum: str
    context_authority_checksum: str
    identity_epoch: int
    identity_checksum: str

    def __init__(
        self,
        *,
        operator_id: object,
        operator_role: object,
        operator_authority_manifest_checksum: object,
        context_authority_checksum: object,
        identity_epoch: object,
        identity_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_operator_id(operator_id)
        normalized_role = normalize_operator_role(operator_role)
        normalized_manifest = _normalize_required_checksum(
            operator_authority_manifest_checksum, "operator_authority_manifest_checksum"
        )
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        normalized_epoch = normalize_operator_authority_epoch(identity_epoch)
        computed_checksum = operator_identity_claim_checksum(
            operator_id=normalized_id,
            operator_role=normalized_role,
            operator_authority_manifest_checksum=normalized_manifest,
            context_authority_checksum=normalized_context,
            identity_epoch=normalized_epoch,
        )
        normalized_checksum = _normalize_supplied_checksum(
            identity_checksum, computed_checksum, "identity_checksum"
        )

        object.__setattr__(self, "operator_id", normalized_id)
        object.__setattr__(self, "operator_role", normalized_role)
        object.__setattr__(self, "operator_authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "identity_epoch", normalized_epoch)
        object.__setattr__(self, "identity_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class OperatorApprovalNonce:
    """Deterministic nonce evidence binding one operator identity to one quarantine."""

    nonce_id: str
    quarantine_checksum: str
    operator_identity_checksum: str
    approval_epoch: int
    nonce_checksum: str

    def __init__(
        self,
        *,
        nonce_id: object,
        quarantine_checksum: object,
        operator_identity_checksum: object,
        approval_epoch: object,
        nonce_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_required_checksum(nonce_id, "nonce_id")
        normalized_quarantine = _normalize_required_checksum(
            quarantine_checksum, "quarantine_checksum"
        )
        normalized_identity = _normalize_required_checksum(
            operator_identity_checksum, "operator_identity_checksum"
        )
        normalized_epoch = normalize_operator_authority_epoch(approval_epoch)
        computed_checksum = operator_approval_nonce_checksum(
            nonce_id=normalized_id,
            quarantine_checksum=normalized_quarantine,
            operator_identity_checksum=normalized_identity,
            approval_epoch=normalized_epoch,
        )
        normalized_checksum = _normalize_supplied_checksum(
            nonce_checksum, computed_checksum, "nonce_checksum"
        )

        object.__setattr__(self, "nonce_id", normalized_id)
        object.__setattr__(self, "quarantine_checksum", normalized_quarantine)
        object.__setattr__(self, "operator_identity_checksum", normalized_identity)
        object.__setattr__(self, "approval_epoch", normalized_epoch)
        object.__setattr__(self, "nonce_checksum", normalized_checksum)


def build_operator_identity_claim(
    *,
    manifest: object,
    operator_id: object,
    operator_role: object,
    context_authority_checksum: object,
    identity_epoch: object,
) -> OperatorIdentityClaim:
    """Build an identity claim for an operator role registered in the manifest."""
    if type(manifest) is not OperatorAuthorityManifest:
        raise ValueError(
            OperatorAuthorityReason.OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST.value
        )
    current_manifest = manifest
    if current_manifest.manifest_checksum != recompute_operator_authority_manifest_checksum(
        current_manifest
    ):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value)
    normalized_role = normalize_operator_role(operator_role)
    if normalized_role not in current_manifest.allowed_operator_roles:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE.value)
    normalized_context = _normalize_required_checksum(
        context_authority_checksum, "context_authority_checksum"
    )
    if normalized_context != current_manifest.required_context_authority_checksum:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT.value)
    normalized_epoch = normalize_operator_authority_epoch(identity_epoch)
    if normalized_epoch != current_manifest.approval_epoch:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value)
    return OperatorIdentityClaim(
        operator_id=_normalize_operator_id(operator_id),
        operator_role=normalized_role,
        operator_authority_manifest_checksum=current_manifest.manifest_checksum,
        context_authority_checksum=normalized_context,
        identity_epoch=normalized_epoch,
    )


def build_operator_approval_nonce(
    *,
    quarantine: object,
    operator_identity: object,
    approval_epoch: object,
) -> OperatorApprovalNonce:
    """Build deterministic nonce evidence for one quarantine and identity claim."""
    if type(quarantine) is not CommandQuarantineEnvelope:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
    if type(operator_identity) is not OperatorIdentityClaim:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
    current_quarantine = quarantine
    current_identity = operator_identity
    if current_quarantine.quarantine_checksum != recompute_command_quarantine_checksum(
        current_quarantine
    ):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_CHECKSUM_DRIFT.value)
    if current_identity.identity_checksum != recompute_operator_identity_claim_checksum(
        current_identity
    ):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT.value)
    normalized_epoch = normalize_operator_authority_epoch(approval_epoch)
    if normalized_epoch != current_quarantine.quarantine_epoch:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value)
    if normalized_epoch != current_identity.identity_epoch:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value)
    nonce_id = operator_approval_nonce_id(
        quarantine_checksum=current_quarantine.quarantine_checksum,
        operator_identity_checksum=current_identity.identity_checksum,
        approval_epoch=normalized_epoch,
    )
    return OperatorApprovalNonce(
        nonce_id=nonce_id,
        quarantine_checksum=current_quarantine.quarantine_checksum,
        operator_identity_checksum=current_identity.identity_checksum,
        approval_epoch=normalized_epoch,
    )


def operator_identity_claim_checksum(
    *,
    operator_id: str,
    operator_role: str,
    operator_authority_manifest_checksum: str,
    context_authority_checksum: str,
    identity_epoch: int,
) -> str:
    """Return the deterministic checksum for an operator identity claim."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "operator_id": operator_id,
            "operator_role": operator_role,
            "operator_authority_manifest_checksum": operator_authority_manifest_checksum,
            "context_authority_checksum": context_authority_checksum,
            "identity_epoch": identity_epoch,
        }
    )


def recompute_operator_identity_claim_checksum(identity: OperatorIdentityClaim) -> str:
    """Recompute an OperatorIdentityClaim checksum from authoritative fields."""
    return operator_identity_claim_checksum(
        operator_id=identity.operator_id,
        operator_role=identity.operator_role,
        operator_authority_manifest_checksum=identity.operator_authority_manifest_checksum,
        context_authority_checksum=identity.context_authority_checksum,
        identity_epoch=identity.identity_epoch,
    )


def operator_approval_nonce_id(
    *,
    quarantine_checksum: str,
    operator_identity_checksum: str,
    approval_epoch: int,
) -> str:
    """Return the deterministic identifier for one approval nonce."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "quarantine_checksum": quarantine_checksum,
            "operator_identity_checksum": operator_identity_checksum,
            "approval_epoch": approval_epoch,
        }
    )


def operator_approval_nonce_checksum(
    *,
    nonce_id: str,
    quarantine_checksum: str,
    operator_identity_checksum: str,
    approval_epoch: int,
) -> str:
    """Return the deterministic checksum for approval nonce evidence."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "nonce_id": nonce_id,
            "quarantine_checksum": quarantine_checksum,
            "operator_identity_checksum": operator_identity_checksum,
            "approval_epoch": approval_epoch,
        }
    )


def recompute_operator_approval_nonce_checksum(nonce: OperatorApprovalNonce) -> str:
    """Recompute an OperatorApprovalNonce checksum from authoritative fields."""
    return operator_approval_nonce_checksum(
        nonce_id=nonce.nonce_id,
        quarantine_checksum=nonce.quarantine_checksum,
        operator_identity_checksum=nonce.operator_identity_checksum,
        approval_epoch=nonce.approval_epoch,
    )


def operator_identity_checksum_or_fallback(value: object) -> str:
    """Return a valid identity checksum string or the closed fallback checksum."""
    if type(value) is OperatorIdentityClaim:
        return checksum_or_fallback(value.identity_checksum)
    return checksum_or_fallback(getattr(value, "identity_checksum", None))


def operator_nonce_checksum_or_fallback(value: object) -> str:
    """Return a valid nonce checksum string or the closed fallback checksum."""
    if type(value) is OperatorApprovalNonce:
        return checksum_or_fallback(value.nonce_checksum)
    return checksum_or_fallback(getattr(value, "nonce_checksum", None))


def _normalize_operator_id(value: object) -> str:
    try:
        return normalize_operator_id(value)
    except ValueError as exc:
        raise ValueError(
            OperatorAuthorityReason.OPERATOR_AUTHORITY_OPERATOR_ID_MALFORMED.value
        ) from exc


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
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


def _sha256(payload: Mapping[str, CanonicalOperatorIdentityValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalOperatorIdentityValue],
) -> dict[str, CanonicalOperatorIdentityValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalOperatorIdentityValue) -> CanonicalOperatorIdentityValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalOperatorIdentityValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "OperatorApprovalNonce",
    "OperatorIdentityClaim",
    "build_operator_approval_nonce",
    "build_operator_identity_claim",
    "operator_approval_nonce_checksum",
    "operator_approval_nonce_id",
    "operator_identity_claim_checksum",
    "operator_identity_checksum_or_fallback",
    "operator_nonce_checksum_or_fallback",
    "recompute_operator_approval_nonce_checksum",
    "recompute_operator_identity_claim_checksum",
]
