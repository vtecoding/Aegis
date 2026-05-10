"""Structural operator authority manifests for ADR-0023."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import cast

from aegis.aegis_constants import MAX_ADAPTER_STRING_LENGTH, OPERATOR_AUTHORITY_CONTRACT_VERSION
from aegis.execution.aegis_capability_lease import checksum_or_fallback

type CanonicalOperatorAuthorityValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalOperatorAuthorityValue]
    | dict[str, CanonicalOperatorAuthorityValue]
)


class OperatorAuthorityManifestStatus(StrEnum):
    """Closed ADR-0023 operator authority manifest statuses."""

    ACTIVE_STRUCTURAL_ONLY = "ACTIVE_STRUCTURAL_ONLY"


class OperatorAuthorityReason(StrEnum):
    """Stable ADR-0023 operator authority and replay reason codes."""

    OPERATOR_AUTHORITY_REPLAY_VALID = "OPERATOR_AUTHORITY_REPLAY_VALID"
    OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE = "OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE"
    OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE = "OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE"
    OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE = "OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE"
    OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY = "OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY"
    OPERATOR_AUTHORITY_OPERATOR_ID_MALFORMED = "OPERATOR_AUTHORITY_OPERATOR_ID_MALFORMED"
    OPERATOR_AUTHORITY_MANIFEST_DRIFT = "OPERATOR_AUTHORITY_MANIFEST_DRIFT"
    OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT = "OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT"
    OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT = "OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT"
    OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT = "OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT"
    OPERATOR_AUTHORITY_APPROVAL_CHECKSUM_DRIFT = "OPERATOR_AUTHORITY_APPROVAL_CHECKSUM_DRIFT"
    OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY = "OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY"
    OPERATOR_AUTHORITY_NONCE_IDENTITY_REPLAY = "OPERATOR_AUTHORITY_NONCE_IDENTITY_REPLAY"
    OPERATOR_AUTHORITY_QUARANTINE_REPLAY = "OPERATOR_AUTHORITY_QUARANTINE_REPLAY"
    OPERATOR_AUTHORITY_DISPATCH_PLAN_REPLAY = "OPERATOR_AUTHORITY_DISPATCH_PLAN_REPLAY"
    OPERATOR_AUTHORITY_LEASE_REPLAY = "OPERATOR_AUTHORITY_LEASE_REPLAY"
    OPERATOR_AUTHORITY_BACKEND_ADMISSION_REPLAY = "OPERATOR_AUTHORITY_BACKEND_ADMISSION_REPLAY"
    OPERATOR_AUTHORITY_BACKEND_DESCRIPTOR_REPLAY = "OPERATOR_AUTHORITY_BACKEND_DESCRIPTOR_REPLAY"
    OPERATOR_AUTHORITY_REGISTRY_REPLAY = "OPERATOR_AUTHORITY_REGISTRY_REPLAY"
    OPERATOR_AUTHORITY_CERTIFICATION_REPLAY = "OPERATOR_AUTHORITY_CERTIFICATION_REPLAY"
    OPERATOR_AUTHORITY_BACKEND_REPLAY_PROOF_REPLAY = (
        "OPERATOR_AUTHORITY_BACKEND_REPLAY_PROOF_REPLAY"
    )
    OPERATOR_AUTHORITY_OPERATOR_IDENTITY_REPLAY = "OPERATOR_AUTHORITY_OPERATOR_IDENTITY_REPLAY"
    OPERATOR_AUTHORITY_ROLE_REPLAY = "OPERATOR_AUTHORITY_ROLE_REPLAY"
    OPERATOR_AUTHORITY_EPOCH_REPLAY = "OPERATOR_AUTHORITY_EPOCH_REPLAY"
    OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE = "OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE"
    OPERATOR_AUTHORITY_PARTIAL_APPROVAL_SCOPE = "OPERATOR_AUTHORITY_PARTIAL_APPROVAL_SCOPE"
    OPERATOR_AUTHORITY_REJECTED_APPROVAL = "OPERATOR_AUTHORITY_REJECTED_APPROVAL"
    OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID = "OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID"
    OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST = "OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST"
    OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION = "OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION"
    OPERATOR_AUTHORITY_QUARANTINE_CHECKSUM_DRIFT = "OPERATOR_AUTHORITY_QUARANTINE_CHECKSUM_DRIFT"
    OPERATOR_AUTHORITY_LEASE_INVALID = "OPERATOR_AUTHORITY_LEASE_INVALID"
    DIRECT_AUTHORITY_BOUND_APPROVAL_CONSTRUCTION = "DIRECT_AUTHORITY_BOUND_APPROVAL_CONSTRUCTION"
    DIRECT_APPROVAL_REPLAY_VALIDATION_CONSTRUCTION = (
        "DIRECT_APPROVAL_REPLAY_VALIDATION_CONSTRUCTION"
    )


@dataclass(frozen=True, slots=True, init=False)
class OperatorAuthorityManifest:
    """Checksum-bound structural operator approval authority manifest."""

    authority_id: str
    authority_version: str
    allowed_operator_roles: frozenset[str]
    allowed_approval_scopes: frozenset[str]
    required_context_authority_checksum: str
    approval_epoch: int
    manifest_status: OperatorAuthorityManifestStatus
    manifest_checksum: str

    def __init__(
        self,
        *,
        authority_id: object,
        authority_version: object,
        allowed_operator_roles: Iterable[object],
        allowed_approval_scopes: Iterable[object],
        required_context_authority_checksum: object,
        approval_epoch: object,
        manifest_status: object,
        manifest_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_required_checksum(authority_id, "authority_id")
        normalized_version = _normalize_authority_version(authority_version)
        normalized_roles = normalize_operator_roles(allowed_operator_roles)
        normalized_scopes = normalize_operator_approval_scopes(allowed_approval_scopes)
        normalized_context = _normalize_required_checksum(
            required_context_authority_checksum, "required_context_authority_checksum"
        )
        normalized_epoch = normalize_operator_authority_epoch(approval_epoch)
        normalized_status = _normalize_manifest_status(manifest_status)
        computed_checksum = operator_authority_manifest_checksum(
            authority_id=normalized_id,
            authority_version=normalized_version,
            allowed_operator_roles=normalized_roles,
            allowed_approval_scopes=normalized_scopes,
            required_context_authority_checksum=normalized_context,
            approval_epoch=normalized_epoch,
            manifest_status=normalized_status,
        )
        normalized_checksum = _normalize_supplied_checksum(
            manifest_checksum, computed_checksum, "manifest_checksum"
        )

        object.__setattr__(self, "authority_id", normalized_id)
        object.__setattr__(self, "authority_version", normalized_version)
        object.__setattr__(self, "allowed_operator_roles", normalized_roles)
        object.__setattr__(self, "allowed_approval_scopes", normalized_scopes)
        object.__setattr__(self, "required_context_authority_checksum", normalized_context)
        object.__setattr__(self, "approval_epoch", normalized_epoch)
        object.__setattr__(self, "manifest_status", normalized_status)
        object.__setattr__(self, "manifest_checksum", normalized_checksum)


def build_operator_authority_manifest(
    *,
    allowed_operator_roles: Iterable[object],
    allowed_approval_scopes: Iterable[object],
    required_context_authority_checksum: object,
    approval_epoch: object,
) -> OperatorAuthorityManifest:
    """Build the ADR-0023 structural operator authority manifest."""
    normalized_roles = normalize_operator_roles(allowed_operator_roles)
    normalized_scopes = normalize_operator_approval_scopes(allowed_approval_scopes)
    normalized_context = _normalize_required_checksum(
        required_context_authority_checksum, "required_context_authority_checksum"
    )
    normalized_epoch = normalize_operator_authority_epoch(approval_epoch)
    authority_id = operator_authority_id(
        authority_version=OPERATOR_AUTHORITY_CONTRACT_VERSION,
        allowed_operator_roles=normalized_roles,
        allowed_approval_scopes=normalized_scopes,
        required_context_authority_checksum=normalized_context,
        approval_epoch=normalized_epoch,
        manifest_status=OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY,
    )
    return OperatorAuthorityManifest(
        authority_id=authority_id,
        authority_version=OPERATOR_AUTHORITY_CONTRACT_VERSION,
        allowed_operator_roles=normalized_roles,
        allowed_approval_scopes=normalized_scopes,
        required_context_authority_checksum=normalized_context,
        approval_epoch=normalized_epoch,
        manifest_status=OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY,
    )


def operator_authority_id(
    *,
    authority_version: str,
    allowed_operator_roles: Iterable[str],
    allowed_approval_scopes: Iterable[str],
    required_context_authority_checksum: str,
    approval_epoch: int,
    manifest_status: OperatorAuthorityManifestStatus | str,
) -> str:
    """Return the deterministic identifier for an operator authority manifest."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "authority_version": authority_version,
            "allowed_operator_roles": _canonical_string_sequence(sorted(allowed_operator_roles)),
            "allowed_approval_scopes": _canonical_string_sequence(sorted(allowed_approval_scopes)),
            "required_context_authority_checksum": required_context_authority_checksum,
            "approval_epoch": approval_epoch,
            "manifest_status": _manifest_status_checksum_value(manifest_status),
        }
    )


def operator_authority_manifest_checksum(
    *,
    authority_id: str,
    authority_version: str,
    allowed_operator_roles: Iterable[str],
    allowed_approval_scopes: Iterable[str],
    required_context_authority_checksum: str,
    approval_epoch: int,
    manifest_status: OperatorAuthorityManifestStatus | str,
) -> str:
    """Return the deterministic checksum for an operator authority manifest."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "authority_id": authority_id,
            "authority_version": authority_version,
            "allowed_operator_roles": _canonical_string_sequence(sorted(allowed_operator_roles)),
            "allowed_approval_scopes": _canonical_string_sequence(sorted(allowed_approval_scopes)),
            "required_context_authority_checksum": required_context_authority_checksum,
            "approval_epoch": approval_epoch,
            "manifest_status": _manifest_status_checksum_value(manifest_status),
        }
    )


def recompute_operator_authority_manifest_checksum(manifest: OperatorAuthorityManifest) -> str:
    """Recompute an OperatorAuthorityManifest checksum from authoritative fields."""
    return operator_authority_manifest_checksum(
        authority_id=manifest.authority_id,
        authority_version=manifest.authority_version,
        allowed_operator_roles=manifest.allowed_operator_roles,
        allowed_approval_scopes=manifest.allowed_approval_scopes,
        required_context_authority_checksum=manifest.required_context_authority_checksum,
        approval_epoch=manifest.approval_epoch,
        manifest_status=manifest.manifest_status,
    )


def normalize_operator_roles(values: Iterable[object]) -> frozenset[str]:
    """Normalize non-empty operator roles and reject wildcard or runtime values."""
    if isinstance(values, (str, Mapping)) or callable(values):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
    normalized = frozenset(normalize_operator_role(value) for value in values)
    if not normalized:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE.value)
    return normalized


def normalize_operator_role(value: object) -> str:
    """Normalize one canonical structural operator role."""
    normalized = _normalize_required_text(value, "operator_role")
    if normalized == "*":
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE.value)
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE.value)
    return normalized


def normalize_operator_approval_scopes(values: Iterable[object]) -> frozenset[str]:
    """Normalize explicit non-wildcard approval scopes as checksum identifiers."""
    if isinstance(values, (str, Mapping)) or callable(values):
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
    normalized: set[str] = set()
    for value in values:
        if callable(value):
            raise ValueError(
                OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
            )
        if value == "*":
            raise ValueError(
                OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE.value
            )
        normalized.add(_normalize_required_checksum(value, "allowed_approval_scopes"))
    if not normalized:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY.value)
    return frozenset(normalized)


def normalize_operator_authority_epoch(value: object) -> int:
    """Normalize an explicit deterministic operator authority epoch."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("approval_epoch must be an integer")
    if value < 0:
        raise ValueError("approval_epoch must be >= 0")
    return value


def operator_authority_manifest_checksum_or_fallback(value: object) -> str:
    """Return a valid manifest checksum or the closed fallback checksum."""
    if type(value) is OperatorAuthorityManifest:
        return checksum_or_fallback(value.manifest_checksum)
    return checksum_or_fallback(getattr(value, "manifest_checksum", None))


def _normalize_authority_version(value: object) -> str:
    normalized = _normalize_required_text(value, "authority_version")
    if normalized != OPERATOR_AUTHORITY_CONTRACT_VERSION:
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value)
    return normalized


def _normalize_manifest_status(value: object) -> OperatorAuthorityManifestStatus:
    if isinstance(value, OperatorAuthorityManifestStatus):
        if value is OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY:
            return value
    elif isinstance(value, str) and value == OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY:
        return OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY
    raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value)


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


def _manifest_status_checksum_value(value: OperatorAuthorityManifestStatus | str) -> str:
    if isinstance(value, OperatorAuthorityManifestStatus):
        return value.value
    return value


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalOperatorAuthorityValue]:
    return [value for value in values]


def _sha256(payload: Mapping[str, CanonicalOperatorAuthorityValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalOperatorAuthorityValue],
) -> dict[str, CanonicalOperatorAuthorityValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalOperatorAuthorityValue,
) -> CanonicalOperatorAuthorityValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalOperatorAuthorityValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "OperatorAuthorityManifest",
    "OperatorAuthorityManifestStatus",
    "OperatorAuthorityReason",
    "build_operator_authority_manifest",
    "normalize_operator_approval_scopes",
    "normalize_operator_authority_epoch",
    "normalize_operator_role",
    "normalize_operator_roles",
    "operator_authority_id",
    "operator_authority_manifest_checksum",
    "operator_authority_manifest_checksum_or_fallback",
    "recompute_operator_authority_manifest_checksum",
]
