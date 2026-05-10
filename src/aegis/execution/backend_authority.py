"""Immutable backend authority manifests for ADR-0020."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import cast

from aegis.constants import (
    BACKEND_AUTHORITY_CONTRACT_VERSION,
    MAX_ADAPTER_STRING_LENGTH,
    RUNTIME_BACKEND_CONTRACT_VERSION,
)
from aegis.contracts.backend_replay import BackendReplayProfile
from aegis.contracts.runtime_backend import (
    BackendCertificationStatus,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
)
from aegis.contracts.runtime_dispatch import RuntimeDispatchKind

type CanonicalBackendAuthorityValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalBackendAuthorityValue]
    | dict[str, CanonicalBackendAuthorityValue]
)


class BackendAuthorityAdmissionStatus(StrEnum):
    """Closed ADR-0020 manifest admission statuses."""

    ADMITTED_NULL_ONLY = "ADMITTED_NULL_ONLY"


@dataclass(frozen=True, slots=True, init=False)
class BackendAuthorityManifest:
    """Checksum-bound authority scope for one registered runtime backend kind."""

    backend_kind: RuntimeBackendKind
    backend_version: str
    allowed_modes: frozenset[RuntimeBackendMode]
    allowed_runtime_kinds: frozenset[RuntimeDispatchKind]
    allowed_capabilities: frozenset[str]
    required_certification_profile: BackendCertificationStatus
    required_replay_profile: BackendReplayProfile
    allows_execution: bool
    allows_io: bool
    allows_async: bool
    admission_status: BackendAuthorityAdmissionStatus
    manifest_checksum: str

    def __init__(
        self,
        *,
        backend_kind: object,
        backend_version: object,
        allowed_modes: Iterable[object],
        allowed_runtime_kinds: Iterable[object],
        allowed_capabilities: Iterable[object],
        required_certification_profile: object,
        required_replay_profile: object,
        allows_execution: object,
        allows_io: object,
        allows_async: object,
        admission_status: object,
        manifest_checksum: str | None = None,
    ) -> None:
        normalized_kind = _normalize_backend_kind(backend_kind)
        normalized_version = _normalize_backend_version(backend_version)
        normalized_modes = _normalize_allowed_modes(allowed_modes)
        normalized_runtime_kinds = _normalize_runtime_kind_scope(allowed_runtime_kinds)
        normalized_capabilities = _normalize_capability_scope(allowed_capabilities)
        normalized_certification = _normalize_certification_profile(required_certification_profile)
        normalized_replay = _normalize_replay_profile(required_replay_profile)
        normalized_execution = _normalize_false_bool(allows_execution, "allows_execution")
        normalized_io = _normalize_false_bool(allows_io, "allows_io")
        normalized_async = _normalize_false_bool(allows_async, "allows_async")
        normalized_status = _normalize_admission_status(admission_status)
        computed_checksum = backend_authority_manifest_checksum(
            backend_kind=normalized_kind,
            backend_version=normalized_version,
            allowed_modes=normalized_modes,
            allowed_runtime_kinds=normalized_runtime_kinds,
            allowed_capabilities=normalized_capabilities,
            required_certification_profile=normalized_certification,
            required_replay_profile=normalized_replay,
            allows_execution=normalized_execution,
            allows_io=normalized_io,
            allows_async=normalized_async,
            admission_status=normalized_status,
        )
        normalized_checksum = _normalize_supplied_checksum(
            manifest_checksum,
            computed_checksum,
            "manifest_checksum",
        )

        object.__setattr__(self, "backend_kind", normalized_kind)
        object.__setattr__(self, "backend_version", normalized_version)
        object.__setattr__(self, "allowed_modes", normalized_modes)
        object.__setattr__(self, "allowed_runtime_kinds", normalized_runtime_kinds)
        object.__setattr__(self, "allowed_capabilities", normalized_capabilities)
        object.__setattr__(self, "required_certification_profile", normalized_certification)
        object.__setattr__(self, "required_replay_profile", normalized_replay)
        object.__setattr__(self, "allows_execution", normalized_execution)
        object.__setattr__(self, "allows_io", normalized_io)
        object.__setattr__(self, "allows_async", normalized_async)
        object.__setattr__(self, "admission_status", normalized_status)
        object.__setattr__(self, "manifest_checksum", normalized_checksum)


def build_backend_authority_manifest(descriptor: object) -> BackendAuthorityManifest:
    """Return the ADR-0020 authority manifest scoped exactly to a descriptor."""
    if not isinstance(descriptor, RuntimeBackendDescriptor):
        raise ValueError("descriptor must be a RuntimeBackendDescriptor")
    return BackendAuthorityManifest(
        backend_kind=descriptor.backend_kind,
        backend_version=RUNTIME_BACKEND_CONTRACT_VERSION,
        allowed_modes={descriptor.backend_mode},
        allowed_runtime_kinds=descriptor.supported_runtime_kinds,
        allowed_capabilities=descriptor.supported_capabilities,
        required_certification_profile=BackendCertificationStatus.CERTIFIED_NULL,
        required_replay_profile=BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
        allows_execution=False,
        allows_io=False,
        allows_async=False,
        admission_status=BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY,
    )


def backend_authority_manifest_checksum(
    *,
    backend_kind: RuntimeBackendKind | str,
    backend_version: str,
    allowed_modes: Iterable[RuntimeBackendMode | str],
    allowed_runtime_kinds: Iterable[RuntimeDispatchKind | str],
    allowed_capabilities: Iterable[str],
    required_certification_profile: BackendCertificationStatus | str,
    required_replay_profile: BackendReplayProfile | str,
    allows_execution: bool,
    allows_io: bool,
    allows_async: bool,
    admission_status: BackendAuthorityAdmissionStatus | str,
) -> str:
    """Return the deterministic checksum for a backend authority manifest."""
    return _sha256(
        {
            "backend_authority_contract_version": BACKEND_AUTHORITY_CONTRACT_VERSION,
            "backend_kind": _backend_kind_checksum_value(backend_kind),
            "backend_version": backend_version,
            "allowed_modes": _canonical_string_sequence(
                sorted(_backend_mode_checksum_value(mode) for mode in allowed_modes)
            ),
            "allowed_runtime_kinds": _canonical_string_sequence(
                sorted(
                    _runtime_kind_checksum_value(runtime_kind)
                    for runtime_kind in allowed_runtime_kinds
                )
            ),
            "allowed_capabilities": _canonical_string_sequence(sorted(allowed_capabilities)),
            "required_certification_profile": _certification_checksum_value(
                required_certification_profile
            ),
            "required_replay_profile": _replay_profile_checksum_value(required_replay_profile),
            "allows_execution": allows_execution,
            "allows_io": allows_io,
            "allows_async": allows_async,
            "admission_status": _authority_status_checksum_value(admission_status),
        }
    )


def recompute_backend_authority_manifest_checksum(
    manifest: BackendAuthorityManifest,
) -> str:
    """Recompute a BackendAuthorityManifest checksum from authoritative fields."""
    return backend_authority_manifest_checksum(
        backend_kind=manifest.backend_kind,
        backend_version=manifest.backend_version,
        allowed_modes=manifest.allowed_modes,
        allowed_runtime_kinds=manifest.allowed_runtime_kinds,
        allowed_capabilities=manifest.allowed_capabilities,
        required_certification_profile=manifest.required_certification_profile,
        required_replay_profile=manifest.required_replay_profile,
        allows_execution=manifest.allows_execution,
        allows_io=manifest.allows_io,
        allows_async=manifest.allows_async,
        admission_status=manifest.admission_status,
    )


def _normalize_backend_kind(value: object) -> RuntimeBackendKind:
    if isinstance(value, RuntimeBackendKind):
        if value is RuntimeBackendKind.NULL_BACKEND_V1:
            return value
    elif isinstance(value, str) and value == RuntimeBackendKind.NULL_BACKEND_V1.value:
        return RuntimeBackendKind.NULL_BACKEND_V1
    raise ValueError("BACKEND_AUTHORITY_BACKEND_KIND_NOT_NULL")


def _normalize_backend_version(value: object) -> str:
    normalized = _normalize_required_text(value, "backend_version")
    if normalized != RUNTIME_BACKEND_CONTRACT_VERSION:
        raise ValueError("BACKEND_AUTHORITY_BACKEND_VERSION_DRIFT")
    return normalized


def _normalize_allowed_modes(values: Iterable[object]) -> frozenset[RuntimeBackendMode]:
    if isinstance(values, (str, Mapping)):
        raise ValueError("allowed_modes must be an immutable scope iterable")
    normalized: set[RuntimeBackendMode] = set()
    for value in values:
        if callable(value):
            raise ValueError("allowed_modes must not contain callable values")
        if isinstance(value, RuntimeBackendMode):
            normalized.add(value)
            continue
        if isinstance(value, str):
            try:
                normalized.add(RuntimeBackendMode(value))
            except ValueError:
                raise ValueError("allowed_modes contains an unsupported mode") from None
            continue
        raise ValueError("allowed_modes must contain RuntimeBackendMode values")
    if normalized != {RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY}:
        raise ValueError("BACKEND_AUTHORITY_MODE_SCOPE_DRIFT")
    return frozenset(normalized)


def _normalize_runtime_kind_scope(
    values: Iterable[object],
) -> frozenset[RuntimeDispatchKind]:
    if isinstance(values, (str, Mapping)):
        raise ValueError("allowed_runtime_kinds must be an immutable scope iterable")
    normalized: set[RuntimeDispatchKind] = set()
    for value in values:
        if callable(value):
            raise ValueError("allowed_runtime_kinds must not contain callable values")
        if value == "*":
            raise ValueError("BACKEND_AUTHORITY_WILDCARD_RUNTIME_KIND")
        if isinstance(value, RuntimeDispatchKind):
            normalized.add(value)
            continue
        if isinstance(value, str):
            try:
                normalized.add(RuntimeDispatchKind(value))
            except ValueError:
                raise ValueError("allowed_runtime_kinds contains an undeclared kind") from None
            continue
        raise ValueError("allowed_runtime_kinds must contain RuntimeDispatchKind values")
    if not normalized:
        raise ValueError("allowed_runtime_kinds must be non-empty")
    return frozenset(normalized)


def _normalize_capability_scope(values: Iterable[object]) -> frozenset[str]:
    if isinstance(values, (str, Mapping)):
        raise ValueError("allowed_capabilities must be an immutable scope iterable")
    normalized = frozenset(_normalize_capability(value) for value in values)
    if not normalized:
        raise ValueError("allowed_capabilities must be non-empty")
    return normalized


def _normalize_capability(value: object) -> str:
    normalized = _normalize_required_text(value, "allowed_capabilities")
    if normalized == "*":
        raise ValueError("BACKEND_AUTHORITY_WILDCARD_CAPABILITY")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("allowed_capabilities must be canonical dotted lowercase identifiers")
    return normalized


def _normalize_certification_profile(value: object) -> BackendCertificationStatus:
    if isinstance(value, BackendCertificationStatus):
        if value is BackendCertificationStatus.CERTIFIED_NULL:
            return value
    elif isinstance(value, str) and value == BackendCertificationStatus.CERTIFIED_NULL.value:
        return BackendCertificationStatus.CERTIFIED_NULL
    raise ValueError("BACKEND_AUTHORITY_CERTIFICATION_PROFILE_NOT_CERTIFIED_NULL")


def _normalize_replay_profile(value: object) -> BackendReplayProfile:
    if isinstance(value, BackendReplayProfile):
        if value is BackendReplayProfile.STRICT_BACKEND_REPLAY_V1:
            return value
    elif isinstance(value, str) and value == BackendReplayProfile.STRICT_BACKEND_REPLAY_V1.value:
        return BackendReplayProfile.STRICT_BACKEND_REPLAY_V1
    raise ValueError("BACKEND_AUTHORITY_REPLAY_PROFILE_NOT_STRICT")


def _normalize_false_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool")
    if value:
        raise ValueError(f"BACKEND_AUTHORITY_{field_name.upper()}_CLAIMED")
    return value


def _normalize_admission_status(value: object) -> BackendAuthorityAdmissionStatus:
    if isinstance(value, BackendAuthorityAdmissionStatus):
        if value is BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY:
            return value
    elif isinstance(value, str) and value == BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY:
        return BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY
    raise ValueError("BACKEND_AUTHORITY_STATUS_NOT_ADMITTED_NULL_ONLY")


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


def _backend_kind_checksum_value(value: RuntimeBackendKind | str) -> str:
    if isinstance(value, RuntimeBackendKind):
        return value.value
    return value


def _backend_mode_checksum_value(value: RuntimeBackendMode | str) -> str:
    if isinstance(value, RuntimeBackendMode):
        return value.value
    return value


def _runtime_kind_checksum_value(value: RuntimeDispatchKind | str) -> str:
    if isinstance(value, RuntimeDispatchKind):
        return value.value
    return value


def _certification_checksum_value(value: BackendCertificationStatus | str) -> str:
    if isinstance(value, BackendCertificationStatus):
        return value.value
    return value


def _replay_profile_checksum_value(value: BackendReplayProfile | str) -> str:
    if isinstance(value, BackendReplayProfile):
        return value.value
    return value


def _authority_status_checksum_value(value: BackendAuthorityAdmissionStatus | str) -> str:
    if isinstance(value, BackendAuthorityAdmissionStatus):
        return value.value
    return value


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalBackendAuthorityValue]:
    return [value for value in values]


def _sha256(payload: Mapping[str, CanonicalBackendAuthorityValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalBackendAuthorityValue],
) -> dict[str, CanonicalBackendAuthorityValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalBackendAuthorityValue,
) -> CanonicalBackendAuthorityValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalBackendAuthorityValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "BackendAuthorityAdmissionStatus",
    "BackendAuthorityManifest",
    "backend_authority_manifest_checksum",
    "build_backend_authority_manifest",
    "recompute_backend_authority_manifest_checksum",
]
