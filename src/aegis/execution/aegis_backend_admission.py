"""Fail-closed backend admission gate for ADR-0020."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import (
    BACKEND_AUTHORITY_CONTRACT_VERSION,
    RUNTIME_BACKEND_CONTRACT_VERSION,
)
from aegis.contracts.aegis_backend_replay import (
    BackendReplayProfile,
    BackendReplayProofResult,
    recompute_backend_replay_proof_checksum,
)
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    BackendCertificationStatus,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
    recompute_backend_certification_checksum,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.aegis_runtime_dispatch import RuntimeDispatchKind
from aegis.execution.aegis_backend_authority import (
    BackendAuthorityManifest,
    recompute_backend_authority_manifest_checksum,
)
from aegis.execution.aegis_backend_registry import backend_authority_registry_checksum

type BackendAdmissionStatusValue = Literal["ADMITTED", "BLOCKED"]
type CanonicalBackendAdmissionValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalBackendAdmissionValue]
    | dict[str, CanonicalBackendAdmissionValue]
)

_FALLBACK_CHECKSUM = "0" * 64
_UNKNOWN_BACKEND_KIND = "UNKNOWN_BACKEND_KIND"


class BackendAdmissionReason(StrEnum):
    """Stable ADR-0020 backend admission reason codes."""

    BACKEND_ADMISSION_ADMITTED_NULL_BACKEND = "BACKEND_ADMISSION_ADMITTED_NULL_BACKEND"
    BACKEND_ADMISSION_UNKNOWN_BACKEND_KIND = "BACKEND_ADMISSION_UNKNOWN_BACKEND_KIND"
    BACKEND_ADMISSION_BACKEND_KIND_NOT_NULL = "BACKEND_ADMISSION_BACKEND_KIND_NOT_NULL"
    BACKEND_ADMISSION_BACKEND_VERSION_DRIFT = "BACKEND_ADMISSION_BACKEND_VERSION_DRIFT"
    BACKEND_ADMISSION_MANIFEST_CHECKSUM_DRIFT = "BACKEND_ADMISSION_MANIFEST_CHECKSUM_DRIFT"
    BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT = "BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT"
    BACKEND_ADMISSION_CERTIFICATION_MISSING = "BACKEND_ADMISSION_CERTIFICATION_MISSING"
    BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL = (
        "BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL"
    )
    BACKEND_ADMISSION_REPLAY_PROOF_MISSING = "BACKEND_ADMISSION_REPLAY_PROOF_MISSING"
    BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED = "BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED"
    BACKEND_ADMISSION_EXECUTION_CAPABILITY_CLAIMED = (
        "BACKEND_ADMISSION_EXECUTION_CAPABILITY_CLAIMED"
    )
    BACKEND_ADMISSION_IO_CAPABILITY_CLAIMED = "BACKEND_ADMISSION_IO_CAPABILITY_CLAIMED"
    BACKEND_ADMISSION_ASYNC_CAPABILITY_CLAIMED = "BACKEND_ADMISSION_ASYNC_CAPABILITY_CLAIMED"
    BACKEND_ADMISSION_CAPABILITY_SCOPE_OVERCLAIM = "BACKEND_ADMISSION_CAPABILITY_SCOPE_OVERCLAIM"
    BACKEND_ADMISSION_RUNTIME_KIND_SCOPE_OVERCLAIM = (
        "BACKEND_ADMISSION_RUNTIME_KIND_SCOPE_OVERCLAIM"
    )
    BACKEND_ADMISSION_WILDCARD_CAPABILITY = "BACKEND_ADMISSION_WILDCARD_CAPABILITY"
    BACKEND_ADMISSION_WILDCARD_RUNTIME_KIND = "BACKEND_ADMISSION_WILDCARD_RUNTIME_KIND"
    BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION = "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION"
    BACKEND_ADMISSION_MUTABLE_MANIFEST_INJECTION = "BACKEND_ADMISSION_MUTABLE_MANIFEST_INJECTION"
    BACKEND_ADMISSION_DESCRIPTOR_CHECKSUM_DRIFT = "BACKEND_ADMISSION_DESCRIPTOR_CHECKSUM_DRIFT"
    BACKEND_ADMISSION_DESCRIPTOR_MANIFEST_MISMATCH = (
        "BACKEND_ADMISSION_DESCRIPTOR_MANIFEST_MISMATCH"
    )
    BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH = (
        "BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH"
    )
    BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH = "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH"


@dataclass(frozen=True, slots=True, init=False)
class BackendAdmissionRequest:
    """Immutable request to admit a runtime backend authority manifest."""

    backend_descriptor: RuntimeBackendDescriptor
    backend_certification: BackendCertificationResult
    backend_replay_proof: BackendReplayProofResult
    authority_manifest: BackendAuthorityManifest
    registry_checksum: str

    def __init__(
        self,
        *,
        backend_descriptor: object,
        backend_certification: object,
        backend_replay_proof: object,
        authority_manifest: object,
        registry_checksum: object,
    ) -> None:
        if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
            raise ValueError("backend_descriptor must be a RuntimeBackendDescriptor")
        if not isinstance(backend_certification, BackendCertificationResult):
            raise ValueError("backend_certification must be a BackendCertificationResult")
        if not isinstance(backend_replay_proof, BackendReplayProofResult):
            raise ValueError("backend_replay_proof must be a BackendReplayProofResult")
        if not isinstance(authority_manifest, BackendAuthorityManifest):
            raise ValueError("authority_manifest must be a BackendAuthorityManifest")
        object.__setattr__(self, "backend_descriptor", backend_descriptor)
        object.__setattr__(self, "backend_certification", backend_certification)
        object.__setattr__(self, "backend_replay_proof", backend_replay_proof)
        object.__setattr__(self, "authority_manifest", authority_manifest)
        object.__setattr__(
            self,
            "registry_checksum",
            _normalize_required_checksum(registry_checksum, "registry_checksum"),
        )


@dataclass(frozen=True, slots=True, init=False)
class BackendAdmissionDecision:
    """Checksum-bound backend admission decision."""

    status: BackendAdmissionStatusValue
    reason_code: str
    backend_kind: str
    backend_descriptor_checksum: str
    certification_checksum: str
    replay_proof_checksum: str
    authority_manifest_checksum: str
    registry_checksum: str
    decision_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        backend_kind: object,
        backend_descriptor_checksum: object,
        certification_checksum: object,
        replay_proof_checksum: object,
        authority_manifest_checksum: object,
        registry_checksum: object,
        decision_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_kind = _normalize_kind_label(backend_kind)
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_certification = _normalize_required_checksum(
            certification_checksum, "certification_checksum"
        )
        normalized_replay = _normalize_required_checksum(
            replay_proof_checksum, "replay_proof_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            authority_manifest_checksum, "authority_manifest_checksum"
        )
        normalized_registry = _normalize_required_checksum(registry_checksum, "registry_checksum")
        if normalized_status == "ADMITTED":
            _validate_admitted_decision(normalized_reason, normalized_kind)
        computed_checksum = backend_admission_decision_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            backend_kind=normalized_kind,
            backend_descriptor_checksum=normalized_descriptor,
            certification_checksum=normalized_certification,
            replay_proof_checksum=normalized_replay,
            authority_manifest_checksum=normalized_manifest,
            registry_checksum=normalized_registry,
        )
        normalized_checksum = _normalize_supplied_checksum(
            decision_checksum,
            computed_checksum,
            "decision_checksum",
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "backend_kind", normalized_kind)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(self, "certification_checksum", normalized_certification)
        object.__setattr__(self, "replay_proof_checksum", normalized_replay)
        object.__setattr__(self, "authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "registry_checksum", normalized_registry)
        object.__setattr__(self, "decision_checksum", normalized_checksum)


def admit_runtime_backend(request: BackendAdmissionRequest) -> BackendAdmissionDecision:
    """Return a deterministic fail-closed backend admission decision."""
    descriptor_object = _object_field(request, "backend_descriptor")
    certification_object = _object_field(request, "backend_certification")
    replay_object = _object_field(request, "backend_replay_proof")
    manifest_object = _object_field(request, "authority_manifest")
    registry_checksum_object = _object_field(request, "registry_checksum")
    backend_kind = _backend_kind_for_decision(descriptor_object, manifest_object)

    if not isinstance(descriptor_object, RuntimeBackendDescriptor):
        return _blocked_decision(
            reason=BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION,
            backend_kind=backend_kind,
            certification=certification_object,
            replay_proof=replay_object,
            manifest=manifest_object,
            registry_checksum=registry_checksum_object,
        )
    descriptor = descriptor_object
    if certification_object is None:
        return _blocked_decision(
            reason=BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_MISSING,
            descriptor=descriptor,
            replay_proof=replay_object,
            manifest=manifest_object,
            registry_checksum=registry_checksum_object,
        )
    if not isinstance(certification_object, BackendCertificationResult):
        return _blocked_decision(
            reason=BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION,
            descriptor=descriptor,
            replay_proof=replay_object,
            manifest=manifest_object,
            registry_checksum=registry_checksum_object,
        )
    certification = certification_object
    if replay_object is None:
        return _blocked_decision(
            reason=BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_PROOF_MISSING,
            descriptor=descriptor,
            certification=certification,
            manifest=manifest_object,
            registry_checksum=registry_checksum_object,
        )
    if not isinstance(replay_object, BackendReplayProofResult):
        return _blocked_decision(
            reason=BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION,
            descriptor=descriptor,
            certification=certification,
            manifest=manifest_object,
            registry_checksum=registry_checksum_object,
        )
    replay_proof = replay_object
    if not isinstance(manifest_object, BackendAuthorityManifest):
        return _blocked_decision(
            reason=_manifest_injection_reason(manifest_object),
            descriptor=descriptor,
            certification=certification,
            replay_proof=replay_proof,
            registry_checksum=registry_checksum_object,
        )
    manifest = manifest_object

    source_block_reason = _source_block_reason(
        descriptor=descriptor,
        certification=certification,
        replay_proof=replay_proof,
        manifest=manifest,
        registry_checksum=registry_checksum_object,
    )
    if source_block_reason is not None:
        return _blocked_decision(
            reason=source_block_reason,
            descriptor=descriptor,
            certification=certification,
            replay_proof=replay_proof,
            manifest=manifest,
            registry_checksum=registry_checksum_object,
        )
    return BackendAdmissionDecision(
        status="ADMITTED",
        reason_code=BackendAdmissionReason.BACKEND_ADMISSION_ADMITTED_NULL_BACKEND.value,
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1.value,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        certification_checksum=certification.certification_checksum,
        replay_proof_checksum=replay_proof.proof_checksum,
        authority_manifest_checksum=manifest.manifest_checksum,
        registry_checksum=cast(str, registry_checksum_object),
    )


def backend_admission_decision_checksum(
    *,
    status: BackendAdmissionStatusValue,
    reason_code: str,
    backend_kind: str,
    backend_descriptor_checksum: str,
    certification_checksum: str,
    replay_proof_checksum: str,
    authority_manifest_checksum: str,
    registry_checksum: str,
) -> str:
    """Return the deterministic checksum for a backend admission decision."""
    return _sha256(
        {
            "backend_authority_contract_version": BACKEND_AUTHORITY_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "backend_kind": backend_kind,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "certification_checksum": certification_checksum,
            "replay_proof_checksum": replay_proof_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "registry_checksum": registry_checksum,
        }
    )


def recompute_backend_admission_decision_checksum(
    decision: BackendAdmissionDecision,
) -> str:
    """Recompute a BackendAdmissionDecision checksum from authoritative fields."""
    return backend_admission_decision_checksum(
        status=decision.status,
        reason_code=decision.reason_code,
        backend_kind=decision.backend_kind,
        backend_descriptor_checksum=decision.backend_descriptor_checksum,
        certification_checksum=decision.certification_checksum,
        replay_proof_checksum=decision.replay_proof_checksum,
        authority_manifest_checksum=decision.authority_manifest_checksum,
        registry_checksum=decision.registry_checksum,
    )


def _source_block_reason(
    *,
    descriptor: RuntimeBackendDescriptor,
    certification: BackendCertificationResult,
    replay_proof: BackendReplayProofResult,
    manifest: BackendAuthorityManifest,
    registry_checksum: object,
) -> BackendAdmissionReason | None:
    descriptor_kind = _backend_kind_value(descriptor.backend_kind)
    manifest_kind = _backend_kind_value(manifest.backend_kind)
    if descriptor_kind is None or manifest_kind is None:
        return BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION
    if descriptor_kind == _UNKNOWN_BACKEND_KIND or manifest_kind == _UNKNOWN_BACKEND_KIND:
        return BackendAdmissionReason.BACKEND_ADMISSION_UNKNOWN_BACKEND_KIND
    if descriptor_kind != RuntimeBackendKind.NULL_BACKEND_V1.value:
        return BackendAdmissionReason.BACKEND_ADMISSION_BACKEND_KIND_NOT_NULL
    if manifest_kind != RuntimeBackendKind.NULL_BACKEND_V1.value:
        return BackendAdmissionReason.BACKEND_ADMISSION_UNKNOWN_BACKEND_KIND
    if manifest.backend_version != RUNTIME_BACKEND_CONTRACT_VERSION:
        return BackendAdmissionReason.BACKEND_ADMISSION_BACKEND_VERSION_DRIFT
    execution_reason = _execution_boundary_reason(descriptor, manifest)
    if execution_reason is not None:
        return execution_reason
    wildcard_reason = _wildcard_reason(manifest)
    if wildcard_reason is not None:
        return wildcard_reason
    if not _manifest_shape_is_immutable(manifest):
        return BackendAdmissionReason.BACKEND_ADMISSION_MUTABLE_MANIFEST_INJECTION
    scope_reason = _scope_reason(descriptor, manifest)
    if scope_reason is not None:
        return scope_reason
    if descriptor.backend_mode not in manifest.allowed_modes:
        return BackendAdmissionReason.BACKEND_ADMISSION_DESCRIPTOR_MANIFEST_MISMATCH
    if descriptor.descriptor_checksum != _recompute_descriptor_checksum_or_fallback(descriptor):
        return BackendAdmissionReason.BACKEND_ADMISSION_DESCRIPTOR_CHECKSUM_DRIFT
    if manifest.manifest_checksum != _recompute_manifest_checksum_or_fallback(manifest):
        return BackendAdmissionReason.BACKEND_ADMISSION_MANIFEST_CHECKSUM_DRIFT
    expected_registry_checksum = backend_authority_registry_checksum((manifest,))
    if registry_checksum != expected_registry_checksum:
        return BackendAdmissionReason.BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT
    certification_reason = _certification_reason(descriptor, certification, manifest)
    if certification_reason is not None:
        return certification_reason
    replay_reason = _replay_reason(descriptor, certification, replay_proof, manifest)
    if replay_reason is not None:
        return replay_reason
    return None


def _execution_boundary_reason(
    descriptor: RuntimeBackendDescriptor,
    manifest: BackendAuthorityManifest,
) -> BackendAdmissionReason | None:
    if descriptor.allows_execution or manifest.allows_execution:
        return BackendAdmissionReason.BACKEND_ADMISSION_EXECUTION_CAPABILITY_CLAIMED
    if descriptor.allows_io or manifest.allows_io:
        return BackendAdmissionReason.BACKEND_ADMISSION_IO_CAPABILITY_CLAIMED
    if descriptor.allows_async or manifest.allows_async:
        return BackendAdmissionReason.BACKEND_ADMISSION_ASYNC_CAPABILITY_CLAIMED
    return None


def _wildcard_reason(manifest: BackendAuthorityManifest) -> BackendAdmissionReason | None:
    allowed_capabilities = cast(Iterable[object], _object_field(manifest, "allowed_capabilities"))
    allowed_runtime_kinds = cast(Iterable[object], _object_field(manifest, "allowed_runtime_kinds"))
    if any(capability == "*" for capability in allowed_capabilities):
        return BackendAdmissionReason.BACKEND_ADMISSION_WILDCARD_CAPABILITY
    if any(runtime_kind == "*" for runtime_kind in allowed_runtime_kinds):
        return BackendAdmissionReason.BACKEND_ADMISSION_WILDCARD_RUNTIME_KIND
    return None


def _scope_reason(
    descriptor: RuntimeBackendDescriptor,
    manifest: BackendAuthorityManifest,
) -> BackendAdmissionReason | None:
    if not _capability_scope_shape_is_valid(descriptor.supported_capabilities):
        return BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION
    if not _runtime_kind_scope_shape_is_valid(descriptor.supported_runtime_kinds):
        return BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION
    if descriptor.supported_capabilities != manifest.allowed_capabilities:
        return BackendAdmissionReason.BACKEND_ADMISSION_CAPABILITY_SCOPE_OVERCLAIM
    if descriptor.supported_runtime_kinds != manifest.allowed_runtime_kinds:
        return BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_KIND_SCOPE_OVERCLAIM
    return None


def _certification_reason(
    descriptor: RuntimeBackendDescriptor,
    certification: BackendCertificationResult,
    manifest: BackendAuthorityManifest,
) -> BackendAdmissionReason | None:
    if manifest.required_certification_profile is not BackendCertificationStatus.CERTIFIED_NULL:
        return BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH
    if certification.status is not BackendCertificationStatus.CERTIFIED_NULL:
        return BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL
    if certification.certification_checksum != recompute_backend_certification_checksum(
        certification
    ):
        return BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH
    if certification.backend_descriptor_checksum != descriptor.descriptor_checksum:
        return BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH
    if not all(
        (
            certification.no_execution_guarantee,
            certification.no_io_guarantee,
            certification.no_async_guarantee,
            certification.capability_scope_match,
            certification.runtime_kind_scope_match,
        )
    ):
        return BackendAdmissionReason.BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL
    return None


def _replay_reason(
    descriptor: RuntimeBackendDescriptor,
    certification: BackendCertificationResult,
    replay_proof: BackendReplayProofResult,
    manifest: BackendAuthorityManifest,
) -> BackendAdmissionReason | None:
    if manifest.required_replay_profile is not BackendReplayProfile.STRICT_BACKEND_REPLAY_V1:
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH
    if replay_proof.status != "PASSED":
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED
    if replay_proof.proof_checksum != recompute_backend_replay_proof_checksum(replay_proof):
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH
    if replay_proof.backend_descriptor_checksum != descriptor.descriptor_checksum:
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH
    if replay_proof.expected_certification_checksum != certification.certification_checksum:
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH
    if replay_proof.replayed_certification_checksum != certification.certification_checksum:
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH
    if not all(
        (
            replay_proof.zero_execution_verified,
            replay_proof.scope_match_verified,
            replay_proof.certification_match,
            replay_proof.receipt_match,
        )
    ):
        return BackendAdmissionReason.BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED
    return None


def _manifest_shape_is_immutable(manifest: BackendAuthorityManifest) -> bool:
    allowed_modes = _object_field(manifest, "allowed_modes")
    allowed_runtime_kinds = _object_field(manifest, "allowed_runtime_kinds")
    allowed_capabilities = _object_field(manifest, "allowed_capabilities")
    if not isinstance(allowed_modes, frozenset):
        return False
    if not isinstance(allowed_runtime_kinds, frozenset):
        return False
    if not isinstance(allowed_capabilities, frozenset):
        return False
    modes = cast(frozenset[object], allowed_modes)
    runtime_kinds = cast(frozenset[object], allowed_runtime_kinds)
    capabilities = cast(frozenset[object], allowed_capabilities)
    return (
        all(isinstance(mode, RuntimeBackendMode) for mode in modes)
        and all(isinstance(runtime_kind, RuntimeDispatchKind) for runtime_kind in runtime_kinds)
        and all(isinstance(capability, str) for capability in capabilities)
    )


def _capability_scope_shape_is_valid(value: object) -> bool:
    if not isinstance(value, frozenset):
        return False
    return all(isinstance(item, str) for item in cast(frozenset[object], value))


def _runtime_kind_scope_shape_is_valid(value: object) -> bool:
    if not isinstance(value, frozenset):
        return False
    return all(isinstance(item, RuntimeDispatchKind) for item in cast(frozenset[object], value))


def _manifest_injection_reason(value: object) -> BackendAdmissionReason:
    if isinstance(value, (Mapping, list, set)):
        return BackendAdmissionReason.BACKEND_ADMISSION_MUTABLE_MANIFEST_INJECTION
    return BackendAdmissionReason.BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION


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


def _blocked_decision(
    *,
    reason: BackendAdmissionReason,
    backend_kind: str | None = None,
    descriptor: object | None = None,
    certification: object | None = None,
    replay_proof: object | None = None,
    manifest: object | None = None,
    registry_checksum: object | None = None,
) -> BackendAdmissionDecision:
    return BackendAdmissionDecision(
        status="BLOCKED",
        reason_code=reason.value,
        backend_kind=backend_kind or _backend_kind_for_decision(descriptor, manifest),
        backend_descriptor_checksum=_descriptor_checksum_or_fallback(descriptor),
        certification_checksum=_certification_checksum_or_fallback(certification),
        replay_proof_checksum=_proof_checksum_or_fallback(replay_proof),
        authority_manifest_checksum=_manifest_checksum_or_fallback(manifest),
        registry_checksum=_checksum_or_fallback(registry_checksum),
    )


def _descriptor_checksum_or_fallback(value: object) -> str:
    if isinstance(value, RuntimeBackendDescriptor):
        return _checksum_or_fallback(value.descriptor_checksum)
    return _FALLBACK_CHECKSUM


def _certification_checksum_or_fallback(value: object) -> str:
    if isinstance(value, BackendCertificationResult):
        return _checksum_or_fallback(value.certification_checksum)
    return _FALLBACK_CHECKSUM


def _proof_checksum_or_fallback(value: object) -> str:
    if isinstance(value, BackendReplayProofResult):
        return _checksum_or_fallback(value.proof_checksum)
    return _FALLBACK_CHECKSUM


def _manifest_checksum_or_fallback(value: object) -> str:
    if isinstance(value, BackendAuthorityManifest):
        return _checksum_or_fallback(value.manifest_checksum)
    return _FALLBACK_CHECKSUM


def _backend_kind_for_decision(descriptor: object, manifest: object) -> str:
    descriptor_kind = _backend_kind_value(getattr(descriptor, "backend_kind", None))
    if descriptor_kind is not None:
        return descriptor_kind
    manifest_kind = _backend_kind_value(getattr(manifest, "backend_kind", None))
    if manifest_kind is not None:
        return manifest_kind
    return _UNKNOWN_BACKEND_KIND


def _backend_kind_value(value: object) -> str | None:
    if isinstance(value, RuntimeBackendKind):
        return value.value
    if isinstance(value, str):
        if value == "UNDECLARED_BACKEND_V1":
            return _UNKNOWN_BACKEND_KIND
        return value
    return None


def _checksum_or_fallback(value: object) -> str:
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return _FALLBACK_CHECKSUM


def _normalize_status(value: object) -> BackendAdmissionStatusValue:
    if value in {"ADMITTED", "BLOCKED"}:
        return cast(BackendAdmissionStatusValue, value)
    raise ValueError("status must be ADMITTED or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_kind_label(value: object) -> str:
    normalized = _normalize_required_text(value, "backend_kind")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("backend_kind must be an uppercase machine identifier")
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


def _validate_admitted_decision(reason_code: str, backend_kind: str) -> None:
    if reason_code != BackendAdmissionReason.BACKEND_ADMISSION_ADMITTED_NULL_BACKEND.value:
        raise ValueError("ADMITTED backend decisions require admitted-null reason")
    if backend_kind != RuntimeBackendKind.NULL_BACKEND_V1.value:
        raise ValueError("ADMITTED backend decisions require NULL_BACKEND_V1")


def _object_field(instance: object, field_name: str) -> object:
    return cast(object, getattr(instance, field_name))


def _sha256(payload: Mapping[str, CanonicalBackendAdmissionValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalBackendAdmissionValue],
) -> dict[str, CanonicalBackendAdmissionValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalBackendAdmissionValue,
) -> CanonicalBackendAdmissionValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalBackendAdmissionValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "BackendAdmissionDecision",
    "BackendAdmissionReason",
    "BackendAdmissionRequest",
    "BackendAdmissionStatusValue",
    "admit_runtime_backend",
    "backend_admission_decision_checksum",
    "recompute_backend_admission_decision_checksum",
]
