"""Deterministic trust-policy configuration validation contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import cast

from aegis.contracts.aegis_attestation_verifier import AttestationVerifierAdapterMetadata
from aegis.contracts.aegis_world_snapshot_trust import (
    TrustDomain,
    WorldSnapshotSourceType,
    WorldSnapshotTrustPolicy,
)

type CanonicalPolicyConfigValue = (
    str
    | int
    | float
    | bool
    | None
    | list[CanonicalPolicyConfigValue]
    | dict[str, CanonicalPolicyConfigValue]
)


class TrustPolicyConfigStatus(StrEnum):
    """Trust-policy configuration validation status values."""

    VALID = "VALID"
    MISSING_POLICY = "MISSING_POLICY"
    EMPTY_ALLOWED_SOURCES = "EMPTY_ALLOWED_SOURCES"
    EMPTY_ALLOWED_SOURCE_TYPES = "EMPTY_ALLOWED_SOURCE_TYPES"
    EMPTY_ALLOWED_DOMAINS = "EMPTY_ALLOWED_DOMAINS"
    EMPTY_ALLOWED_CAPABILITIES = "EMPTY_ALLOWED_CAPABILITIES"
    EMPTY_ALLOWED_ALGORITHMS = "EMPTY_ALLOWED_ALGORITHMS"
    EMPTY_ALLOWED_KEY_IDS = "EMPTY_ALLOWED_KEY_IDS"
    WILDCARD_SOURCE_NOT_ALLOWED = "WILDCARD_SOURCE_NOT_ALLOWED"
    WILDCARD_DOMAIN_NOT_ALLOWED = "WILDCARD_DOMAIN_NOT_ALLOWED"
    WILDCARD_CAPABILITY_NOT_ALLOWED = "WILDCARD_CAPABILITY_NOT_ALLOWED"
    TEST_SOURCE_FOR_PHYSICAL_RUNTIME = "TEST_SOURCE_FOR_PHYSICAL_RUNTIME"
    SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME = "SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME"
    ATTESTATION_REQUIRED_FALSE_IN_ENFORCE = "ATTESTATION_REQUIRED_FALSE_IN_ENFORCE"
    POLICY_VERIFIER_ALGORITHM_MISMATCH = "POLICY_VERIFIER_ALGORITHM_MISMATCH"
    POLICY_VERIFIER_KEY_MISMATCH = "POLICY_VERIFIER_KEY_MISMATCH"
    POLICY_CAPABILITY_CONTEXT_MISMATCH = "POLICY_CAPABILITY_CONTEXT_MISMATCH"
    CONFLICTING_POLICY_FIELDS = "CONFLICTING_POLICY_FIELDS"
    MALFORMED_POLICY = "MALFORMED_POLICY"


@dataclass(frozen=True, slots=True, init=False)
class TrustPolicyConfigValidationResult:
    """Deterministic result of trust-policy configuration validation."""

    status: TrustPolicyConfigStatus
    reason_code: str
    trust_policy_checksum: str | None
    verifier_metadata_checksum: str | None
    allowed_runtime_domain: TrustDomain | None
    capability: str | None
    enforce_mode: bool
    checksum: str

    def __init__(
        self,
        *,
        status: TrustPolicyConfigStatus,
        reason_code: str,
        trust_policy_checksum: str | None,
        verifier_metadata_checksum: str | None,
        allowed_runtime_domain: TrustDomain | None,
        capability: str | None,
        enforce_mode: object,
        checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_config_status(status)
        normalized_reason = _normalize_reason_code(reason_code, "reason_code")
        normalized_policy_checksum = _normalize_optional_text(
            trust_policy_checksum, "trust_policy_checksum"
        )
        normalized_metadata_checksum = _normalize_optional_text(
            verifier_metadata_checksum, "verifier_metadata_checksum"
        )
        normalized_domain = _normalize_optional_trust_domain(allowed_runtime_domain)
        normalized_capability = (
            None if capability is None else _normalize_capability_name(capability)
        )
        if not isinstance(enforce_mode, bool):
            raise ValueError("enforce_mode must be a bool")
        if normalized_status is TrustPolicyConfigStatus.VALID:
            _validate_valid_config_fields(
                trust_policy_checksum=normalized_policy_checksum,
                verifier_metadata_checksum=normalized_metadata_checksum,
                allowed_runtime_domain=normalized_domain,
                capability=normalized_capability,
            )
        computed_checksum = trust_policy_config_validation_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            trust_policy_checksum=normalized_policy_checksum,
            verifier_metadata_checksum=normalized_metadata_checksum,
            allowed_runtime_domain=normalized_domain,
            capability=normalized_capability,
            enforce_mode=enforce_mode,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "trust_policy_checksum", normalized_policy_checksum)
        object.__setattr__(self, "verifier_metadata_checksum", normalized_metadata_checksum)
        object.__setattr__(self, "allowed_runtime_domain", normalized_domain)
        object.__setattr__(self, "capability", normalized_capability)
        object.__setattr__(self, "enforce_mode", enforce_mode)
        object.__setattr__(self, "checksum", normalized_checksum)


def validate_trust_policy_config(
    trust_policy: object,
    *,
    verifier_metadata: object,
    runtime_domain: object,
    capability: str,
    enforce_mode: object,
) -> TrustPolicyConfigValidationResult:
    """Validate that a trust policy is safe for the verifier and runtime context."""
    if not isinstance(enforce_mode, bool):
        raise ValueError("enforce_mode must be a bool")
    normalized_runtime_domain = _normalize_trust_domain(runtime_domain)
    normalized_capability = _normalize_capability_name(capability)
    if trust_policy is None:
        return _config_result(
            status=TrustPolicyConfigStatus.MISSING_POLICY,
            reason_code="TRUST_POLICY_CONFIG_MISSING",
            runtime_domain=normalized_runtime_domain,
            capability=normalized_capability,
            enforce_mode=enforce_mode,
        )
    if not isinstance(trust_policy, WorldSnapshotTrustPolicy):
        return _config_result(
            status=TrustPolicyConfigStatus.MALFORMED_POLICY,
            reason_code="TRUST_POLICY_CONFIG_MALFORMED",
            runtime_domain=normalized_runtime_domain,
            capability=normalized_capability,
            enforce_mode=enforce_mode,
        )
    if verifier_metadata is None or not isinstance(
        verifier_metadata, AttestationVerifierAdapterMetadata
    ):
        return _config_result(
            status=TrustPolicyConfigStatus.MALFORMED_POLICY,
            reason_code="TRUST_POLICY_VERIFIER_METADATA_MISSING",
            trust_policy_checksum=trust_policy.checksum,
            runtime_domain=normalized_runtime_domain,
            capability=normalized_capability,
            enforce_mode=enforce_mode,
        )

    failure = _trust_policy_config_failure(
        trust_policy=trust_policy,
        verifier_metadata=verifier_metadata,
        runtime_domain=normalized_runtime_domain,
        capability=normalized_capability,
        enforce_mode=enforce_mode,
    )
    if failure is not None:
        status, reason_code = failure
        return _config_result(
            status=status,
            reason_code=reason_code,
            trust_policy_checksum=trust_policy.checksum,
            verifier_metadata_checksum=verifier_metadata.checksum,
            runtime_domain=normalized_runtime_domain,
            capability=normalized_capability,
            enforce_mode=enforce_mode,
        )

    return _config_result(
        status=TrustPolicyConfigStatus.VALID,
        reason_code="TRUST_POLICY_CONFIG_VALID",
        trust_policy_checksum=trust_policy.checksum,
        verifier_metadata_checksum=verifier_metadata.checksum,
        runtime_domain=normalized_runtime_domain,
        capability=normalized_capability,
        enforce_mode=enforce_mode,
    )


def trust_policy_config_validation_result_checksum(
    *,
    status: TrustPolicyConfigStatus,
    reason_code: str,
    trust_policy_checksum: str | None,
    verifier_metadata_checksum: str | None,
    allowed_runtime_domain: TrustDomain | None,
    capability: str | None,
    enforce_mode: bool,
) -> str:
    """Return a deterministic checksum for trust-policy config validation."""
    return _sha256(
        {
            "status": status.value,
            "reason_code": reason_code,
            "trust_policy_checksum": trust_policy_checksum,
            "verifier_metadata_checksum": verifier_metadata_checksum,
            "allowed_runtime_domain": (
                allowed_runtime_domain.value if allowed_runtime_domain is not None else None
            ),
            "capability": capability,
            "enforce_mode": enforce_mode,
        }
    )


def _trust_policy_config_failure(
    *,
    trust_policy: WorldSnapshotTrustPolicy,
    verifier_metadata: AttestationVerifierAdapterMetadata,
    runtime_domain: TrustDomain,
    capability: str,
    enforce_mode: bool,
) -> tuple[TrustPolicyConfigStatus, str] | None:
    if not trust_policy.allowed_source_ids:
        return TrustPolicyConfigStatus.EMPTY_ALLOWED_SOURCES, "TRUST_POLICY_EMPTY_ALLOWED_SOURCES"
    if not trust_policy.allowed_source_types:
        return (
            TrustPolicyConfigStatus.EMPTY_ALLOWED_SOURCE_TYPES,
            "TRUST_POLICY_EMPTY_ALLOWED_SOURCE_TYPES",
        )
    if not trust_policy.allowed_trust_domains:
        return TrustPolicyConfigStatus.EMPTY_ALLOWED_DOMAINS, "TRUST_POLICY_EMPTY_ALLOWED_DOMAINS"
    if not trust_policy.allowed_capabilities:
        return (
            TrustPolicyConfigStatus.EMPTY_ALLOWED_CAPABILITIES,
            "TRUST_POLICY_EMPTY_ALLOWED_CAPABILITIES",
        )
    if not trust_policy.allowed_algorithms:
        return (
            TrustPolicyConfigStatus.EMPTY_ALLOWED_ALGORITHMS,
            "TRUST_POLICY_EMPTY_ALLOWED_ALGORITHMS",
        )
    if not trust_policy.allowed_key_ids:
        return TrustPolicyConfigStatus.EMPTY_ALLOWED_KEY_IDS, "TRUST_POLICY_EMPTY_ALLOWED_KEY_IDS"
    if _contains_wildcard(trust_policy.allowed_source_ids):
        return TrustPolicyConfigStatus.WILDCARD_SOURCE_NOT_ALLOWED, "TRUST_POLICY_WILDCARD_SOURCE"
    if _contains_wildcard(trust_policy.allowed_capabilities):
        return (
            TrustPolicyConfigStatus.WILDCARD_CAPABILITY_NOT_ALLOWED,
            "TRUST_POLICY_WILDCARD_CAPABILITY",
        )
    if enforce_mode and not trust_policy.require_attestation:
        return (
            TrustPolicyConfigStatus.ATTESTATION_REQUIRED_FALSE_IN_ENFORCE,
            "TRUST_POLICY_ATTESTATION_REQUIRED_FALSE_IN_ENFORCE",
        )
    if enforce_mode and runtime_domain is TrustDomain.PHYSICAL_RUNTIME:
        physical_failure = _physical_runtime_config_failure(trust_policy)
        if physical_failure is not None:
            return physical_failure
    if not trust_policy.allowed_algorithms.issubset(verifier_metadata.supported_algorithms):
        return (
            TrustPolicyConfigStatus.POLICY_VERIFIER_ALGORITHM_MISMATCH,
            "TRUST_POLICY_VERIFIER_ALGORITHM_MISMATCH",
        )
    if not trust_policy.allowed_key_ids.issubset(verifier_metadata.supported_key_ids):
        return (
            TrustPolicyConfigStatus.POLICY_VERIFIER_KEY_MISMATCH,
            "TRUST_POLICY_VERIFIER_KEY_MISMATCH",
        )
    if capability not in trust_policy.allowed_capabilities:
        return (
            TrustPolicyConfigStatus.POLICY_CAPABILITY_CONTEXT_MISMATCH,
            "TRUST_POLICY_CAPABILITY_CONTEXT_MISMATCH",
        )
    if runtime_domain not in trust_policy.allowed_trust_domains:
        return (
            TrustPolicyConfigStatus.CONFLICTING_POLICY_FIELDS,
            "TRUST_POLICY_RUNTIME_DOMAIN_MISMATCH",
        )
    return None


def _physical_runtime_config_failure(
    trust_policy: WorldSnapshotTrustPolicy,
) -> tuple[TrustPolicyConfigStatus, str] | None:
    if trust_policy.allowed_trust_domains == frozenset(TrustDomain):
        return TrustPolicyConfigStatus.WILDCARD_DOMAIN_NOT_ALLOWED, "TRUST_POLICY_WILDCARD_DOMAIN"
    test_like_sources = {WorldSnapshotSourceType.TEST_FIXTURE, WorldSnapshotSourceType.STATIC_SCENE}
    if trust_policy.allowed_source_types.intersection(test_like_sources):
        return (
            TrustPolicyConfigStatus.TEST_SOURCE_FOR_PHYSICAL_RUNTIME,
            "TRUST_POLICY_TEST_SOURCE_FOR_PHYSICAL_RUNTIME",
        )
    if TrustDomain.SIMULATION in trust_policy.allowed_trust_domains:
        return (
            TrustPolicyConfigStatus.SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME,
            "TRUST_POLICY_SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME",
        )
    if not trust_policy.reject_test_sources_for_physical_runtime:
        return (
            TrustPolicyConfigStatus.CONFLICTING_POLICY_FIELDS,
            "TRUST_POLICY_TEST_REJECTION_DISABLED",
        )
    return None


def _config_result(
    *,
    status: TrustPolicyConfigStatus,
    reason_code: str,
    runtime_domain: TrustDomain,
    capability: str,
    enforce_mode: bool,
    trust_policy_checksum: str | None = None,
    verifier_metadata_checksum: str | None = None,
) -> TrustPolicyConfigValidationResult:
    return TrustPolicyConfigValidationResult(
        status=status,
        reason_code=reason_code,
        trust_policy_checksum=trust_policy_checksum,
        verifier_metadata_checksum=verifier_metadata_checksum,
        allowed_runtime_domain=runtime_domain,
        capability=capability,
        enforce_mode=enforce_mode,
    )


def _contains_wildcard(values: Iterable[str]) -> bool:
    wildcard_values = {"*", "all", "ALL", "any", "ANY"}
    return any(value in wildcard_values or "*" in value for value in values)


def _validate_valid_config_fields(
    *,
    trust_policy_checksum: str | None,
    verifier_metadata_checksum: str | None,
    allowed_runtime_domain: TrustDomain | None,
    capability: str | None,
) -> None:
    if trust_policy_checksum is None:
        raise ValueError("VALID requires trust_policy_checksum")
    if verifier_metadata_checksum is None:
        raise ValueError("VALID requires verifier_metadata_checksum")
    if allowed_runtime_domain is None:
        raise ValueError("VALID requires allowed_runtime_domain")
    if capability is None:
        raise ValueError("VALID requires capability")


def _normalize_config_status(value: TrustPolicyConfigStatus) -> TrustPolicyConfigStatus:
    if not isinstance(value, TrustPolicyConfigStatus):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("status must be a TrustPolicyConfigStatus")
    return value


def _normalize_trust_domain(value: object) -> TrustDomain:
    if not isinstance(value, TrustDomain):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("runtime_domain must be a TrustDomain")
    return value


def _normalize_optional_trust_domain(value: TrustDomain | None) -> TrustDomain | None:
    if value is None:
        return None
    return _normalize_trust_domain(value)


def _normalize_required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(f"{field_name} must be a string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    if value == "":
        raise ValueError(f"{field_name} must be non-empty")
    return value


def _normalize_optional_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_reason_code(value: str, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a machine-readable uppercase reason code")
    return normalized


def _normalize_capability_name(value: str) -> str:
    normalized = _normalize_required_text(value, "capability")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    if supplied_checksum is None:
        return computed_checksum
    normalized = _normalize_required_text(supplied_checksum, field_name)
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match deterministic checksum")
    return normalized


def _canonicalise(value: object) -> CanonicalPolicyConfigValue:
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
        return _canonical_mapping(cast(Mapping[object, object], value))
    if isinstance(value, tuple):
        return [_canonicalise(item) for item in cast(tuple[object, ...], value)]
    if isinstance(value, list):
        return [_canonicalise(item) for item in cast(list[object], value)]
    if isinstance(value, frozenset):
        set_items = cast(frozenset[object], value)
        return sorted((_canonicalise(item) for item in set_items), key=_canonical_sort_key)
    raise ValueError("policy config values must be JSON-compatible frozen values")


def _canonical_mapping(values: Mapping[object, object]) -> dict[str, CanonicalPolicyConfigValue]:
    canonical: dict[str, CanonicalPolicyConfigValue] = {}
    for key, value in values.items():
        if not isinstance(key, str):
            raise ValueError("policy config mapping keys must be strings")
        canonical[key] = _canonicalise(value)
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sort_key(value: CanonicalPolicyConfigValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha256(value: Mapping[str, object]) -> str:
    canonical = json.dumps(
        _canonical_mapping(cast(Mapping[object, object], value)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "TrustPolicyConfigStatus",
    "TrustPolicyConfigValidationResult",
    "trust_policy_config_validation_result_checksum",
    "validate_trust_policy_config",
]
