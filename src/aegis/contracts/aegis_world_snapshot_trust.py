"""Deterministic world snapshot evidence trust contracts.

This module seals the Phase 2 trust boundary after freshness validation. It
evaluates provenance claims over caller-supplied world snapshot evidence using
only explicit inputs: the snapshot checksum, evidence envelope, deterministic
trust policy, optional attestation, optional verifier, capability, and supplied
evaluation time. It performs no I/O and never reads clocks or process state.

The boundary proves only deterministic provenance-policy enforcement. It does
not prove that the supplied world model is true or physically safe.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol, TypeGuard, cast

from aegis.aegis_errors import AegisError
from aegis.contracts.aegis_json_types import FrozenJsonValue, JsonValue, freeze_json_mapping
from aegis.contracts.aegis_policy import WorldSnapshotStub
from aegis.contracts.aegis_world_snapshot_admissibility import (
    WorldSnapshotAdmissibilityResult,
    WorldSnapshotAdmissibilityStatus,
    validate_world_snapshot_admissibility,
)
from aegis.contracts.aegis_world_snapshot_freshness import (
    WorldSnapshotFreshnessResult,
    WorldSnapshotFreshnessStatus,
)

if TYPE_CHECKING:
    from aegis.contracts.aegis_attestation_verifier import (
        AttestationVerifierAdapterMetadata,
        VerifierAdapterCertificationResult,
    )
    from aegis.contracts.aegis_trust_policy_config import TrustPolicyConfigValidationResult


class WorldSnapshotTrustError(AegisError):
    """Raised when world snapshot trust integrity checks fail catastrophically."""


class WorldSnapshotTrustStatus(StrEnum):
    """Trust verdict values for world snapshot evidence."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    MISSING_TRUST_POLICY = "MISSING_TRUST_POLICY"
    MISSING_VERIFIER = "MISSING_VERIFIER"
    SNAPSHOT_CHECKSUM_MISMATCH = "SNAPSHOT_CHECKSUM_MISMATCH"
    SOURCE_NOT_ALLOWED = "SOURCE_NOT_ALLOWED"
    SOURCE_TYPE_NOT_ALLOWED = "SOURCE_TYPE_NOT_ALLOWED"
    TRUST_DOMAIN_NOT_ALLOWED = "TRUST_DOMAIN_NOT_ALLOWED"
    CAPABILITY_NOT_ALLOWED = "CAPABILITY_NOT_ALLOWED"
    ATTESTATION_MISSING = "ATTESTATION_MISSING"
    ATTESTATION_INVALID = "ATTESTATION_INVALID"
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"
    ATTESTATION_NOT_YET_VALID = "ATTESTATION_NOT_YET_VALID"
    ATTESTATION_REPLAY_DETECTED = "ATTESTATION_REPLAY_DETECTED"
    UNSUPPORTED_ATTESTATION_ALGORITHM = "UNSUPPORTED_ATTESTATION_ALGORITHM"
    MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"


class WorldSnapshotSourceType(StrEnum):
    """Declared producer class for world snapshot evidence."""

    TEST_FIXTURE = "TEST_FIXTURE"
    SIMULATOR = "SIMULATOR"
    SENSOR_BRIDGE = "SENSOR_BRIDGE"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    STATIC_SCENE = "STATIC_SCENE"
    UNKNOWN = "UNKNOWN"


class TrustDomain(StrEnum):
    """Trust domain in which world snapshot evidence is claimed."""

    TEST = "TEST"
    SIMULATION = "SIMULATION"
    DEVELOPMENT = "DEVELOPMENT"
    STAGING = "STAGING"
    PHYSICAL_RUNTIME = "PHYSICAL_RUNTIME"


type CanonicalTrustValue = (
    str | int | float | bool | None | list[CanonicalTrustValue] | dict[str, CanonicalTrustValue]
)


class AttestationVerifier(Protocol):
    """Deterministic verifier interface for injected attestation checks."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return immutable adapter identity and capability metadata."""
        ...

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        """Verify that attestation material binds to the supplied evidence."""
        ...


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotAttestation:
    """Attestation binding a source claim to a snapshot and evidence envelope."""

    attestation_id: str
    subject_snapshot_checksum: str
    subject_envelope_id: str
    source_id: str
    trust_domain: TrustDomain
    issued_at_ms: int
    valid_from_ms: int
    valid_until_ms: int
    algorithm: str
    key_id: str
    signature: str
    signed_payload_checksum: str
    metadata: Mapping[str, FrozenJsonValue]
    checksum: str

    def __init__(
        self,
        *,
        attestation_id: str,
        subject_snapshot_checksum: str,
        subject_envelope_id: str,
        source_id: str,
        trust_domain: TrustDomain,
        issued_at_ms: object,
        valid_from_ms: object,
        valid_until_ms: object,
        algorithm: str,
        key_id: str,
        signature: str,
        signed_payload_checksum: str,
        metadata: Mapping[str, JsonValue] | None = None,
        checksum: str | None = None,
    ) -> None:
        normalized_trust_domain = _normalize_trust_domain(trust_domain)
        normalized_issued_at_ms = _normalize_non_negative_int(issued_at_ms, "issued_at_ms")
        normalized_valid_from_ms = _normalize_non_negative_int(valid_from_ms, "valid_from_ms")
        normalized_valid_until_ms = _normalize_non_negative_int(valid_until_ms, "valid_until_ms")
        if normalized_valid_from_ms > normalized_valid_until_ms:
            raise ValueError("valid_from_ms must be <= valid_until_ms")
        if not normalized_valid_from_ms <= normalized_issued_at_ms <= normalized_valid_until_ms:
            raise ValueError("issued_at_ms must be within attestation validity range")

        frozen_metadata = freeze_json_mapping(metadata or {})
        normalized_fields = {
            "attestation_id": _normalize_required_text(attestation_id, "attestation_id"),
            "subject_snapshot_checksum": _normalize_required_text(
                subject_snapshot_checksum, "subject_snapshot_checksum"
            ),
            "subject_envelope_id": _normalize_required_text(
                subject_envelope_id, "subject_envelope_id"
            ),
            "source_id": _normalize_required_text(source_id, "source_id"),
            "algorithm": _normalize_required_text(algorithm, "algorithm"),
            "key_id": _normalize_required_text(key_id, "key_id"),
            "signature": _normalize_required_text(signature, "signature"),
            "signed_payload_checksum": _normalize_required_text(
                signed_payload_checksum, "signed_payload_checksum"
            ),
        }
        computed_checksum = world_snapshot_attestation_checksum(
            trust_domain=normalized_trust_domain,
            issued_at_ms=normalized_issued_at_ms,
            valid_from_ms=normalized_valid_from_ms,
            valid_until_ms=normalized_valid_until_ms,
            metadata=frozen_metadata,
            **normalized_fields,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        for field_name, value in normalized_fields.items():
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "trust_domain", normalized_trust_domain)
        object.__setattr__(self, "issued_at_ms", normalized_issued_at_ms)
        object.__setattr__(self, "valid_from_ms", normalized_valid_from_ms)
        object.__setattr__(self, "valid_until_ms", normalized_valid_until_ms)
        object.__setattr__(self, "metadata", frozen_metadata)
        object.__setattr__(self, "checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotEvidenceEnvelope:
    """Provenance envelope around an immutable world snapshot checksum."""

    envelope_id: str
    world_snapshot_checksum: str
    source_id: str
    source_type: WorldSnapshotSourceType
    trust_domain: TrustDomain
    issued_at_ms: int
    evidence_nonce: str
    attestation: WorldSnapshotAttestation | None
    metadata: Mapping[str, FrozenJsonValue]
    checksum: str

    def __init__(
        self,
        *,
        envelope_id: str,
        world_snapshot_checksum: str,
        source_id: str,
        source_type: WorldSnapshotSourceType,
        trust_domain: TrustDomain,
        issued_at_ms: object,
        evidence_nonce: str,
        attestation: WorldSnapshotAttestation | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        checksum: str | None = None,
    ) -> None:
        normalized_source_type = _normalize_source_type(source_type)
        normalized_trust_domain = _normalize_trust_domain(trust_domain)
        normalized_issued_at_ms = _normalize_non_negative_int(issued_at_ms, "issued_at_ms")
        frozen_metadata = freeze_json_mapping(metadata or {})
        normalized_fields = {
            "envelope_id": _normalize_required_text(envelope_id, "envelope_id"),
            "world_snapshot_checksum": _normalize_required_text(
                world_snapshot_checksum, "world_snapshot_checksum"
            ),
            "source_id": _normalize_required_text(source_id, "source_id"),
            "evidence_nonce": _normalize_required_text(evidence_nonce, "evidence_nonce"),
        }
        computed_checksum = world_snapshot_evidence_envelope_checksum(
            source_type=normalized_source_type,
            trust_domain=normalized_trust_domain,
            issued_at_ms=normalized_issued_at_ms,
            attestation_checksum=attestation.checksum if attestation is not None else None,
            metadata=frozen_metadata,
            **normalized_fields,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        for field_name, value in normalized_fields.items():
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "source_type", normalized_source_type)
        object.__setattr__(self, "trust_domain", normalized_trust_domain)
        object.__setattr__(self, "issued_at_ms", normalized_issued_at_ms)
        object.__setattr__(self, "attestation", attestation)
        object.__setattr__(self, "metadata", frozen_metadata)
        object.__setattr__(self, "checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotTrustPolicy:
    """Deterministic allowlist policy for world snapshot provenance claims."""

    policy_id: str
    allowed_source_ids: frozenset[str]
    allowed_source_types: frozenset[WorldSnapshotSourceType]
    allowed_trust_domains: frozenset[TrustDomain]
    allowed_capabilities: frozenset[str]
    require_attestation: bool
    allowed_algorithms: frozenset[str]
    allowed_key_ids: frozenset[str]
    max_attestation_age_ms: int | None
    reject_test_sources_for_physical_runtime: bool
    metadata: Mapping[str, FrozenJsonValue]
    checksum: str

    def __init__(
        self,
        *,
        policy_id: str,
        allowed_source_ids: Iterable[str],
        allowed_source_types: Iterable[WorldSnapshotSourceType],
        allowed_trust_domains: Iterable[TrustDomain],
        allowed_capabilities: Iterable[str],
        require_attestation: object = True,
        allowed_algorithms: Iterable[str] = (),
        allowed_key_ids: Iterable[str] = (),
        max_attestation_age_ms: object = None,
        reject_test_sources_for_physical_runtime: object = True,
        metadata: Mapping[str, JsonValue] | None = None,
        checksum: str | None = None,
    ) -> None:
        if not isinstance(require_attestation, bool):
            raise ValueError("require_attestation must be a bool")
        if not isinstance(reject_test_sources_for_physical_runtime, bool):
            raise ValueError("reject_test_sources_for_physical_runtime must be a bool")
        normalized_max_age = _normalize_optional_non_negative_int(
            max_attestation_age_ms, "max_attestation_age_ms"
        )
        normalized_source_ids = frozenset(
            _normalize_required_text(source_id, "allowed_source_ids")
            for source_id in allowed_source_ids
        )
        normalized_source_types = frozenset(
            _normalize_source_type(source_type) for source_type in allowed_source_types
        )
        normalized_trust_domains = frozenset(
            _normalize_trust_domain(trust_domain) for trust_domain in allowed_trust_domains
        )
        normalized_capabilities = frozenset(
            _normalize_capability_name(capability) for capability in allowed_capabilities
        )
        normalized_algorithms = frozenset(
            _normalize_required_text(algorithm, "allowed_algorithms")
            for algorithm in allowed_algorithms
        )
        normalized_key_ids = frozenset(
            _normalize_required_text(key_id, "allowed_key_ids") for key_id in allowed_key_ids
        )
        frozen_metadata = freeze_json_mapping(metadata or {})
        normalized_policy_id = _normalize_required_text(policy_id, "policy_id")
        computed_checksum = world_snapshot_trust_policy_checksum(
            policy_id=normalized_policy_id,
            allowed_source_ids=normalized_source_ids,
            allowed_source_types=normalized_source_types,
            allowed_trust_domains=normalized_trust_domains,
            allowed_capabilities=normalized_capabilities,
            require_attestation=require_attestation,
            allowed_algorithms=normalized_algorithms,
            allowed_key_ids=normalized_key_ids,
            max_attestation_age_ms=normalized_max_age,
            reject_test_sources_for_physical_runtime=reject_test_sources_for_physical_runtime,
            metadata=frozen_metadata,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "policy_id", normalized_policy_id)
        object.__setattr__(self, "allowed_source_ids", normalized_source_ids)
        object.__setattr__(self, "allowed_source_types", normalized_source_types)
        object.__setattr__(self, "allowed_trust_domains", normalized_trust_domains)
        object.__setattr__(self, "allowed_capabilities", normalized_capabilities)
        object.__setattr__(self, "require_attestation", require_attestation)
        object.__setattr__(self, "allowed_algorithms", normalized_algorithms)
        object.__setattr__(self, "allowed_key_ids", normalized_key_ids)
        object.__setattr__(self, "max_attestation_age_ms", normalized_max_age)
        object.__setattr__(
            self,
            "reject_test_sources_for_physical_runtime",
            reject_test_sources_for_physical_runtime,
        )
        object.__setattr__(self, "metadata", frozen_metadata)
        object.__setattr__(self, "checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class AttestationVerificationResult:
    """Deterministic result returned by an injected attestation verifier."""

    status: Literal["PASS", "FAIL"]
    reason_code: str
    attestation_checksum: str
    evidence_envelope_checksum: str
    world_snapshot_checksum: str
    verifier_id: str
    verification_checksum: str

    def __init__(
        self,
        *,
        status: Literal["PASS", "FAIL"],
        reason_code: str,
        attestation_checksum: str,
        evidence_envelope_checksum: str,
        world_snapshot_checksum: str,
        verifier_id: str,
        verification_checksum: str | None = None,
    ) -> None:
        if status not in {"PASS", "FAIL"}:
            raise ValueError("status must be PASS or FAIL")
        normalized_reason = _normalize_reason_code(reason_code, "reason_code")
        normalized_attestation_checksum = _normalize_required_text(
            attestation_checksum, "attestation_checksum"
        )
        normalized_evidence_checksum = _normalize_required_text(
            evidence_envelope_checksum, "evidence_envelope_checksum"
        )
        normalized_snapshot_checksum = _normalize_required_text(
            world_snapshot_checksum, "world_snapshot_checksum"
        )
        normalized_verifier_id = _normalize_required_text(verifier_id, "verifier_id")
        computed_checksum = attestation_verification_result_checksum(
            status=status,
            reason_code=normalized_reason,
            attestation_checksum=normalized_attestation_checksum,
            evidence_envelope_checksum=normalized_evidence_checksum,
            world_snapshot_checksum=normalized_snapshot_checksum,
            verifier_id=normalized_verifier_id,
        )
        normalized_checksum = _normalize_supplied_checksum(
            verification_checksum, computed_checksum, "verification_checksum"
        )

        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "attestation_checksum", normalized_attestation_checksum)
        object.__setattr__(self, "evidence_envelope_checksum", normalized_evidence_checksum)
        object.__setattr__(self, "world_snapshot_checksum", normalized_snapshot_checksum)
        object.__setattr__(self, "verifier_id", normalized_verifier_id)
        object.__setattr__(self, "verification_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotTrustResult:
    """Final deterministic trust verdict used by policy and admission."""

    status: WorldSnapshotTrustStatus
    reason_code: str
    world_snapshot_checksum: str
    world_snapshot_admissibility_status: str | None
    world_snapshot_admissibility_reason_code: str | None
    world_snapshot_admissibility_result_checksum: str | None
    evidence_envelope_checksum: str | None
    attestation_checksum: str | None
    trust_policy_checksum: str
    verifier_certification_checksum: str | None
    trust_policy_config_validation_checksum: str | None
    verifier_id: str | None
    verifier_metadata_checksum: str | None
    source_id: str | None
    source_type: WorldSnapshotSourceType | None
    trust_domain: TrustDomain | None
    capability: str | None
    verification_result_checksum: str | None
    evaluation_time_ms: int
    checksum: str

    def __init__(
        self,
        *,
        status: WorldSnapshotTrustStatus,
        reason_code: str,
        world_snapshot_checksum: str,
        world_snapshot_admissibility_status: str | None = None,
        world_snapshot_admissibility_reason_code: str | None = None,
        world_snapshot_admissibility_result_checksum: str | None = None,
        evidence_envelope_checksum: str | None = None,
        attestation_checksum: str | None = None,
        trust_policy_checksum: str = "",
        verifier_certification_checksum: str | None = None,
        trust_policy_config_validation_checksum: str | None = None,
        verifier_id: str | None = None,
        verifier_metadata_checksum: str | None = None,
        source_id: str | None = None,
        source_type: WorldSnapshotSourceType | None = None,
        trust_domain: TrustDomain | None = None,
        capability: str | None = None,
        verification_result_checksum: str | None = None,
        evaluation_time_ms: object = 0,
        checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_trust_status(status)
        normalized_evaluation_time_ms = _normalize_non_negative_int(
            evaluation_time_ms, "evaluation_time_ms"
        )
        normalized_world_snapshot_checksum = _normalize_result_checksum(
            world_snapshot_checksum, "world_snapshot_checksum", normalized_status
        )
        normalized_trust_policy_checksum = _normalize_result_checksum(
            trust_policy_checksum, "trust_policy_checksum", normalized_status
        )
        normalized_admissibility_status = _normalize_optional_admissibility_status(
            world_snapshot_admissibility_status
        )
        normalized_admissibility_reason_code = _normalize_optional_text(
            world_snapshot_admissibility_reason_code, "world_snapshot_admissibility_reason_code"
        )
        normalized_admissibility_result_checksum = _normalize_optional_text(
            world_snapshot_admissibility_result_checksum,
            "world_snapshot_admissibility_result_checksum",
        )
        normalized_source_type = (
            None if source_type is None else _normalize_source_type(source_type)
        )
        normalized_trust_domain = (
            None if trust_domain is None else _normalize_trust_domain(trust_domain)
        )
        normalized_capability = (
            None if capability is None else _normalize_capability_name(capability)
        )
        normalized_reason_code = _normalize_reason_code(reason_code, "reason_code")
        normalized_evidence_envelope_checksum = _normalize_optional_text(
            evidence_envelope_checksum, "evidence_envelope_checksum"
        )
        normalized_attestation_checksum = _normalize_optional_text(
            attestation_checksum, "attestation_checksum"
        )
        normalized_verifier_certification_checksum = _normalize_optional_text(
            verifier_certification_checksum, "verifier_certification_checksum"
        )
        normalized_config_validation_checksum = _normalize_optional_text(
            trust_policy_config_validation_checksum, "trust_policy_config_validation_checksum"
        )
        normalized_verifier_id = _normalize_optional_text(verifier_id, "verifier_id")
        normalized_verifier_metadata_checksum = _normalize_optional_text(
            verifier_metadata_checksum, "verifier_metadata_checksum"
        )
        normalized_source_id = _normalize_optional_text(source_id, "source_id")
        normalized_verification_result_checksum = _normalize_optional_text(
            verification_result_checksum, "verification_result_checksum"
        )
        if normalized_status is WorldSnapshotTrustStatus.TRUSTED:
            _validate_trusted_result_fields(
                world_snapshot_checksum=normalized_world_snapshot_checksum,
                world_snapshot_admissibility_status=normalized_admissibility_status,
                world_snapshot_admissibility_result_checksum=(
                    normalized_admissibility_result_checksum
                ),
                trust_policy_checksum=normalized_trust_policy_checksum,
                reason_code=normalized_reason_code,
                evidence_envelope_checksum=normalized_evidence_envelope_checksum,
                attestation_checksum=normalized_attestation_checksum,
                verifier_certification_checksum=normalized_verifier_certification_checksum,
                trust_policy_config_validation_checksum=normalized_config_validation_checksum,
                verifier_id=normalized_verifier_id,
                verifier_metadata_checksum=normalized_verifier_metadata_checksum,
                source_id=normalized_source_id,
                source_type=normalized_source_type,
                trust_domain=normalized_trust_domain,
                capability=normalized_capability,
                verification_result_checksum=normalized_verification_result_checksum,
            )
        computed_checksum = world_snapshot_trust_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason_code,
            world_snapshot_checksum=normalized_world_snapshot_checksum,
            world_snapshot_admissibility_status=normalized_admissibility_status,
            world_snapshot_admissibility_reason_code=normalized_admissibility_reason_code,
            world_snapshot_admissibility_result_checksum=(normalized_admissibility_result_checksum),
            evidence_envelope_checksum=normalized_evidence_envelope_checksum,
            attestation_checksum=normalized_attestation_checksum,
            trust_policy_checksum=normalized_trust_policy_checksum,
            verifier_certification_checksum=normalized_verifier_certification_checksum,
            trust_policy_config_validation_checksum=normalized_config_validation_checksum,
            verifier_id=normalized_verifier_id,
            verifier_metadata_checksum=normalized_verifier_metadata_checksum,
            source_id=normalized_source_id,
            source_type=normalized_source_type,
            trust_domain=normalized_trust_domain,
            capability=normalized_capability,
            verification_result_checksum=normalized_verification_result_checksum,
            evaluation_time_ms=normalized_evaluation_time_ms,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "world_snapshot_checksum", normalized_world_snapshot_checksum)
        object.__setattr__(
            self, "world_snapshot_admissibility_status", normalized_admissibility_status
        )
        object.__setattr__(
            self, "world_snapshot_admissibility_reason_code", normalized_admissibility_reason_code
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_result_checksum",
            normalized_admissibility_result_checksum,
        )
        object.__setattr__(self, "trust_policy_checksum", normalized_trust_policy_checksum)
        object.__setattr__(self, "source_type", normalized_source_type)
        object.__setattr__(self, "trust_domain", normalized_trust_domain)
        object.__setattr__(self, "capability", normalized_capability)
        object.__setattr__(self, "evaluation_time_ms", normalized_evaluation_time_ms)
        object.__setattr__(self, "checksum", normalized_checksum)
        object.__setattr__(self, "reason_code", normalized_reason_code)
        object.__setattr__(
            self, "evidence_envelope_checksum", normalized_evidence_envelope_checksum
        )
        object.__setattr__(self, "attestation_checksum", normalized_attestation_checksum)
        object.__setattr__(
            self, "verifier_certification_checksum", normalized_verifier_certification_checksum
        )
        object.__setattr__(
            self,
            "trust_policy_config_validation_checksum",
            normalized_config_validation_checksum,
        )
        object.__setattr__(self, "verifier_id", normalized_verifier_id)
        object.__setattr__(
            self, "verifier_metadata_checksum", normalized_verifier_metadata_checksum
        )
        object.__setattr__(self, "source_id", normalized_source_id)
        object.__setattr__(
            self, "verification_result_checksum", normalized_verification_result_checksum
        )


def evaluate_world_snapshot_trust(
    *,
    world_snapshot: WorldSnapshotStub | None,
    freshness_result: WorldSnapshotFreshnessResult | None,
    evidence_envelope: WorldSnapshotEvidenceEnvelope | None,
    trust_policy: WorldSnapshotTrustPolicy | None,
    capability: str,
    evaluation_time_ms: object,
    admissibility_result: WorldSnapshotAdmissibilityResult | None = None,
    attestation_verifier: AttestationVerifier | None = None,
    verifier_certification: VerifierAdapterCertificationResult | None = None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None = None,
) -> WorldSnapshotTrustResult:
    """Evaluate world snapshot provenance against deterministic trust policy."""
    normalized_evaluation_time_ms = _normalize_non_negative_int(
        evaluation_time_ms, "evaluation_time_ms"
    )
    normalized_capability = _normalize_capability_name(capability)
    world_snapshot_checksum = _world_snapshot_checksum_or_empty(world_snapshot)
    bound_admissibility_result = admissibility_result or validate_world_snapshot_admissibility(
        world_snapshot,
        requested_capability=normalized_capability,
    )
    if bound_admissibility_result.status is not WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
        return _trust_result(
            status=WorldSnapshotTrustStatus.UNTRUSTED,
            reason_code="WORLD_SNAPSHOT_NOT_ADMISSIBLE",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            trust_policy_checksum=trust_policy.checksum if trust_policy is not None else "",
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )

    if trust_policy is None:
        return _trust_result(
            status=WorldSnapshotTrustStatus.MISSING_TRUST_POLICY,
            reason_code="WORLD_SNAPSHOT_TRUST_POLICY_MISSING",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            trust_policy_checksum="",
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
        )
    if evidence_envelope is None:
        return _trust_result(
            status=WorldSnapshotTrustStatus.MISSING_EVIDENCE,
            reason_code="WORLD_SNAPSHOT_EVIDENCE_MISSING",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            trust_policy_checksum=trust_policy.checksum,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    if world_snapshot is None or world_snapshot_checksum == "":
        return _envelope_result(
            status=WorldSnapshotTrustStatus.MALFORMED_EVIDENCE,
            reason_code="WORLD_SNAPSHOT_CHECKSUM_MISSING",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    if (
        freshness_result is None
        or freshness_result.status is not WorldSnapshotFreshnessStatus.FRESH
    ):
        return _envelope_result(
            status=WorldSnapshotTrustStatus.UNTRUSTED,
            reason_code="WORLD_SNAPSHOT_FRESHNESS_NOT_TRUSTABLE",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )

    envelope_checksum_violation = _evidence_envelope_checksum_violation(evidence_envelope)
    if envelope_checksum_violation is not None:
        return _envelope_result(
            status=WorldSnapshotTrustStatus.MALFORMED_EVIDENCE,
            reason_code=envelope_checksum_violation,
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    if evidence_envelope.world_snapshot_checksum != world_snapshot_checksum:
        return _envelope_result(
            status=WorldSnapshotTrustStatus.SNAPSHOT_CHECKSUM_MISMATCH,
            reason_code="WORLD_SNAPSHOT_CHECKSUM_MISMATCH",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )

    allowlist_status = _trust_policy_allowlist_status(
        trust_policy=trust_policy,
        evidence_envelope=evidence_envelope,
        capability=normalized_capability,
    )
    if allowlist_status is not None:
        status, reason_code = allowlist_status
        return _envelope_result(
            status=status,
            reason_code=reason_code,
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )

    verification_result_checksum: str | None = None
    attestation = evidence_envelope.attestation
    if trust_policy.require_attestation:
        if attestation is None:
            return _envelope_result(
                status=WorldSnapshotTrustStatus.ATTESTATION_MISSING,
                reason_code="WORLD_SNAPSHOT_ATTESTATION_MISSING",
                world_snapshot_checksum=world_snapshot_checksum,
                admissibility_result=bound_admissibility_result,
                evidence_envelope=evidence_envelope,
                trust_policy=trust_policy,
                capability=normalized_capability,
                evaluation_time_ms=normalized_evaluation_time_ms,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            )
        attestation_status = _attestation_status(
            attestation=attestation,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            world_snapshot_checksum=world_snapshot_checksum,
            evaluation_time_ms=normalized_evaluation_time_ms,
            capability=normalized_capability,
            admissibility_result=bound_admissibility_result,
            attestation_verifier=attestation_verifier,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
        if isinstance(attestation_status, WorldSnapshotTrustResult):
            return attestation_status
        verification_result_checksum = attestation_status

    if not _is_certified_verifier(verifier_certification):
        return _envelope_result(
            status=WorldSnapshotTrustStatus.UNTRUSTED,
            reason_code="ATTESTATION_VERIFIER_NOT_CERTIFIED",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    if not _is_valid_trust_policy_config(trust_policy_config_validation):
        return _envelope_result(
            status=WorldSnapshotTrustStatus.UNTRUSTED,
            reason_code="TRUST_POLICY_CONFIG_NOT_VALID",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=bound_admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=normalized_capability,
            evaluation_time_ms=normalized_evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )

    return WorldSnapshotTrustResult(
        status=WorldSnapshotTrustStatus.TRUSTED,
        reason_code="WORLD_SNAPSHOT_TRUSTED",
        world_snapshot_checksum=world_snapshot_checksum,
        world_snapshot_admissibility_status=bound_admissibility_result.status.value,
        world_snapshot_admissibility_reason_code=bound_admissibility_result.reason_code,
        world_snapshot_admissibility_result_checksum=bound_admissibility_result.checksum,
        evidence_envelope_checksum=evidence_envelope.checksum,
        attestation_checksum=attestation.checksum if attestation is not None else None,
        trust_policy_checksum=trust_policy.checksum,
        verifier_certification_checksum=verifier_certification.checksum,
        trust_policy_config_validation_checksum=trust_policy_config_validation.checksum,
        verifier_id=verifier_certification.verifier_id,
        verifier_metadata_checksum=verifier_certification.verifier_metadata_checksum,
        source_id=evidence_envelope.source_id,
        source_type=evidence_envelope.source_type,
        trust_domain=evidence_envelope.trust_domain,
        capability=normalized_capability,
        verification_result_checksum=verification_result_checksum,
        evaluation_time_ms=normalized_evaluation_time_ms,
    )


def assert_world_snapshot_trust_integrity(
    *,
    world_snapshot: WorldSnapshotStub,
    trust_result: WorldSnapshotTrustResult,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    trust_policy: WorldSnapshotTrustPolicy,
    capability: str,
    evaluation_time_ms: int,
) -> WorldSnapshotTrustResult:
    """Verify that a TRUSTED result binds to exact snapshot, policy, and envelope."""
    expected_checksum = world_snapshot_trust_result_checksum(
        status=trust_result.status,
        reason_code=trust_result.reason_code,
        world_snapshot_checksum=trust_result.world_snapshot_checksum,
        world_snapshot_admissibility_status=trust_result.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=(
            trust_result.world_snapshot_admissibility_reason_code
        ),
        world_snapshot_admissibility_result_checksum=(
            trust_result.world_snapshot_admissibility_result_checksum
        ),
        evidence_envelope_checksum=trust_result.evidence_envelope_checksum,
        attestation_checksum=trust_result.attestation_checksum,
        trust_policy_checksum=trust_result.trust_policy_checksum,
        verifier_certification_checksum=trust_result.verifier_certification_checksum,
        trust_policy_config_validation_checksum=(
            trust_result.trust_policy_config_validation_checksum
        ),
        verifier_id=trust_result.verifier_id,
        verifier_metadata_checksum=trust_result.verifier_metadata_checksum,
        source_id=trust_result.source_id,
        source_type=trust_result.source_type,
        trust_domain=trust_result.trust_domain,
        capability=trust_result.capability,
        verification_result_checksum=trust_result.verification_result_checksum,
        evaluation_time_ms=trust_result.evaluation_time_ms,
    )
    violations: list[str] = []
    snapshot_checksum = _world_snapshot_checksum_or_empty(world_snapshot)
    if trust_result.status is not WorldSnapshotTrustStatus.TRUSTED:
        violations.append("TRUST_STATUS_NOT_TRUSTED")
    if trust_result.world_snapshot_checksum != snapshot_checksum:
        violations.append("TRUST_SNAPSHOT_CHECKSUM_MISMATCH")
    if trust_result.evidence_envelope_checksum != evidence_envelope.checksum:
        violations.append("TRUST_EVIDENCE_ENVELOPE_CHECKSUM_MISMATCH")
    if trust_result.trust_policy_checksum != trust_policy.checksum:
        violations.append("TRUST_POLICY_CHECKSUM_MISMATCH")
    if trust_result.source_id != evidence_envelope.source_id:
        violations.append("TRUST_SOURCE_ID_MISMATCH")
    if trust_result.source_type is not evidence_envelope.source_type:
        violations.append("TRUST_SOURCE_TYPE_MISMATCH")
    if trust_result.trust_domain is not evidence_envelope.trust_domain:
        violations.append("TRUST_DOMAIN_MISMATCH")
    if trust_result.capability != _normalize_capability_name(capability):
        violations.append("TRUST_CAPABILITY_MISMATCH")
    if trust_result.evaluation_time_ms != evaluation_time_ms:
        violations.append("TRUST_EVALUATION_TIME_MISMATCH")
    if trust_result.checksum != expected_checksum:
        violations.append("TRUST_RESULT_CHECKSUM_MISMATCH")
    if violations:
        raise WorldSnapshotTrustError(
            message="World snapshot trust integrity check failed",
            layer="policy",
            context={"reasons": list(violations), "snapshot_checksum": snapshot_checksum},
        )
    return trust_result


def is_trust_backed_admission(
    *,
    trust_result: WorldSnapshotTrustResult | None,
    expected_snapshot_checksum: str | None,
    expected_trust_checksum: str | None,
) -> bool:
    """Return True only when admission carries a fully-bound TRUSTED result."""
    if trust_result is None:
        return False
    if trust_result.status is not WorldSnapshotTrustStatus.TRUSTED:
        return False
    if (
        expected_snapshot_checksum is None
        or trust_result.world_snapshot_checksum != expected_snapshot_checksum
    ):
        return False
    return expected_trust_checksum is not None and trust_result.checksum == expected_trust_checksum


def world_snapshot_attestation_payload_checksum(
    *,
    subject_snapshot_checksum: str,
    subject_envelope_id: str,
    source_id: str,
    trust_domain: TrustDomain,
    issued_at_ms: int,
    valid_from_ms: int,
    valid_until_ms: int,
    algorithm: str,
    key_id: str,
) -> str:
    """Return the deterministic payload checksum an attestation claims to sign."""
    return _sha256(
        {
            "subject_snapshot_checksum": subject_snapshot_checksum,
            "subject_envelope_id": subject_envelope_id,
            "source_id": source_id,
            "trust_domain": trust_domain.value,
            "issued_at_ms": issued_at_ms,
            "valid_from_ms": valid_from_ms,
            "valid_until_ms": valid_until_ms,
            "algorithm": algorithm,
            "key_id": key_id,
        }
    )


def world_snapshot_attestation_checksum(
    *,
    attestation_id: str,
    subject_snapshot_checksum: str,
    subject_envelope_id: str,
    source_id: str,
    trust_domain: TrustDomain,
    issued_at_ms: int,
    valid_from_ms: int,
    valid_until_ms: int,
    algorithm: str,
    key_id: str,
    signature: str,
    signed_payload_checksum: str,
    metadata: Mapping[str, FrozenJsonValue],
) -> str:
    """Return a deterministic checksum for a WorldSnapshotAttestation."""
    return _sha256(
        {
            "attestation_id": attestation_id,
            "subject_snapshot_checksum": subject_snapshot_checksum,
            "subject_envelope_id": subject_envelope_id,
            "source_id": source_id,
            "trust_domain": trust_domain.value,
            "issued_at_ms": issued_at_ms,
            "valid_from_ms": valid_from_ms,
            "valid_until_ms": valid_until_ms,
            "algorithm": algorithm,
            "key_id": key_id,
            "signature": signature,
            "signed_payload_checksum": signed_payload_checksum,
            "metadata": _canonicalise(metadata),
        }
    )


def world_snapshot_evidence_envelope_checksum(
    *,
    envelope_id: str,
    world_snapshot_checksum: str,
    source_id: str,
    source_type: WorldSnapshotSourceType,
    trust_domain: TrustDomain,
    issued_at_ms: int,
    evidence_nonce: str,
    attestation_checksum: str | None,
    metadata: Mapping[str, FrozenJsonValue],
) -> str:
    """Return a deterministic checksum for a WorldSnapshotEvidenceEnvelope."""
    return _sha256(
        {
            "envelope_id": envelope_id,
            "world_snapshot_checksum": world_snapshot_checksum,
            "source_id": source_id,
            "source_type": source_type.value,
            "trust_domain": trust_domain.value,
            "issued_at_ms": issued_at_ms,
            "evidence_nonce": evidence_nonce,
            "attestation_checksum": attestation_checksum,
            "metadata": _canonicalise(metadata),
        }
    )


def world_snapshot_trust_policy_checksum(
    *,
    policy_id: str,
    allowed_source_ids: frozenset[str],
    allowed_source_types: frozenset[WorldSnapshotSourceType],
    allowed_trust_domains: frozenset[TrustDomain],
    allowed_capabilities: frozenset[str],
    require_attestation: bool,
    allowed_algorithms: frozenset[str],
    allowed_key_ids: frozenset[str],
    max_attestation_age_ms: int | None,
    reject_test_sources_for_physical_runtime: bool,
    metadata: Mapping[str, FrozenJsonValue],
) -> str:
    """Return a deterministic checksum for a WorldSnapshotTrustPolicy."""
    return _sha256(
        {
            "policy_id": policy_id,
            "allowed_source_ids": sorted(allowed_source_ids),
            "allowed_source_types": sorted(
                source_type.value for source_type in allowed_source_types
            ),
            "allowed_trust_domains": sorted(domain.value for domain in allowed_trust_domains),
            "allowed_capabilities": sorted(allowed_capabilities),
            "require_attestation": require_attestation,
            "allowed_algorithms": sorted(allowed_algorithms),
            "allowed_key_ids": sorted(allowed_key_ids),
            "max_attestation_age_ms": max_attestation_age_ms,
            "reject_test_sources_for_physical_runtime": reject_test_sources_for_physical_runtime,
            "metadata": _canonicalise(metadata),
        }
    )


def attestation_verification_result_checksum(
    *,
    status: Literal["PASS", "FAIL"],
    reason_code: str,
    attestation_checksum: str,
    evidence_envelope_checksum: str,
    world_snapshot_checksum: str,
    verifier_id: str,
) -> str:
    """Return a deterministic checksum for verifier output."""
    return _sha256(
        {
            "status": status,
            "reason_code": reason_code,
            "attestation_checksum": attestation_checksum,
            "evidence_envelope_checksum": evidence_envelope_checksum,
            "world_snapshot_checksum": world_snapshot_checksum,
            "verifier_id": verifier_id,
        }
    )


def world_snapshot_trust_result_checksum(
    *,
    status: WorldSnapshotTrustStatus,
    reason_code: str,
    world_snapshot_checksum: str,
    world_snapshot_admissibility_status: str | None,
    world_snapshot_admissibility_reason_code: str | None,
    world_snapshot_admissibility_result_checksum: str | None,
    evidence_envelope_checksum: str | None,
    attestation_checksum: str | None,
    trust_policy_checksum: str,
    verifier_certification_checksum: str | None,
    trust_policy_config_validation_checksum: str | None,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    source_id: str | None,
    source_type: WorldSnapshotSourceType | None,
    trust_domain: TrustDomain | None,
    capability: str | None,
    verification_result_checksum: str | None,
    evaluation_time_ms: int,
) -> str:
    """Return a deterministic checksum for a WorldSnapshotTrustResult."""
    return _sha256(
        {
            "status": status.value,
            "reason_code": reason_code,
            "world_snapshot_checksum": world_snapshot_checksum,
            "world_snapshot_admissibility_status": world_snapshot_admissibility_status,
            "world_snapshot_admissibility_reason_code": world_snapshot_admissibility_reason_code,
            "world_snapshot_admissibility_result_checksum": (
                world_snapshot_admissibility_result_checksum
            ),
            "evidence_envelope_checksum": evidence_envelope_checksum,
            "attestation_checksum": attestation_checksum,
            "trust_policy_checksum": trust_policy_checksum,
            "verifier_certification_checksum": verifier_certification_checksum,
            "trust_policy_config_validation_checksum": trust_policy_config_validation_checksum,
            "verifier_id": verifier_id,
            "verifier_metadata_checksum": verifier_metadata_checksum,
            "source_id": source_id,
            "source_type": source_type.value if source_type is not None else None,
            "trust_domain": trust_domain.value if trust_domain is not None else None,
            "capability": capability,
            "verification_result_checksum": verification_result_checksum,
            "evaluation_time_ms": evaluation_time_ms,
        }
    )


def _attestation_status(
    *,
    attestation: WorldSnapshotAttestation,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    trust_policy: WorldSnapshotTrustPolicy,
    world_snapshot_checksum: str,
    evaluation_time_ms: int,
    capability: str,
    admissibility_result: WorldSnapshotAdmissibilityResult,
    attestation_verifier: AttestationVerifier | None,
    verifier_certification: VerifierAdapterCertificationResult | None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None,
) -> str | WorldSnapshotTrustResult:
    failure = _attestation_binding_failure(
        attestation=attestation,
        evidence_envelope=evidence_envelope,
        trust_policy=trust_policy,
        world_snapshot_checksum=world_snapshot_checksum,
        evaluation_time_ms=evaluation_time_ms,
    )
    if failure is not None:
        status, reason_code = failure
        return _envelope_result(
            status=status,
            reason_code=reason_code,
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=capability,
            evaluation_time_ms=evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    if attestation_verifier is None:
        return _envelope_result(
            status=WorldSnapshotTrustStatus.MISSING_VERIFIER,
            reason_code="WORLD_SNAPSHOT_ATTESTATION_VERIFIER_MISSING",
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=capability,
            evaluation_time_ms=evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    verification = attestation_verifier.verify(
        attestation=attestation,
        evidence_envelope=evidence_envelope,
        world_snapshot_checksum=world_snapshot_checksum,
    )
    verification_failure = _verification_failure(
        verification=verification,
        attestation=attestation,
        evidence_envelope=evidence_envelope,
        world_snapshot_checksum=world_snapshot_checksum,
    )
    if verification_failure is not None:
        return _envelope_result(
            status=WorldSnapshotTrustStatus.ATTESTATION_INVALID,
            reason_code=verification_failure,
            world_snapshot_checksum=world_snapshot_checksum,
            admissibility_result=admissibility_result,
            evidence_envelope=evidence_envelope,
            trust_policy=trust_policy,
            capability=capability,
            evaluation_time_ms=evaluation_time_ms,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    return verification.verification_checksum


def _attestation_binding_failure(
    *,
    attestation: WorldSnapshotAttestation,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    trust_policy: WorldSnapshotTrustPolicy,
    world_snapshot_checksum: str,
    evaluation_time_ms: int,
) -> tuple[WorldSnapshotTrustStatus, str] | None:
    if _attestation_checksum_violation(attestation) is not None:
        return WorldSnapshotTrustStatus.MALFORMED_EVIDENCE, "ATTESTATION_CHECKSUM_MISMATCH"
    if attestation.subject_snapshot_checksum != world_snapshot_checksum:
        return WorldSnapshotTrustStatus.SNAPSHOT_CHECKSUM_MISMATCH, "ATTESTATION_SNAPSHOT_MISMATCH"
    if attestation.subject_envelope_id != evidence_envelope.envelope_id:
        return WorldSnapshotTrustStatus.CONTRADICTORY_EVIDENCE, "ATTESTATION_ENVELOPE_MISMATCH"
    if attestation.source_id != evidence_envelope.source_id:
        return WorldSnapshotTrustStatus.CONTRADICTORY_EVIDENCE, "ATTESTATION_SOURCE_MISMATCH"
    if attestation.trust_domain is not evidence_envelope.trust_domain:
        return WorldSnapshotTrustStatus.CONTRADICTORY_EVIDENCE, "ATTESTATION_DOMAIN_MISMATCH"
    expected_payload_checksum = world_snapshot_attestation_payload_checksum(
        subject_snapshot_checksum=attestation.subject_snapshot_checksum,
        subject_envelope_id=attestation.subject_envelope_id,
        source_id=attestation.source_id,
        trust_domain=attestation.trust_domain,
        issued_at_ms=attestation.issued_at_ms,
        valid_from_ms=attestation.valid_from_ms,
        valid_until_ms=attestation.valid_until_ms,
        algorithm=attestation.algorithm,
        key_id=attestation.key_id,
    )
    if attestation.signed_payload_checksum != expected_payload_checksum:
        return WorldSnapshotTrustStatus.ATTESTATION_INVALID, "ATTESTATION_PAYLOAD_MISMATCH"
    if attestation.algorithm not in trust_policy.allowed_algorithms:
        return (
            WorldSnapshotTrustStatus.UNSUPPORTED_ATTESTATION_ALGORITHM,
            "ATTESTATION_ALGORITHM_NOT_ALLOWED",
        )
    if attestation.key_id not in trust_policy.allowed_key_ids:
        return WorldSnapshotTrustStatus.ATTESTATION_INVALID, "ATTESTATION_KEY_ID_NOT_ALLOWED"
    if (
        evaluation_time_ms < attestation.valid_from_ms
        or evaluation_time_ms < attestation.issued_at_ms
    ):
        return WorldSnapshotTrustStatus.ATTESTATION_NOT_YET_VALID, "ATTESTATION_NOT_YET_VALID"
    if evaluation_time_ms > attestation.valid_until_ms:
        return WorldSnapshotTrustStatus.ATTESTATION_EXPIRED, "ATTESTATION_EXPIRED"
    if trust_policy.max_attestation_age_ms is not None:
        attestation_age_ms = evaluation_time_ms - attestation.issued_at_ms
        if attestation_age_ms > trust_policy.max_attestation_age_ms:
            return WorldSnapshotTrustStatus.ATTESTATION_EXPIRED, "ATTESTATION_AGE_EXCEEDED"
    return None


def _verification_failure(
    *,
    verification: AttestationVerificationResult,
    attestation: WorldSnapshotAttestation,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    world_snapshot_checksum: str,
) -> str | None:
    expected_verification_checksum = attestation_verification_result_checksum(
        status=verification.status,
        reason_code=verification.reason_code,
        attestation_checksum=verification.attestation_checksum,
        evidence_envelope_checksum=verification.evidence_envelope_checksum,
        world_snapshot_checksum=verification.world_snapshot_checksum,
        verifier_id=verification.verifier_id,
    )
    if verification.verification_checksum != expected_verification_checksum:
        return "ATTESTATION_VERIFICATION_CHECKSUM_MISMATCH"
    if verification.status != "PASS":
        return verification.reason_code
    if verification.attestation_checksum != attestation.checksum:
        return "ATTESTATION_VERIFICATION_ATTESTATION_MISMATCH"
    if verification.evidence_envelope_checksum != evidence_envelope.checksum:
        return "ATTESTATION_VERIFICATION_ENVELOPE_MISMATCH"
    if verification.world_snapshot_checksum != world_snapshot_checksum:
        return "ATTESTATION_VERIFICATION_SNAPSHOT_MISMATCH"
    return None


def _trust_policy_allowlist_status(
    *,
    trust_policy: WorldSnapshotTrustPolicy,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    capability: str,
) -> tuple[WorldSnapshotTrustStatus, str] | None:
    if evidence_envelope.source_id not in trust_policy.allowed_source_ids:
        return WorldSnapshotTrustStatus.SOURCE_NOT_ALLOWED, "WORLD_SNAPSHOT_SOURCE_NOT_ALLOWED"
    if evidence_envelope.source_type not in trust_policy.allowed_source_types:
        return (
            WorldSnapshotTrustStatus.SOURCE_TYPE_NOT_ALLOWED,
            "WORLD_SNAPSHOT_SOURCE_TYPE_NOT_ALLOWED",
        )
    if evidence_envelope.source_type is WorldSnapshotSourceType.UNKNOWN:
        return WorldSnapshotTrustStatus.SOURCE_TYPE_NOT_ALLOWED, "WORLD_SNAPSHOT_SOURCE_UNKNOWN"
    if evidence_envelope.trust_domain not in trust_policy.allowed_trust_domains:
        return (
            WorldSnapshotTrustStatus.TRUST_DOMAIN_NOT_ALLOWED,
            "WORLD_SNAPSHOT_TRUST_DOMAIN_NOT_ALLOWED",
        )
    if capability not in trust_policy.allowed_capabilities:
        return (
            WorldSnapshotTrustStatus.CAPABILITY_NOT_ALLOWED,
            "WORLD_SNAPSHOT_CAPABILITY_NOT_ALLOWED",
        )
    test_like_sources = {
        WorldSnapshotSourceType.TEST_FIXTURE,
        WorldSnapshotSourceType.STATIC_SCENE,
    }
    if (
        trust_policy.reject_test_sources_for_physical_runtime
        and evidence_envelope.trust_domain is TrustDomain.PHYSICAL_RUNTIME
        and evidence_envelope.source_type in test_like_sources
    ):
        return (
            WorldSnapshotTrustStatus.SOURCE_TYPE_NOT_ALLOWED,
            "WORLD_SNAPSHOT_TEST_SOURCE_FOR_PHYSICAL_RUNTIME",
        )
    return None


def _trust_result(
    *,
    status: WorldSnapshotTrustStatus,
    reason_code: str,
    world_snapshot_checksum: str,
    admissibility_result: WorldSnapshotAdmissibilityResult,
    trust_policy_checksum: str,
    capability: str,
    evaluation_time_ms: int,
    verifier_certification: VerifierAdapterCertificationResult | None = None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None = None,
) -> WorldSnapshotTrustResult:
    certification_checksum, config_checksum, verifier_id, verifier_metadata_checksum = (
        _trust_authority_bindings(verifier_certification, trust_policy_config_validation)
    )
    return WorldSnapshotTrustResult(
        status=status,
        reason_code=reason_code,
        world_snapshot_checksum=world_snapshot_checksum,
        world_snapshot_admissibility_status=admissibility_result.status.value,
        world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
        world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
        evidence_envelope_checksum=None,
        attestation_checksum=None,
        trust_policy_checksum=trust_policy_checksum,
        verifier_certification_checksum=certification_checksum,
        trust_policy_config_validation_checksum=config_checksum,
        verifier_id=verifier_id,
        verifier_metadata_checksum=verifier_metadata_checksum,
        source_id=None,
        source_type=None,
        trust_domain=None,
        capability=capability,
        verification_result_checksum=None,
        evaluation_time_ms=evaluation_time_ms,
    )


def _envelope_result(
    *,
    status: WorldSnapshotTrustStatus,
    reason_code: str,
    world_snapshot_checksum: str,
    admissibility_result: WorldSnapshotAdmissibilityResult,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    trust_policy: WorldSnapshotTrustPolicy,
    capability: str,
    evaluation_time_ms: int,
    verifier_certification: VerifierAdapterCertificationResult | None = None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None = None,
) -> WorldSnapshotTrustResult:
    certification_checksum, config_checksum, verifier_id, verifier_metadata_checksum = (
        _trust_authority_bindings(verifier_certification, trust_policy_config_validation)
    )
    return WorldSnapshotTrustResult(
        status=status,
        reason_code=reason_code,
        world_snapshot_checksum=world_snapshot_checksum,
        world_snapshot_admissibility_status=admissibility_result.status.value,
        world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
        world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
        evidence_envelope_checksum=evidence_envelope.checksum,
        attestation_checksum=(
            evidence_envelope.attestation.checksum
            if evidence_envelope.attestation is not None
            else None
        ),
        trust_policy_checksum=trust_policy.checksum,
        verifier_certification_checksum=certification_checksum,
        trust_policy_config_validation_checksum=config_checksum,
        verifier_id=verifier_id,
        verifier_metadata_checksum=verifier_metadata_checksum,
        source_id=evidence_envelope.source_id,
        source_type=evidence_envelope.source_type,
        trust_domain=evidence_envelope.trust_domain,
        capability=capability,
        verification_result_checksum=None,
        evaluation_time_ms=evaluation_time_ms,
    )


def _world_snapshot_checksum_or_empty(snapshot: WorldSnapshotStub | None) -> str:
    if snapshot is None or snapshot.checksum is None:
        return ""
    return snapshot.checksum


def _evidence_envelope_checksum_violation(
    envelope: WorldSnapshotEvidenceEnvelope,
) -> str | None:
    expected = world_snapshot_evidence_envelope_checksum(
        envelope_id=envelope.envelope_id,
        world_snapshot_checksum=envelope.world_snapshot_checksum,
        source_id=envelope.source_id,
        source_type=envelope.source_type,
        trust_domain=envelope.trust_domain,
        issued_at_ms=envelope.issued_at_ms,
        evidence_nonce=envelope.evidence_nonce,
        attestation_checksum=(envelope.attestation.checksum if envelope.attestation else None),
        metadata=envelope.metadata,
    )
    if envelope.checksum != expected:
        return "EVIDENCE_ENVELOPE_CHECKSUM_MISMATCH"
    return None


def _attestation_checksum_violation(attestation: WorldSnapshotAttestation) -> str | None:
    expected = world_snapshot_attestation_checksum(
        attestation_id=attestation.attestation_id,
        subject_snapshot_checksum=attestation.subject_snapshot_checksum,
        subject_envelope_id=attestation.subject_envelope_id,
        source_id=attestation.source_id,
        trust_domain=attestation.trust_domain,
        issued_at_ms=attestation.issued_at_ms,
        valid_from_ms=attestation.valid_from_ms,
        valid_until_ms=attestation.valid_until_ms,
        algorithm=attestation.algorithm,
        key_id=attestation.key_id,
        signature=attestation.signature,
        signed_payload_checksum=attestation.signed_payload_checksum,
        metadata=attestation.metadata,
    )
    if attestation.checksum != expected:
        return "ATTESTATION_CHECKSUM_MISMATCH"
    return None


def _validate_trusted_result_fields(
    *,
    world_snapshot_checksum: str,
    world_snapshot_admissibility_status: str | None,
    world_snapshot_admissibility_result_checksum: str | None,
    trust_policy_checksum: str,
    reason_code: str,
    evidence_envelope_checksum: str | None,
    attestation_checksum: str | None,
    verifier_certification_checksum: str | None,
    trust_policy_config_validation_checksum: str | None,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    source_id: str | None,
    source_type: WorldSnapshotSourceType | None,
    trust_domain: TrustDomain | None,
    capability: str | None,
    verification_result_checksum: str | None,
) -> None:
    del reason_code, attestation_checksum, verification_result_checksum
    if world_snapshot_checksum == "":
        raise ValueError("TRUSTED requires world_snapshot_checksum")
    if trust_policy_checksum == "":
        raise ValueError("TRUSTED requires trust_policy_checksum")
    if evidence_envelope_checksum is None:
        raise ValueError("TRUSTED requires evidence_envelope_checksum")
    if verifier_certification_checksum is None:
        raise ValueError("TRUSTED requires verifier_certification_checksum")
    if trust_policy_config_validation_checksum is None:
        raise ValueError("TRUSTED requires trust_policy_config_validation_checksum")
    if verifier_id is None:
        raise ValueError("TRUSTED requires verifier_id")
    if verifier_metadata_checksum is None:
        raise ValueError("TRUSTED requires verifier_metadata_checksum")
    if source_id is None:
        raise ValueError("TRUSTED requires source_id")
    if source_type is None or source_type is WorldSnapshotSourceType.UNKNOWN:
        raise ValueError("TRUSTED requires known source_type")
    if trust_domain is None:
        raise ValueError("TRUSTED requires trust_domain")
    if capability is None:
        raise ValueError("TRUSTED requires capability")
    if world_snapshot_admissibility_status != WorldSnapshotAdmissibilityStatus.ADMISSIBLE.value:
        raise ValueError("TRUSTED requires admissible world_snapshot_admissibility_status")
    if world_snapshot_admissibility_result_checksum is None:
        raise ValueError("TRUSTED requires world_snapshot_admissibility_result_checksum")


def _is_certified_verifier(
    result: VerifierAdapterCertificationResult | None,
) -> TypeGuard[VerifierAdapterCertificationResult]:
    if result is None:
        return False
    return getattr(result.status, "value", None) == "CERTIFIED"


def _is_valid_trust_policy_config(
    result: TrustPolicyConfigValidationResult | None,
) -> TypeGuard[TrustPolicyConfigValidationResult]:
    if result is None:
        return False
    return getattr(result.status, "value", None) == "VALID"


def _trust_authority_bindings(
    verifier_certification: VerifierAdapterCertificationResult | None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    certification_checksum = (
        verifier_certification.checksum if verifier_certification is not None else None
    )
    config_checksum = (
        trust_policy_config_validation.checksum
        if trust_policy_config_validation is not None
        else None
    )
    verifier_id = verifier_certification.verifier_id if verifier_certification is not None else None
    verifier_metadata_checksum = (
        verifier_certification.verifier_metadata_checksum
        if verifier_certification is not None
        else None
    )
    return certification_checksum, config_checksum, verifier_id, verifier_metadata_checksum


def _normalize_trust_status(value: WorldSnapshotTrustStatus) -> WorldSnapshotTrustStatus:
    if not isinstance(value, WorldSnapshotTrustStatus):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("status must be a WorldSnapshotTrustStatus")
    return value


def _normalize_source_type(value: WorldSnapshotSourceType) -> WorldSnapshotSourceType:
    if not isinstance(value, WorldSnapshotSourceType):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("source_type must be a WorldSnapshotSourceType")
    return value


def _normalize_trust_domain(value: TrustDomain) -> TrustDomain:
    if not isinstance(value, TrustDomain):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("trust_domain must be a TrustDomain")
    return value


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_optional_non_negative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _normalize_non_negative_int(value, field_name)


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


def _normalize_optional_admissibility_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = _normalize_required_text(value, "world_snapshot_admissibility_status")
    allowed_values = {status.value for status in WorldSnapshotAdmissibilityStatus}
    if normalized not in allowed_values:
        raise ValueError("world_snapshot_admissibility_status must be a known status")
    return normalized


def _normalize_result_checksum(
    value: str,
    field_name: str,
    status: WorldSnapshotTrustStatus,
) -> str:
    if status is WorldSnapshotTrustStatus.TRUSTED:
        return _normalize_required_text(value, field_name)
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(f"{field_name} must be a string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return value


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


def _canonicalise(value: object) -> CanonicalTrustValue:
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
    if isinstance(value, MappingProxyType):
        return _canonical_mapping(cast(Mapping[object, object], value))
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[object, object], value))
    if isinstance(value, tuple):
        tuple_value = cast(tuple[object, ...], value)
        return [_canonicalise(item) for item in tuple_value]
    if isinstance(value, list):
        list_value = cast(list[object], value)
        return [_canonicalise(item) for item in list_value]
    if isinstance(value, frozenset):
        set_value = cast(frozenset[object], value)
        return sorted((_canonicalise(item) for item in set_value), key=_canonical_sort_key)
    raise ValueError("trust values must be JSON-compatible frozen values")


def _canonical_mapping(values: Mapping[object, object]) -> dict[str, CanonicalTrustValue]:
    canonical: dict[str, CanonicalTrustValue] = {}
    for key, value in values.items():
        if not isinstance(key, str):
            raise ValueError("trust mapping keys must be strings")
        canonical[key] = _canonicalise(value)
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sort_key(value: CanonicalTrustValue) -> str:
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
    "AttestationVerificationResult",
    "AttestationVerifier",
    "TrustDomain",
    "WorldSnapshotAttestation",
    "WorldSnapshotEvidenceEnvelope",
    "WorldSnapshotSourceType",
    "WorldSnapshotTrustError",
    "WorldSnapshotTrustPolicy",
    "WorldSnapshotTrustResult",
    "WorldSnapshotTrustStatus",
    "assert_world_snapshot_trust_integrity",
    "attestation_verification_result_checksum",
    "evaluate_world_snapshot_trust",
    "is_trust_backed_admission",
    "world_snapshot_attestation_checksum",
    "world_snapshot_attestation_payload_checksum",
    "world_snapshot_evidence_envelope_checksum",
    "world_snapshot_trust_policy_checksum",
    "world_snapshot_trust_result_checksum",
]
