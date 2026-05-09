"""Deterministic attestation verifier adapter certification contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, Protocol, cast

from aegis.contracts.json_types import JsonValue
from aegis.contracts.world_snapshot_trust import (
    AttestationVerificationResult,
    TrustDomain,
    WorldSnapshotAttestation,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotSourceType,
    world_snapshot_attestation_payload_checksum,
)

CURRENT_VERIFIER_CONTRACT_VERSION = "aegis-attestation-verifier-v1"
DEFAULT_CERTIFICATION_REPLAY_COUNT = 2

_CERTIFICATION_SNAPSHOT_CHECKSUM = "fixture-certification-snapshot-checksum"
_CERTIFICATION_ALT_SNAPSHOT_CHECKSUM = "fixture-certification-alt-snapshot-checksum"
_CERTIFICATION_SOURCE_ID = "trusted-simulator"
_CERTIFICATION_ENVELOPE_ID = "world-snapshot-evidence-envelope"
_CERTIFICATION_WRONG_ENVELOPE_ID = "wrong-world-snapshot-evidence-envelope"
_CERTIFICATION_NONCE = "world-snapshot-evidence-nonce"
_CERTIFICATION_ALGORITHM = "fixture-sha256"
_CERTIFICATION_KEY_ID = "fixture-key"
_CERTIFICATION_WRONG_KEY_ID = "wrong-fixture-key"
_CERTIFICATION_UNSUPPORTED_ALGORITHM = "none"
_CERTIFICATION_SIGNATURE = "fixture-signature"
_CERTIFICATION_TAMPERED_SIGNATURE = "tampered-fixture-signature"
_CERTIFICATION_ISSUED_AT_MS = 1_000
_CERTIFICATION_VALID_FROM_MS = 1_000
_CERTIFICATION_VALID_UNTIL_MS = 2_000

type CanonicalVerifierValue = (
    str
    | int
    | float
    | bool
    | None
    | list[CanonicalVerifierValue]
    | dict[str, CanonicalVerifierValue]
)


class VerifierCertificationStatus(StrEnum):
    """Certification status for attestation verifier adapters."""

    CERTIFIED = "CERTIFIED"
    MISSING_VERIFIER = "MISSING_VERIFIER"
    UNSUPPORTED_ADAPTER_TYPE = "UNSUPPORTED_ADAPTER_TYPE"
    MISSING_VERIFIER_ID = "MISSING_VERIFIER_ID"
    MISSING_DECLARED_ALGORITHMS = "MISSING_DECLARED_ALGORITHMS"
    MISSING_DECLARED_KEY_IDS = "MISSING_DECLARED_KEY_IDS"
    POSITIVE_VECTOR_FAILED = "POSITIVE_VECTOR_FAILED"
    NEGATIVE_VECTOR_ACCEPTED = "NEGATIVE_VECTOR_ACCEPTED"
    WRONG_SNAPSHOT_ACCEPTED = "WRONG_SNAPSHOT_ACCEPTED"
    WRONG_ENVELOPE_ACCEPTED = "WRONG_ENVELOPE_ACCEPTED"
    WRONG_KEY_ACCEPTED = "WRONG_KEY_ACCEPTED"
    UNSUPPORTED_ALGORITHM_ACCEPTED = "UNSUPPORTED_ALGORITHM_ACCEPTED"
    NON_DETERMINISTIC_RESULT = "NON_DETERMINISTIC_RESULT"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    CHECKSUM_BINDING_MISSING = "CHECKSUM_BINDING_MISSING"
    UNSAFE_FOR_ENFORCE = "UNSAFE_FOR_ENFORCE"


class AttestationVerifierAdapter(Protocol):
    """Metadata-bearing deterministic attestation verifier adapter protocol."""

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
class AttestationVerifierAdapterMetadata:
    """Immutable identity and capability declaration for a verifier adapter."""

    verifier_id: str
    verifier_version: str
    supported_algorithms: frozenset[str]
    supported_key_ids: frozenset[str]
    deterministic_contract_version: str
    adapter_kind: str
    unsafe_test_only: bool
    checksum: str

    def __init__(
        self,
        *,
        verifier_id: str,
        verifier_version: str,
        supported_algorithms: Iterable[str],
        supported_key_ids: Iterable[str],
        deterministic_contract_version: str = CURRENT_VERIFIER_CONTRACT_VERSION,
        adapter_kind: str = "fixture",
        unsafe_test_only: object = False,
        checksum: str | None = None,
    ) -> None:
        if not isinstance(unsafe_test_only, bool):
            raise ValueError("unsafe_test_only must be a bool")
        normalized_algorithms = _normalize_text_frozenset(
            supported_algorithms, "supported_algorithms"
        )
        normalized_key_ids = _normalize_text_frozenset(supported_key_ids, "supported_key_ids")
        computed_checksum = attestation_verifier_adapter_metadata_checksum(
            verifier_id=_normalize_required_text(verifier_id, "verifier_id"),
            verifier_version=_normalize_required_text(verifier_version, "verifier_version"),
            supported_algorithms=normalized_algorithms,
            supported_key_ids=normalized_key_ids,
            deterministic_contract_version=_normalize_required_text(
                deterministic_contract_version, "deterministic_contract_version"
            ),
            adapter_kind=_normalize_required_text(adapter_kind, "adapter_kind"),
            unsafe_test_only=unsafe_test_only,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(
            self, "verifier_id", _normalize_required_text(verifier_id, "verifier_id")
        )
        object.__setattr__(
            self, "verifier_version", _normalize_required_text(verifier_version, "verifier_version")
        )
        object.__setattr__(self, "supported_algorithms", normalized_algorithms)
        object.__setattr__(self, "supported_key_ids", normalized_key_ids)
        object.__setattr__(
            self,
            "deterministic_contract_version",
            _normalize_required_text(
                deterministic_contract_version, "deterministic_contract_version"
            ),
        )
        object.__setattr__(
            self, "adapter_kind", _normalize_required_text(adapter_kind, "adapter_kind")
        )
        object.__setattr__(self, "unsafe_test_only", unsafe_test_only)
        object.__setattr__(self, "checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class AttestationVerifierTestVector:
    """Deterministic behavioural vector used to certify verifier adapters."""

    vector_id: str
    description: str
    world_snapshot_checksum: str
    evidence_envelope: WorldSnapshotEvidenceEnvelope
    attestation: WorldSnapshotAttestation
    expected_status: Literal["PASS", "FAIL"]
    expected_reason_code: str
    checksum: str

    def __init__(
        self,
        *,
        vector_id: str,
        description: str,
        world_snapshot_checksum: str,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        attestation: WorldSnapshotAttestation,
        expected_status: Literal["PASS", "FAIL"],
        expected_reason_code: str,
        checksum: str | None = None,
    ) -> None:
        if expected_status not in {"PASS", "FAIL"}:
            raise ValueError("expected_status must be PASS or FAIL")
        normalized_vector_id = _normalize_required_text(vector_id, "vector_id")
        normalized_description = _normalize_required_text(description, "description")
        normalized_snapshot_checksum = _normalize_required_text(
            world_snapshot_checksum, "world_snapshot_checksum"
        )
        normalized_reason = _normalize_reason_code(expected_reason_code, "expected_reason_code")
        computed_checksum = attestation_verifier_test_vector_checksum(
            vector_id=normalized_vector_id,
            description=normalized_description,
            world_snapshot_checksum=normalized_snapshot_checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            attestation_checksum=attestation.checksum,
            expected_status=expected_status,
            expected_reason_code=normalized_reason,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "vector_id", normalized_vector_id)
        object.__setattr__(self, "description", normalized_description)
        object.__setattr__(self, "world_snapshot_checksum", normalized_snapshot_checksum)
        object.__setattr__(self, "evidence_envelope", evidence_envelope)
        object.__setattr__(self, "attestation", attestation)
        object.__setattr__(self, "expected_status", expected_status)
        object.__setattr__(self, "expected_reason_code", normalized_reason)
        object.__setattr__(self, "checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class VerifierAdapterCertificationResult:
    """Deterministic result of verifier adapter certification."""

    status: VerifierCertificationStatus
    reason_code: str
    verifier_id: str | None
    verifier_metadata_checksum: str | None
    passed_vector_ids: frozenset[str]
    failed_vector_ids: frozenset[str]
    rejected_vector_ids: frozenset[str]
    deterministic_replay_count: int
    contract_version: str
    checksum: str

    def __init__(
        self,
        *,
        status: VerifierCertificationStatus,
        reason_code: str,
        verifier_id: str | None,
        verifier_metadata_checksum: str | None,
        passed_vector_ids: Iterable[str],
        failed_vector_ids: Iterable[str],
        rejected_vector_ids: Iterable[str],
        deterministic_replay_count: object,
        contract_version: str = CURRENT_VERIFIER_CONTRACT_VERSION,
        checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_certification_status(status)
        normalized_reason = _normalize_reason_code(reason_code, "reason_code")
        normalized_verifier_id = _normalize_optional_text(verifier_id, "verifier_id")
        normalized_metadata_checksum = _normalize_optional_text(
            verifier_metadata_checksum, "verifier_metadata_checksum"
        )
        normalized_passed = _normalize_text_frozenset_allow_empty(
            passed_vector_ids, "passed_vector_ids"
        )
        normalized_failed = _normalize_text_frozenset_allow_empty(
            failed_vector_ids, "failed_vector_ids"
        )
        normalized_rejected = _normalize_text_frozenset_allow_empty(
            rejected_vector_ids, "rejected_vector_ids"
        )
        normalized_replay_count = _normalize_positive_int(
            deterministic_replay_count, "deterministic_replay_count"
        )
        normalized_contract_version = _normalize_required_text(contract_version, "contract_version")
        if normalized_status is VerifierCertificationStatus.CERTIFIED:
            _validate_certified_result_fields(
                verifier_id=normalized_verifier_id,
                verifier_metadata_checksum=normalized_metadata_checksum,
                passed_vector_ids=normalized_passed,
                failed_vector_ids=normalized_failed,
                rejected_vector_ids=normalized_rejected,
            )
        computed_checksum = verifier_adapter_certification_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            verifier_id=normalized_verifier_id,
            verifier_metadata_checksum=normalized_metadata_checksum,
            passed_vector_ids=normalized_passed,
            failed_vector_ids=normalized_failed,
            rejected_vector_ids=normalized_rejected,
            deterministic_replay_count=normalized_replay_count,
            contract_version=normalized_contract_version,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "verifier_id", normalized_verifier_id)
        object.__setattr__(self, "verifier_metadata_checksum", normalized_metadata_checksum)
        object.__setattr__(self, "passed_vector_ids", normalized_passed)
        object.__setattr__(self, "failed_vector_ids", normalized_failed)
        object.__setattr__(self, "rejected_vector_ids", normalized_rejected)
        object.__setattr__(self, "deterministic_replay_count", normalized_replay_count)
        object.__setattr__(self, "contract_version", normalized_contract_version)
        object.__setattr__(self, "checksum", normalized_checksum)


def certify_attestation_verifier_adapter(
    verifier: AttestationVerifierAdapter | None,
    *,
    enforce_mode: object,
    runtime_domain: TrustDomain,
    test_vectors: Iterable[AttestationVerifierTestVector] | None = None,
    deterministic_replay_count: int = DEFAULT_CERTIFICATION_REPLAY_COUNT,
) -> VerifierAdapterCertificationResult:
    """Certify that a verifier adapter satisfies deterministic fixture vectors."""
    if not isinstance(enforce_mode, bool):
        raise ValueError("enforce_mode must be a bool")
    normalized_runtime_domain = _normalize_trust_domain(runtime_domain)
    normalized_replay_count = _normalize_positive_int(
        deterministic_replay_count, "deterministic_replay_count"
    )
    if verifier is None:
        return _certification_result(
            status=VerifierCertificationStatus.MISSING_VERIFIER,
            reason_code="ATTESTATION_VERIFIER_MISSING",
            replay_count=normalized_replay_count,
        )

    metadata = _metadata_or_none(verifier)
    if metadata is None:
        return _certification_result(
            status=VerifierCertificationStatus.UNSUPPORTED_ADAPTER_TYPE,
            reason_code="ATTESTATION_VERIFIER_METADATA_UNSUPPORTED",
            replay_count=normalized_replay_count,
        )
    metadata_status = _metadata_failure_status(metadata, enforce_mode, normalized_runtime_domain)
    if metadata_status is not None:
        status, reason_code = metadata_status
        return _certification_result(
            status=status,
            reason_code=reason_code,
            verifier_id=metadata.verifier_id,
            verifier_metadata_checksum=metadata.checksum,
            replay_count=normalized_replay_count,
        )

    passed_vector_ids: set[str] = set()
    failed_vector_ids: set[str] = set()
    rejected_vector_ids: set[str] = set()
    for vector in tuple(test_vectors or build_attestation_verifier_test_vectors()):
        verification, vector_failure = _stable_vector_result(
            verifier=verifier,
            metadata=metadata,
            vector=vector,
            replay_count=normalized_replay_count,
        )
        if vector_failure is not None:
            failed_vector_ids.add(vector.vector_id)
            return _certification_result(
                status=vector_failure,
                reason_code=_certification_reason(vector_failure),
                verifier_id=metadata.verifier_id,
                verifier_metadata_checksum=metadata.checksum,
                passed_vector_ids=passed_vector_ids,
                failed_vector_ids=failed_vector_ids,
                rejected_vector_ids=rejected_vector_ids,
                replay_count=normalized_replay_count,
            )
        assert verification is not None
        vector_binding_failure = _vector_binding_failure(verification, vector)
        if vector_binding_failure is not None:
            failed_vector_ids.add(vector.vector_id)
            return _certification_result(
                status=vector_binding_failure,
                reason_code=_certification_reason(vector_binding_failure),
                verifier_id=metadata.verifier_id,
                verifier_metadata_checksum=metadata.checksum,
                passed_vector_ids=passed_vector_ids,
                failed_vector_ids=failed_vector_ids,
                rejected_vector_ids=rejected_vector_ids,
                replay_count=normalized_replay_count,
            )
        if (
            vector.expected_status == "PASS"
            and verification.status == "PASS"
            and verification.reason_code == vector.expected_reason_code
        ):
            passed_vector_ids.add(vector.vector_id)
            continue
        if vector.expected_status == "PASS":
            failed_vector_ids.add(vector.vector_id)
            return _certification_result(
                status=VerifierCertificationStatus.POSITIVE_VECTOR_FAILED,
                reason_code="ATTESTATION_VERIFIER_POSITIVE_VECTOR_FAILED",
                verifier_id=metadata.verifier_id,
                verifier_metadata_checksum=metadata.checksum,
                passed_vector_ids=passed_vector_ids,
                failed_vector_ids=failed_vector_ids,
                rejected_vector_ids=rejected_vector_ids,
                replay_count=normalized_replay_count,
            )
        if (
            vector.expected_status == "FAIL"
            and verification.status == "FAIL"
            and verification.reason_code == vector.expected_reason_code
        ):
            rejected_vector_ids.add(vector.vector_id)
            continue
        if vector.expected_status == "FAIL" and verification.status == "FAIL":
            failed_vector_ids.add(vector.vector_id)
            return _certification_result(
                status=VerifierCertificationStatus.MALFORMED_RESULT,
                reason_code="ATTESTATION_VERIFIER_VECTOR_REASON_MISMATCH",
                verifier_id=metadata.verifier_id,
                verifier_metadata_checksum=metadata.checksum,
                passed_vector_ids=passed_vector_ids,
                failed_vector_ids=failed_vector_ids,
                rejected_vector_ids=rejected_vector_ids,
                replay_count=normalized_replay_count,
            )

        failed_vector_ids.add(vector.vector_id)
        status = _negative_acceptance_status(vector.vector_id)
        return _certification_result(
            status=status,
            reason_code=_certification_reason(status),
            verifier_id=metadata.verifier_id,
            verifier_metadata_checksum=metadata.checksum,
            passed_vector_ids=passed_vector_ids,
            failed_vector_ids=failed_vector_ids,
            rejected_vector_ids=rejected_vector_ids,
            replay_count=normalized_replay_count,
        )

    return _certification_result(
        status=VerifierCertificationStatus.CERTIFIED,
        reason_code="ATTESTATION_VERIFIER_CERTIFIED",
        verifier_id=metadata.verifier_id,
        verifier_metadata_checksum=metadata.checksum,
        passed_vector_ids=passed_vector_ids,
        failed_vector_ids=failed_vector_ids,
        rejected_vector_ids=rejected_vector_ids,
        replay_count=normalized_replay_count,
    )


def build_attestation_verifier_test_vectors() -> tuple[AttestationVerifierTestVector, ...]:
    """Return the deterministic certification vectors required for adapters."""
    positive_attestation = _certification_attestation()
    positive_envelope = _certification_envelope(attestation=positive_attestation)
    wrong_envelope = _certification_envelope(
        envelope_id=_CERTIFICATION_WRONG_ENVELOPE_ID,
        attestation=positive_attestation,
    )
    wrong_key_attestation = _certification_attestation(key_id=_CERTIFICATION_WRONG_KEY_ID)
    unsupported_algorithm_attestation = _certification_attestation(
        algorithm=_CERTIFICATION_UNSUPPORTED_ALGORITHM
    )
    tampered_signature_attestation = _certification_attestation(
        signature=_CERTIFICATION_TAMPERED_SIGNATURE
    )
    metadata_self_trust_attestation = _certification_attestation(
        key_id=_CERTIFICATION_WRONG_KEY_ID,
        attestation_id="metadata-self-trust-attestation",
    )
    metadata_self_trust_envelope = _certification_envelope(
        envelope_id="metadata-self-trust-envelope",
        attestation=metadata_self_trust_attestation,
        metadata={"trusted": True, "verifier_status": "CERTIFIED"},
    )
    empty_signature_vector_attestation = _certification_attestation(
        signature="empty-signature-vector",
        attestation_id="empty-signature-attestation",
    )
    return (
        AttestationVerifierTestVector(
            vector_id="valid_positive",
            description="valid fixture attestation must pass",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=positive_envelope,
            attestation=positive_attestation,
            expected_status="PASS",
            expected_reason_code="FIXTURE_VERIFIED",
        ),
        AttestationVerifierTestVector(
            vector_id="wrong_snapshot",
            description="attestation bound to a different snapshot must fail",
            world_snapshot_checksum=_CERTIFICATION_ALT_SNAPSHOT_CHECKSUM,
            evidence_envelope=positive_envelope,
            attestation=positive_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_SNAPSHOT_MISMATCH",
        ),
        AttestationVerifierTestVector(
            vector_id="wrong_envelope",
            description="attestation bound to a different envelope must fail",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=wrong_envelope,
            attestation=positive_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_ENVELOPE_MISMATCH",
        ),
        AttestationVerifierTestVector(
            vector_id="wrong_key",
            description="attestation signed by an unsupported key must fail",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=_certification_envelope(attestation=wrong_key_attestation),
            attestation=wrong_key_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_KEY_UNSUPPORTED",
        ),
        AttestationVerifierTestVector(
            vector_id="unsupported_algorithm",
            description="unsupported attestation algorithm must fail",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=_certification_envelope(
                attestation=unsupported_algorithm_attestation
            ),
            attestation=unsupported_algorithm_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_ALGORITHM_UNSUPPORTED",
        ),
        AttestationVerifierTestVector(
            vector_id="tampered_signature",
            description="tampered signature material must fail",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=_certification_envelope(attestation=tampered_signature_attestation),
            attestation=tampered_signature_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_SIGNATURE_INVALID",
        ),
        AttestationVerifierTestVector(
            vector_id="metadata_self_trust",
            description="metadata claims must not certify an invalid attestation",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=metadata_self_trust_envelope,
            attestation=metadata_self_trust_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_METADATA_INERT",
        ),
        AttestationVerifierTestVector(
            vector_id="empty_signature",
            description="signature placeholder vector must fail unless exact fixture matches",
            world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
            evidence_envelope=_certification_envelope(
                attestation=empty_signature_vector_attestation
            ),
            attestation=empty_signature_vector_attestation,
            expected_status="FAIL",
            expected_reason_code="FIXTURE_SIGNATURE_INVALID",
        ),
    )


def attestation_verifier_adapter_metadata_checksum(
    *,
    verifier_id: str,
    verifier_version: str,
    supported_algorithms: frozenset[str],
    supported_key_ids: frozenset[str],
    deterministic_contract_version: str,
    adapter_kind: str,
    unsafe_test_only: bool,
) -> str:
    """Return a deterministic checksum for verifier adapter metadata."""
    return _sha256(
        {
            "verifier_id": verifier_id,
            "verifier_version": verifier_version,
            "supported_algorithms": sorted(supported_algorithms),
            "supported_key_ids": sorted(supported_key_ids),
            "deterministic_contract_version": deterministic_contract_version,
            "adapter_kind": adapter_kind,
            "unsafe_test_only": unsafe_test_only,
        }
    )


def attestation_verifier_test_vector_checksum(
    *,
    vector_id: str,
    description: str,
    world_snapshot_checksum: str,
    evidence_envelope_checksum: str,
    attestation_checksum: str,
    expected_status: Literal["PASS", "FAIL"],
    expected_reason_code: str,
) -> str:
    """Return a deterministic checksum for a verifier certification vector."""
    return _sha256(
        {
            "vector_id": vector_id,
            "description": description,
            "world_snapshot_checksum": world_snapshot_checksum,
            "evidence_envelope_checksum": evidence_envelope_checksum,
            "attestation_checksum": attestation_checksum,
            "expected_status": expected_status,
            "expected_reason_code": expected_reason_code,
        }
    )


def verifier_adapter_certification_result_checksum(
    *,
    status: VerifierCertificationStatus,
    reason_code: str,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    passed_vector_ids: frozenset[str],
    failed_vector_ids: frozenset[str],
    rejected_vector_ids: frozenset[str],
    deterministic_replay_count: int,
    contract_version: str,
) -> str:
    """Return a deterministic checksum for verifier adapter certification."""
    return _sha256(
        {
            "status": status.value,
            "reason_code": reason_code,
            "verifier_id": verifier_id,
            "verifier_metadata_checksum": verifier_metadata_checksum,
            "passed_vector_ids": sorted(passed_vector_ids),
            "failed_vector_ids": sorted(failed_vector_ids),
            "rejected_vector_ids": sorted(rejected_vector_ids),
            "deterministic_replay_count": deterministic_replay_count,
            "contract_version": contract_version,
        }
    )


def _certification_attestation(
    *,
    attestation_id: str = "world-snapshot-attestation",
    subject_snapshot_checksum: str = _CERTIFICATION_SNAPSHOT_CHECKSUM,
    subject_envelope_id: str = _CERTIFICATION_ENVELOPE_ID,
    source_id: str = _CERTIFICATION_SOURCE_ID,
    trust_domain: TrustDomain = TrustDomain.SIMULATION,
    algorithm: str = _CERTIFICATION_ALGORITHM,
    key_id: str = _CERTIFICATION_KEY_ID,
    signature: str = _CERTIFICATION_SIGNATURE,
) -> WorldSnapshotAttestation:
    payload_checksum = world_snapshot_attestation_payload_checksum(
        subject_snapshot_checksum=subject_snapshot_checksum,
        subject_envelope_id=subject_envelope_id,
        source_id=source_id,
        trust_domain=trust_domain,
        issued_at_ms=_CERTIFICATION_ISSUED_AT_MS,
        valid_from_ms=_CERTIFICATION_VALID_FROM_MS,
        valid_until_ms=_CERTIFICATION_VALID_UNTIL_MS,
        algorithm=algorithm,
        key_id=key_id,
    )
    return WorldSnapshotAttestation(
        attestation_id=attestation_id,
        subject_snapshot_checksum=subject_snapshot_checksum,
        subject_envelope_id=subject_envelope_id,
        source_id=source_id,
        trust_domain=trust_domain,
        issued_at_ms=_CERTIFICATION_ISSUED_AT_MS,
        valid_from_ms=_CERTIFICATION_VALID_FROM_MS,
        valid_until_ms=_CERTIFICATION_VALID_UNTIL_MS,
        algorithm=algorithm,
        key_id=key_id,
        signature=signature,
        signed_payload_checksum=payload_checksum,
    )


def _certification_envelope(
    *,
    envelope_id: str = _CERTIFICATION_ENVELOPE_ID,
    attestation: WorldSnapshotAttestation,
    source_id: str = _CERTIFICATION_SOURCE_ID,
    source_type: WorldSnapshotSourceType = WorldSnapshotSourceType.SIMULATOR,
    trust_domain: TrustDomain = TrustDomain.SIMULATION,
    metadata: Mapping[str, JsonValue] | None = None,
) -> WorldSnapshotEvidenceEnvelope:
    return WorldSnapshotEvidenceEnvelope(
        envelope_id=envelope_id,
        world_snapshot_checksum=_CERTIFICATION_SNAPSHOT_CHECKSUM,
        source_id=source_id,
        source_type=source_type,
        trust_domain=trust_domain,
        issued_at_ms=_CERTIFICATION_ISSUED_AT_MS,
        evidence_nonce=_CERTIFICATION_NONCE,
        attestation=attestation,
        metadata=metadata,
    )


def _stable_vector_result(
    *,
    verifier: AttestationVerifierAdapter,
    metadata: AttestationVerifierAdapterMetadata,
    vector: AttestationVerifierTestVector,
    replay_count: int,
) -> tuple[AttestationVerificationResult | None, VerifierCertificationStatus | None]:
    results: list[AttestationVerificationResult] = []
    for _replay_index in range(replay_count):
        try:
            verification = cast(
                object,
                verifier.verify(
                    attestation=vector.attestation,
                    evidence_envelope=vector.evidence_envelope,
                    world_snapshot_checksum=vector.world_snapshot_checksum,
                ),
            )
        except Exception:  # noqa: BLE001
            return None, VerifierCertificationStatus.MALFORMED_RESULT
        if not isinstance(verification, AttestationVerificationResult):
            return None, VerifierCertificationStatus.MALFORMED_RESULT
        binding_failure = _verification_binding_failure(verification, metadata)
        if binding_failure is not None:
            return verification, binding_failure
        results.append(verification)

    first_result = results[0]
    if any(result != first_result for result in results[1:]):
        return first_result, VerifierCertificationStatus.NON_DETERMINISTIC_RESULT
    return first_result, None


def _verification_binding_failure(
    verification: AttestationVerificationResult,
    metadata: AttestationVerifierAdapterMetadata,
) -> VerifierCertificationStatus | None:
    if verification.verifier_id != metadata.verifier_id:
        return VerifierCertificationStatus.MALFORMED_RESULT
    if verification.verification_checksum == "":
        return VerifierCertificationStatus.CHECKSUM_BINDING_MISSING
    return None


def _vector_binding_failure(
    verification: AttestationVerificationResult,
    vector: AttestationVerifierTestVector,
) -> VerifierCertificationStatus | None:
    if verification.status != "PASS":
        return None
    if verification.attestation_checksum != vector.attestation.checksum:
        return VerifierCertificationStatus.CHECKSUM_BINDING_MISSING
    if verification.evidence_envelope_checksum != vector.evidence_envelope.checksum:
        return VerifierCertificationStatus.CHECKSUM_BINDING_MISSING
    if verification.world_snapshot_checksum != vector.world_snapshot_checksum:
        return VerifierCertificationStatus.CHECKSUM_BINDING_MISSING
    return None


def _metadata_or_none(
    verifier: AttestationVerifierAdapter,
) -> AttestationVerifierAdapterMetadata | None:
    try:
        metadata = cast(object, verifier.metadata)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(metadata, AttestationVerifierAdapterMetadata):
        return None
    return metadata


def _metadata_failure_status(
    metadata: AttestationVerifierAdapterMetadata,
    enforce_mode: bool,
    runtime_domain: TrustDomain,
) -> tuple[VerifierCertificationStatus, str] | None:
    if metadata.verifier_id == "":
        return VerifierCertificationStatus.MISSING_VERIFIER_ID, "ATTESTATION_VERIFIER_ID_MISSING"
    if not metadata.supported_algorithms:
        return (
            VerifierCertificationStatus.MISSING_DECLARED_ALGORITHMS,
            "ATTESTATION_VERIFIER_ALGORITHMS_MISSING",
        )
    if not metadata.supported_key_ids:
        return (
            VerifierCertificationStatus.MISSING_DECLARED_KEY_IDS,
            "ATTESTATION_VERIFIER_KEY_IDS_MISSING",
        )
    if metadata.deterministic_contract_version != CURRENT_VERIFIER_CONTRACT_VERSION:
        return VerifierCertificationStatus.UNSUPPORTED_ADAPTER_TYPE, "VERIFIER_CONTRACT_UNSUPPORTED"
    if (
        metadata.unsafe_test_only
        and enforce_mode
        and runtime_domain is TrustDomain.PHYSICAL_RUNTIME
    ):
        return VerifierCertificationStatus.UNSAFE_FOR_ENFORCE, "VERIFIER_UNSAFE_FOR_ENFORCE"
    return None


def _negative_acceptance_status(vector_id: str) -> VerifierCertificationStatus:
    if vector_id == "wrong_snapshot":
        return VerifierCertificationStatus.WRONG_SNAPSHOT_ACCEPTED
    if vector_id == "wrong_envelope":
        return VerifierCertificationStatus.WRONG_ENVELOPE_ACCEPTED
    if vector_id == "wrong_key":
        return VerifierCertificationStatus.WRONG_KEY_ACCEPTED
    if vector_id == "unsupported_algorithm":
        return VerifierCertificationStatus.UNSUPPORTED_ALGORITHM_ACCEPTED
    return VerifierCertificationStatus.NEGATIVE_VECTOR_ACCEPTED


def _certification_result(
    *,
    status: VerifierCertificationStatus,
    reason_code: str,
    replay_count: int,
    verifier_id: str | None = None,
    verifier_metadata_checksum: str | None = None,
    passed_vector_ids: Iterable[str] = (),
    failed_vector_ids: Iterable[str] = (),
    rejected_vector_ids: Iterable[str] = (),
) -> VerifierAdapterCertificationResult:
    return VerifierAdapterCertificationResult(
        status=status,
        reason_code=reason_code,
        verifier_id=verifier_id,
        verifier_metadata_checksum=verifier_metadata_checksum,
        passed_vector_ids=passed_vector_ids,
        failed_vector_ids=failed_vector_ids,
        rejected_vector_ids=rejected_vector_ids,
        deterministic_replay_count=replay_count,
    )


def _certification_reason(status: VerifierCertificationStatus) -> str:
    return f"ATTESTATION_VERIFIER_{status.value}"


def _validate_certified_result_fields(
    *,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    passed_vector_ids: frozenset[str],
    failed_vector_ids: frozenset[str],
    rejected_vector_ids: frozenset[str],
) -> None:
    if verifier_id is None:
        raise ValueError("CERTIFIED requires verifier_id")
    if verifier_metadata_checksum is None:
        raise ValueError("CERTIFIED requires verifier_metadata_checksum")
    if not passed_vector_ids:
        raise ValueError("CERTIFIED requires passed positive vectors")
    if failed_vector_ids:
        raise ValueError("CERTIFIED requires no failed vectors")
    if not rejected_vector_ids:
        raise ValueError("CERTIFIED requires rejected negative vectors")


def _normalize_certification_status(
    value: VerifierCertificationStatus,
) -> VerifierCertificationStatus:
    if not isinstance(value, VerifierCertificationStatus):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("status must be a VerifierCertificationStatus")
    return value


def _normalize_trust_domain(value: TrustDomain) -> TrustDomain:
    if not isinstance(value, TrustDomain):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("runtime_domain must be a TrustDomain")
    return value


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


def _normalize_text_frozenset(values: Iterable[str], field_name: str) -> frozenset[str]:
    normalized = _normalize_text_frozenset_allow_empty(values, field_name)
    if not normalized:
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


def _normalize_text_frozenset_allow_empty(values: Iterable[str], field_name: str) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of strings")
    return frozenset(_normalize_required_text(value, field_name) for value in values)


def _normalize_positive_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be greater than 0")
    return value


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


def _canonicalise(value: object) -> CanonicalVerifierValue:
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
    raise ValueError("verifier values must be JSON-compatible frozen values")


def _canonical_mapping(values: Mapping[object, object]) -> dict[str, CanonicalVerifierValue]:
    canonical: dict[str, CanonicalVerifierValue] = {}
    for key, value in values.items():
        if not isinstance(key, str):
            raise ValueError("verifier mapping keys must be strings")
        canonical[key] = _canonicalise(value)
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sort_key(value: CanonicalVerifierValue) -> str:
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
    "CURRENT_VERIFIER_CONTRACT_VERSION",
    "AttestationVerifierAdapter",
    "AttestationVerifierAdapterMetadata",
    "AttestationVerifierTestVector",
    "VerifierAdapterCertificationResult",
    "VerifierCertificationStatus",
    "attestation_verifier_adapter_metadata_checksum",
    "attestation_verifier_test_vector_checksum",
    "build_attestation_verifier_test_vectors",
    "certify_attestation_verifier_adapter",
    "verifier_adapter_certification_result_checksum",
]
