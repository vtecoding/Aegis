"""Contract tests for deterministic attestation verifier adapter certification."""

from __future__ import annotations

from tests.policy_trust_fixtures import (
    TRUST_KEY_ID,
    TRUST_VERIFIER_ID,
    TRUST_VERIFIER_METADATA,
    PassingAttestationVerifier,
)

from aegis.contracts.attestation_verifier import (
    AttestationVerifierAdapterMetadata,
    VerifierCertificationStatus,
    build_attestation_verifier_test_vectors,
    certify_attestation_verifier_adapter,
)
from aegis.contracts.world_snapshot_trust import (
    AttestationVerificationResult,
    TrustDomain,
    WorldSnapshotAttestation,
    WorldSnapshotEvidenceEnvelope,
)


class AlwaysPassingVerifier:
    """Verifier that incorrectly accepts every vector."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return metadata declaring fixture support."""
        return TRUST_VERIFIER_METADATA

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        """Return a PASS verdict for every input."""
        return AttestationVerificationResult(
            status="PASS",
            reason_code="FIXTURE_VERIFIED",
            attestation_checksum=attestation.checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            world_snapshot_checksum=world_snapshot_checksum,
            verifier_id=TRUST_VERIFIER_ID,
        )


def test_passing_fixture_verifier_certifies_against_required_vectors() -> None:
    result = certify_attestation_verifier_adapter(
        PassingAttestationVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
    )

    assert result.status is VerifierCertificationStatus.CERTIFIED
    assert result.reason_code == "ATTESTATION_VERIFIER_CERTIFIED"
    assert result.verifier_id == TRUST_VERIFIER_ID
    assert result.verifier_metadata_checksum == TRUST_VERIFIER_METADATA.checksum
    assert result.passed_vector_ids == frozenset({"valid_positive"})
    assert result.rejected_vector_ids == frozenset(
        vector.vector_id
        for vector in build_attestation_verifier_test_vectors()
        if vector.expected_status == "FAIL"
    )


def test_missing_verifier_fails_closed() -> None:
    result = certify_attestation_verifier_adapter(
        None,
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
    )

    assert result.status is VerifierCertificationStatus.MISSING_VERIFIER
    assert result.reason_code == "ATTESTATION_VERIFIER_MISSING"
    assert result.verifier_id is None


def test_accepting_negative_vector_rejects_certification() -> None:
    result = certify_attestation_verifier_adapter(
        AlwaysPassingVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
    )

    assert result.status is VerifierCertificationStatus.WRONG_SNAPSHOT_ACCEPTED
    assert result.failed_vector_ids == frozenset({"wrong_snapshot"})


def test_metadata_declares_non_empty_identity_algorithm_and_keys() -> None:
    metadata = AttestationVerifierAdapterMetadata(
        verifier_id="metadata-verifier",
        verifier_version="v1",
        supported_algorithms={"fixture-sha256"},
        supported_key_ids={TRUST_KEY_ID},
    )

    assert metadata.verifier_id == "metadata-verifier"
    assert metadata.supported_key_ids == frozenset({TRUST_KEY_ID})
    assert metadata.checksum != ""
