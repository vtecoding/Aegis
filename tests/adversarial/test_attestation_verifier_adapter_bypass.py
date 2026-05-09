"""Adversarial tests for attestation verifier adapter certification bypasses."""

from __future__ import annotations

from typing import cast

from tests.policy_trust_fixtures import (
    TRUST_ALGORITHM,
    TRUST_KEY_ID,
    TRUST_VERIFIER_ID,
    PassingAttestationVerifier,
)

from aegis.contracts.attestation_verifier import (
    AttestationVerifierAdapter,
    AttestationVerifierAdapterMetadata,
    VerifierCertificationStatus,
    certify_attestation_verifier_adapter,
)
from aegis.contracts.world_snapshot_trust import (
    AttestationVerificationResult,
    TrustDomain,
    WorldSnapshotAttestation,
    WorldSnapshotEvidenceEnvelope,
)


class UnsafePhysicalRuntimeVerifier(PassingAttestationVerifier):
    """Verifier with metadata declaring it unsafe for physical enforcement."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return unsafe metadata using the otherwise valid fixture identity."""
        return AttestationVerifierAdapterMetadata(
            verifier_id=TRUST_VERIFIER_ID,
            verifier_version="fixture-v1",
            supported_algorithms={TRUST_ALGORITHM},
            supported_key_ids={TRUST_KEY_ID},
            adapter_kind="strict-fixture",
            unsafe_test_only=True,
        )


class MalformedReturnVerifier(PassingAttestationVerifier):
    """Verifier that returns a non-contract object."""

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        """Return a malformed value through an explicit cast for adversarial coverage."""
        del attestation, evidence_envelope, world_snapshot_checksum
        return cast(AttestationVerificationResult, "PASS")


class NoMetadataVerifier:
    """Object with a verify method but no metadata authority."""

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        """Return a superficially valid result without certifiable metadata."""
        return AttestationVerificationResult(
            status="PASS",
            reason_code="FIXTURE_VERIFIED",
            attestation_checksum=attestation.checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            world_snapshot_checksum=world_snapshot_checksum,
            verifier_id=TRUST_VERIFIER_ID,
        )


def test_unsafe_test_only_verifier_is_rejected_for_physical_enforce() -> None:
    result = certify_attestation_verifier_adapter(
        UnsafePhysicalRuntimeVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.PHYSICAL_RUNTIME,
    )

    assert result.status is VerifierCertificationStatus.UNSAFE_FOR_ENFORCE
    assert result.reason_code == "VERIFIER_UNSAFE_FOR_ENFORCE"


def test_malformed_verifier_result_fails_certification() -> None:
    result = certify_attestation_verifier_adapter(
        MalformedReturnVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
    )

    assert result.status is VerifierCertificationStatus.MALFORMED_RESULT


def test_arbitrary_object_without_metadata_cannot_certify() -> None:
    verifier = cast(AttestationVerifierAdapter, NoMetadataVerifier())

    result = certify_attestation_verifier_adapter(
        verifier,
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
    )

    assert result.status is VerifierCertificationStatus.UNSUPPORTED_ADAPTER_TYPE
    assert result.reason_code == "ATTESTATION_VERIFIER_METADATA_UNSUPPORTED"
