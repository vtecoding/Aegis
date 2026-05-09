"""Shared deterministic trust fixtures for world snapshot admission tests."""

from __future__ import annotations

from tests.policy_freshness_fixtures import FRESH_EVALUATION_TIME_MS, fresh_world_snapshot_result

from aegis.contracts.attestation_verifier import (
    AttestationVerifierAdapterMetadata,
    certify_attestation_verifier_adapter,
)
from aegis.contracts.policy import PolicyEvaluationResult, WorldSnapshotStub
from aegis.contracts.trust_policy_config import validate_trust_policy_config
from aegis.contracts.world_snapshot_trust import (
    AttestationVerificationResult,
    TrustDomain,
    WorldSnapshotAttestation,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotSourceType,
    WorldSnapshotTrustPolicy,
    WorldSnapshotTrustResult,
    evaluate_world_snapshot_trust,
    world_snapshot_attestation_payload_checksum,
)
from aegis.governance.context_authority import ContextAuthority

TRUST_CAPABILITY = "locomotion.translation"
TRUST_SOURCE_ID = "trusted-simulator"
TRUST_POLICY_ID = "world-snapshot-trust-policy"
TRUST_ALGORITHM = "fixture-sha256"
TRUST_KEY_ID = "fixture-key"
TRUST_VERIFIER_ID = "fixture-verifier"
TRUST_ENVELOPE_ID = "world-snapshot-evidence-envelope"
TRUST_NONCE = "world-snapshot-evidence-nonce"

TRUST_VERIFIER_METADATA = AttestationVerifierAdapterMetadata(
    verifier_id=TRUST_VERIFIER_ID,
    verifier_version="fixture-v1",
    supported_algorithms={TRUST_ALGORITHM},
    supported_key_ids={TRUST_KEY_ID},
    adapter_kind="strict-fixture",
    unsafe_test_only=False,
)


class PassingAttestationVerifier:
    """Deterministic verifier that accepts matching fixture attestations."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return immutable verifier adapter metadata."""
        return TRUST_VERIFIER_METADATA

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        failure_reason = _fixture_verification_failure_reason(
            attestation=attestation,
            evidence_envelope=evidence_envelope,
            world_snapshot_checksum=world_snapshot_checksum,
        )
        return AttestationVerificationResult(
            status="PASS" if failure_reason is None else "FAIL",
            reason_code="FIXTURE_VERIFIED" if failure_reason is None else failure_reason,
            attestation_checksum=attestation.checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            world_snapshot_checksum=world_snapshot_checksum,
            verifier_id=TRUST_VERIFIER_ID,
        )


class FailingAttestationVerifier:
    """Deterministic verifier that rejects fixture attestations."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return immutable verifier adapter metadata."""
        return TRUST_VERIFIER_METADATA

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        return AttestationVerificationResult(
            status="FAIL",
            reason_code="FIXTURE_REJECTED",
            attestation_checksum=attestation.checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            world_snapshot_checksum=world_snapshot_checksum,
            verifier_id=TRUST_VERIFIER_ID,
        )


def _fixture_verification_failure_reason(
    *,
    attestation: WorldSnapshotAttestation,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    world_snapshot_checksum: str,
) -> str | None:
    if evidence_envelope.world_snapshot_checksum != world_snapshot_checksum:
        return "FIXTURE_SNAPSHOT_MISMATCH"
    if attestation.subject_snapshot_checksum != world_snapshot_checksum:
        return "FIXTURE_SNAPSHOT_MISMATCH"
    if evidence_envelope.metadata and (
        evidence_envelope.metadata.get("trusted") is True
        or evidence_envelope.metadata.get("verifier_status") == "CERTIFIED"
    ):
        return "FIXTURE_METADATA_INERT"
    if attestation.subject_envelope_id != evidence_envelope.envelope_id:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.source_id != evidence_envelope.source_id:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.trust_domain is not evidence_envelope.trust_domain:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.algorithm not in TRUST_VERIFIER_METADATA.supported_algorithms:
        return "FIXTURE_ALGORITHM_UNSUPPORTED"
    if attestation.key_id not in TRUST_VERIFIER_METADATA.supported_key_ids:
        return "FIXTURE_KEY_UNSUPPORTED"
    if attestation.signature != "fixture-signature":
        return "FIXTURE_SIGNATURE_INVALID"
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
        return "FIXTURE_SIGNATURE_INVALID"
    return None


def trusted_attestation(
    snapshot: WorldSnapshotStub,
    *,
    envelope_id: str = TRUST_ENVELOPE_ID,
    source_id: str = TRUST_SOURCE_ID,
    trust_domain: TrustDomain = TrustDomain.SIMULATION,
    issued_at_ms: int = FRESH_EVALUATION_TIME_MS,
    valid_from_ms: int = FRESH_EVALUATION_TIME_MS,
    valid_until_ms: int = FRESH_EVALUATION_TIME_MS + 1_000,
    algorithm: str = TRUST_ALGORITHM,
    key_id: str = TRUST_KEY_ID,
) -> WorldSnapshotAttestation:
    """Return an attestation bound to the supplied snapshot checksum."""
    if snapshot.checksum is None:
        raise ValueError("trusted_attestation requires snapshot.checksum")
    payload_checksum = world_snapshot_attestation_payload_checksum(
        subject_snapshot_checksum=snapshot.checksum,
        subject_envelope_id=envelope_id,
        source_id=source_id,
        trust_domain=trust_domain,
        issued_at_ms=issued_at_ms,
        valid_from_ms=valid_from_ms,
        valid_until_ms=valid_until_ms,
        algorithm=algorithm,
        key_id=key_id,
    )
    return WorldSnapshotAttestation(
        attestation_id="world-snapshot-attestation",
        subject_snapshot_checksum=snapshot.checksum,
        subject_envelope_id=envelope_id,
        source_id=source_id,
        trust_domain=trust_domain,
        issued_at_ms=issued_at_ms,
        valid_from_ms=valid_from_ms,
        valid_until_ms=valid_until_ms,
        algorithm=algorithm,
        key_id=key_id,
        signature="fixture-signature",
        signed_payload_checksum=payload_checksum,
    )


def trusted_evidence_envelope(
    snapshot: WorldSnapshotStub,
    *,
    envelope_id: str = TRUST_ENVELOPE_ID,
    source_id: str = TRUST_SOURCE_ID,
    source_type: WorldSnapshotSourceType = WorldSnapshotSourceType.SIMULATOR,
    trust_domain: TrustDomain = TrustDomain.SIMULATION,
    attestation: WorldSnapshotAttestation | None = None,
    metadata: dict[str, object] | None = None,
) -> WorldSnapshotEvidenceEnvelope:
    """Return an evidence envelope bound to the supplied snapshot checksum."""
    if snapshot.checksum is None:
        raise ValueError("trusted_evidence_envelope requires snapshot.checksum")
    envelope_attestation = attestation or trusted_attestation(
        snapshot,
        envelope_id=envelope_id,
        source_id=source_id,
        trust_domain=trust_domain,
    )
    return WorldSnapshotEvidenceEnvelope(
        envelope_id=envelope_id,
        world_snapshot_checksum=snapshot.checksum,
        source_id=source_id,
        source_type=source_type,
        trust_domain=trust_domain,
        issued_at_ms=FRESH_EVALUATION_TIME_MS,
        evidence_nonce=TRUST_NONCE,
        attestation=envelope_attestation,
        metadata=metadata,
    )


def trusted_world_snapshot_policy(
    *,
    capability: str = TRUST_CAPABILITY,
    source_id: str = TRUST_SOURCE_ID,
    source_type: WorldSnapshotSourceType = WorldSnapshotSourceType.SIMULATOR,
    trust_domain: TrustDomain = TrustDomain.SIMULATION,
    require_attestation: bool = True,
) -> WorldSnapshotTrustPolicy:
    """Return a deterministic trust policy allowing the fixture source."""
    return WorldSnapshotTrustPolicy(
        policy_id=TRUST_POLICY_ID,
        allowed_source_ids={source_id},
        allowed_source_types={source_type},
        allowed_trust_domains={trust_domain},
        allowed_capabilities={capability},
        require_attestation=require_attestation,
        allowed_algorithms={TRUST_ALGORITHM},
        allowed_key_ids={TRUST_KEY_ID},
        max_attestation_age_ms=1_000,
    )


def trusted_world_snapshot_result(
    snapshot: WorldSnapshotStub,
    *,
    capability: str = TRUST_CAPABILITY,
    evaluation_time_ms: int = FRESH_EVALUATION_TIME_MS,
    evidence_envelope: WorldSnapshotEvidenceEnvelope | None = None,
    trust_policy: WorldSnapshotTrustPolicy | None = None,
) -> WorldSnapshotTrustResult:
    """Return the deterministic TRUSTED result for a fixture snapshot."""
    freshness_result = fresh_world_snapshot_result(
        snapshot,
        evaluation_time_ms=evaluation_time_ms,
        requested_capability=capability,
    )
    verifier = PassingAttestationVerifier()
    policy = trust_policy or trusted_world_snapshot_policy(capability=capability)
    return evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=freshness_result,
        evidence_envelope=evidence_envelope or trusted_evidence_envelope(snapshot),
        trust_policy=policy,
        capability=capability,
        evaluation_time_ms=evaluation_time_ms,
        attestation_verifier=verifier,
        verifier_certification=certify_attestation_verifier_adapter(
            verifier,
            enforce_mode=True,
            runtime_domain=TrustDomain.SIMULATION,
        ),
        trust_policy_config_validation=validate_trust_policy_config(
            policy,
            verifier_metadata=verifier.metadata,
            runtime_domain=TrustDomain.SIMULATION,
            capability=capability,
            enforce_mode=True,
        ),
    )


def trusted_pipeline_kwargs(
    snapshot: WorldSnapshotStub,
    *,
    capability: str = TRUST_CAPABILITY,
) -> dict[str, object]:
    """Return keyword arguments that satisfy run_pipeline trust enforcement."""
    return {
        "context_authority": ContextAuthority(
            context_id="trusted-test-context",
            request_id="trusted-test-request",
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            caller_authority="pytest",
            deployment_domain="SIMULATION",
            context_schema_version="context-authority-v1",
        ),
        "world_snapshot_evidence": trusted_evidence_envelope(snapshot),
        "world_snapshot_trust_policy": trusted_world_snapshot_policy(capability=capability),
        "attestation_verifier": PassingAttestationVerifier(),
    }


def bind_policy_result_to_trust(
    policy_result: PolicyEvaluationResult,
    trust_result: WorldSnapshotTrustResult,
) -> PolicyEvaluationResult:
    """Return a PolicyEvaluationResult carrying a TRUSTED evidence binding."""
    return PolicyEvaluationResult(
        policy_result.decision,
        policy_result.policy_id,
        policy_result.matched_rule_ids,
        policy_result.passed_constraints,
        policy_result.failed_constraints,
        policy_result.reasons,
        policy_version=policy_result.policy_version,
        policy_schema_version=policy_result.policy_schema_version,
        policy_checksum=policy_result.policy_checksum,
        policy_authority=policy_result.policy_authority,
        context_authority_checksum=policy_result.context_authority_checksum,
        world_snapshot_id=policy_result.world_snapshot_id,
        world_snapshot_observed_at_ms=policy_result.world_snapshot_observed_at_ms,
        freshness_result_checksum=policy_result.freshness_result_checksum,
        freshness_status=policy_result.freshness_status,
        world_snapshot_admissibility_status=trust_result.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=(
            trust_result.world_snapshot_admissibility_reason_code
        ),
        world_snapshot_admissibility_result_checksum=(
            trust_result.world_snapshot_admissibility_result_checksum
        ),
        world_snapshot_trust_status=trust_result.status.value,
        world_snapshot_trust_reason_code=trust_result.reason_code,
        world_snapshot_trust_result_checksum=trust_result.checksum,
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
        source_type=trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        trust_domain=trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
    )


__all__ = [
    "FailingAttestationVerifier",
    "PassingAttestationVerifier",
    "TRUST_ALGORITHM",
    "TRUST_CAPABILITY",
    "TRUST_ENVELOPE_ID",
    "TRUST_KEY_ID",
    "TRUST_NONCE",
    "TRUST_POLICY_ID",
    "TRUST_SOURCE_ID",
    "TRUST_VERIFIER_METADATA",
    "TRUST_VERIFIER_ID",
    "bind_policy_result_to_trust",
    "trusted_attestation",
    "trusted_evidence_envelope",
    "trusted_pipeline_kwargs",
    "trusted_world_snapshot_policy",
    "trusted_world_snapshot_result",
]
