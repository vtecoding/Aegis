"""Contract tests for deterministic world snapshot trust evaluation."""

from __future__ import annotations

from types import MappingProxyType

import pytest
from tests.policy_freshness_fixtures import FRESH_EVALUATION_TIME_MS, fresh_world_snapshot
from tests.policy_trust_fixtures import (
    TRUST_CAPABILITY,
    TRUST_SOURCE_ID,
    FailingAttestationVerifier,
    PassingAttestationVerifier,
    trusted_attestation,
    trusted_evidence_envelope,
    trusted_world_snapshot_policy,
    trusted_world_snapshot_result,
)

from aegis.contracts.world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    validate_world_snapshot_freshness,
)
from aegis.contracts.world_snapshot_trust import (
    TrustDomain,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotSourceType,
    WorldSnapshotTrustResult,
    WorldSnapshotTrustStatus,
    evaluate_world_snapshot_trust,
)


def _freshness(snapshot):
    return validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )


def test_trusted_fixture_evaluates_to_trusted() -> None:
    snapshot = fresh_world_snapshot()
    envelope = trusted_evidence_envelope(snapshot)
    policy = trusted_world_snapshot_policy()

    result = trusted_world_snapshot_result(
        snapshot,
        evidence_envelope=envelope,
        trust_policy=policy,
    )

    assert result.status is WorldSnapshotTrustStatus.TRUSTED
    assert result.world_snapshot_checksum == snapshot.checksum
    assert result.evidence_envelope_checksum == envelope.checksum
    assert result.trust_policy_checksum == policy.checksum
    assert result.source_id == TRUST_SOURCE_ID
    assert result.source_type is WorldSnapshotSourceType.SIMULATOR
    assert result.trust_domain is TrustDomain.SIMULATION


def test_missing_evidence_and_policy_fail_closed() -> None:
    snapshot = fresh_world_snapshot()
    policy = trusted_world_snapshot_policy()

    missing_evidence = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=None,
        trust_policy=policy,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )
    missing_policy = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=trusted_evidence_envelope(snapshot),
        trust_policy=None,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )

    assert missing_evidence.status is WorldSnapshotTrustStatus.MISSING_EVIDENCE
    assert missing_policy.status is WorldSnapshotTrustStatus.MISSING_TRUST_POLICY


def test_missing_verifier_and_verifier_failure_fail_closed() -> None:
    snapshot = fresh_world_snapshot()
    envelope = trusted_evidence_envelope(snapshot)
    policy = trusted_world_snapshot_policy()

    missing_verifier = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=envelope,
        trust_policy=policy,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )
    verifier_failure = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=envelope,
        trust_policy=policy,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=FailingAttestationVerifier(),
    )

    assert missing_verifier.status is WorldSnapshotTrustStatus.MISSING_VERIFIER
    assert verifier_failure.status is WorldSnapshotTrustStatus.ATTESTATION_INVALID


def test_snapshot_checksum_source_domain_and_capability_mismatches_fail_closed() -> None:
    snapshot = fresh_world_snapshot()
    wrong_checksum = WorldSnapshotEvidenceEnvelope(
        envelope_id="wrong-checksum-envelope",
        world_snapshot_checksum="different-snapshot-checksum",
        source_id=TRUST_SOURCE_ID,
        source_type=WorldSnapshotSourceType.SIMULATOR,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=FRESH_EVALUATION_TIME_MS,
        evidence_nonce="wrong-checksum-nonce",
        attestation=None,
    )
    no_attestation_policy = trusted_world_snapshot_policy(require_attestation=False)

    checksum_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=wrong_checksum,
        trust_policy=no_attestation_policy,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )
    source_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=trusted_evidence_envelope(snapshot),
        trust_policy=trusted_world_snapshot_policy(source_id="other-source"),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )
    capability_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=trusted_evidence_envelope(snapshot),
        trust_policy=trusted_world_snapshot_policy(capability="inspection.observe"),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )

    assert checksum_result.status is WorldSnapshotTrustStatus.SNAPSHOT_CHECKSUM_MISMATCH
    assert source_result.status is WorldSnapshotTrustStatus.SOURCE_NOT_ALLOWED
    assert capability_result.status is WorldSnapshotTrustStatus.CAPABILITY_NOT_ALLOWED


def test_metadata_is_frozen_and_cannot_promote_trust() -> None:
    snapshot = fresh_world_snapshot()
    envelope = WorldSnapshotEvidenceEnvelope(
        envelope_id="metadata-envelope",
        world_snapshot_checksum=snapshot.checksum or "",
        source_id=TRUST_SOURCE_ID,
        source_type=WorldSnapshotSourceType.SIMULATOR,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=FRESH_EVALUATION_TIME_MS,
        evidence_nonce="metadata-nonce",
        attestation=None,
        metadata={"trusted": True, "nested": {"source_type": "SENSOR_BRIDGE"}},
    )

    result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=envelope,
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert isinstance(envelope.metadata, MappingProxyType)
    assert result.status is WorldSnapshotTrustStatus.ATTESTATION_MISSING


def test_attestation_validity_and_algorithm_fail_closed() -> None:
    snapshot = fresh_world_snapshot()
    future_attestation = trusted_attestation(
        snapshot,
        issued_at_ms=FRESH_EVALUATION_TIME_MS + 100,
        valid_from_ms=FRESH_EVALUATION_TIME_MS + 100,
        valid_until_ms=FRESH_EVALUATION_TIME_MS + 1_000,
    )
    future_envelope = trusted_evidence_envelope(snapshot, attestation=future_attestation)
    unsupported_algorithm = trusted_attestation(snapshot, algorithm="unsupported-fixture")
    unsupported_envelope = trusted_evidence_envelope(snapshot, attestation=unsupported_algorithm)

    future_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=future_envelope,
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )
    algorithm_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=unsupported_envelope,
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )

    assert future_result.status is WorldSnapshotTrustStatus.ATTESTATION_NOT_YET_VALID
    assert algorithm_result.status is WorldSnapshotTrustStatus.UNSUPPORTED_ATTESTATION_ALGORITHM


def test_trusted_result_rejects_missing_required_bindings() -> None:
    with pytest.raises(ValueError, match="source_id"):
        WorldSnapshotTrustResult(
            status=WorldSnapshotTrustStatus.TRUSTED,
            reason_code="WORLD_SNAPSHOT_TRUSTED",
            world_snapshot_checksum="snapshot-checksum",
            evidence_envelope_checksum="envelope-checksum",
            attestation_checksum=None,
            trust_policy_checksum="trust-policy-checksum",
            verifier_certification_checksum="verifier-certification-checksum",
            trust_policy_config_validation_checksum="trust-policy-config-validation-checksum",
            verifier_id="fixture-verifier",
            verifier_metadata_checksum="verifier-metadata-checksum",
            source_id=None,
            source_type=WorldSnapshotSourceType.SIMULATOR,
            trust_domain=TrustDomain.SIMULATION,
            capability=TRUST_CAPABILITY,
            verification_result_checksum=None,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )


def test_confusable_enum_and_reason_strings_are_rejected() -> None:
    with pytest.raises(ValueError):
        WorldSnapshotEvidenceEnvelope(
            envelope_id="bad-source-type",
            world_snapshot_checksum="snapshot-checksum",
            source_id=TRUST_SOURCE_ID,
            source_type="SIMULATOR ",
            trust_domain=TrustDomain.SIMULATION,
            issued_at_ms=FRESH_EVALUATION_TIME_MS,
            evidence_nonce="nonce",
        )
    with pytest.raises(ValueError):
        WorldSnapshotTrustResult(
            status=WorldSnapshotTrustStatus.UNTRUSTED,
            reason_code="trusted by metadata",
            world_snapshot_checksum="snapshot-checksum",
            evidence_envelope_checksum=None,
            attestation_checksum=None,
            trust_policy_checksum="trust-policy-checksum",
            source_id=None,
            source_type=None,
            trust_domain=None,
            capability=TRUST_CAPABILITY,
            verification_result_checksum=None,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )
