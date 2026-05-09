"""Adversarial tests for world snapshot trust bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import (
    TRUST_CAPABILITY,
    PassingAttestationVerifier,
    trusted_evidence_envelope,
    trusted_pipeline_kwargs,
    trusted_world_snapshot_policy,
)

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
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
from aegis.gate import gate_audited_plan
from aegis.pipeline import run_pipeline
from aegis.planning import plan_validated_intent
from aegis.validation import validate_intent


def _context(request_id: str = "trust-adversarial") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "adversary", 5, context)


def _policy() -> Policy:
    return Policy(
        "trust-adversarial-policy",
        "v1",
        [
            PolicyRule(
                "rule-1", "locomotion.translation", [Constraint("max_velocity", {"max_mps": 1.0})]
            )
        ],
    )


def _admission(snapshot) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability(TRUST_CAPABILITY, parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def _freshness(snapshot):
    return validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )


def test_fresh_snapshot_with_metadata_self_trust_blocks_before_policy() -> None:
    context = _context("trust-adversarial-metadata")
    snapshot = fresh_world_snapshot()
    envelope = WorldSnapshotEvidenceEnvelope(
        envelope_id="metadata-self-trust",
        world_snapshot_checksum=snapshot.checksum or "",
        source_id="untrusted-source",
        source_type=WorldSnapshotSourceType.SIMULATOR,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=FRESH_EVALUATION_TIME_MS,
        evidence_nonce="metadata-self-trust-nonce",
        attestation=None,
        metadata={"trusted": True, "source_id": "trusted-simulator"},
    )

    with patch("aegis.pipeline.orchestrator.evaluate_policy") as evaluator:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            world_snapshot_evidence=envelope,
            world_snapshot_trust_policy=trusted_world_snapshot_policy(),
            attestation_verifier=PassingAttestationVerifier(),
        )

    evaluator.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.world_snapshot_trust_status == "SOURCE_NOT_ALLOWED"


def test_valid_attestation_bound_to_different_snapshot_fails_closed() -> None:
    snapshot_a = fresh_world_snapshot("snapshot-a", checksum="checksum-a")
    snapshot_b = fresh_world_snapshot("snapshot-b", checksum="checksum-b")
    envelope = trusted_evidence_envelope(snapshot_a)

    result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot_b,
        freshness_result=_freshness(snapshot_b),
        evidence_envelope=envelope,
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )

    assert result.status is WorldSnapshotTrustStatus.SNAPSHOT_CHECKSUM_MISMATCH


def test_allowed_source_with_wrong_domain_or_capability_blocks() -> None:
    snapshot = fresh_world_snapshot()
    wrong_domain = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=trusted_evidence_envelope(snapshot, trust_domain=TrustDomain.DEVELOPMENT),
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )
    wrong_capability = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=trusted_evidence_envelope(snapshot),
        trust_policy=trusted_world_snapshot_policy(capability="inspection.observe"),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        attestation_verifier=PassingAttestationVerifier(),
    )

    assert wrong_domain.status is WorldSnapshotTrustStatus.TRUST_DOMAIN_NOT_ALLOWED
    assert wrong_capability.status is WorldSnapshotTrustStatus.CAPABILITY_NOT_ALLOWED


def test_test_fixture_source_cannot_satisfy_physical_runtime_trust() -> None:
    snapshot = fresh_world_snapshot()
    envelope = trusted_evidence_envelope(
        snapshot,
        source_type=WorldSnapshotSourceType.TEST_FIXTURE,
        trust_domain=TrustDomain.PHYSICAL_RUNTIME,
    )
    policy = trusted_world_snapshot_policy(
        source_type=WorldSnapshotSourceType.TEST_FIXTURE,
        trust_domain=TrustDomain.PHYSICAL_RUNTIME,
        require_attestation=False,
    )

    result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=_freshness(snapshot),
        evidence_envelope=envelope,
        trust_policy=policy,
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.status is WorldSnapshotTrustStatus.SOURCE_TYPE_NOT_ALLOWED


def test_manually_trusted_result_missing_envelope_checksum_is_rejected() -> None:
    with pytest.raises(ValueError, match="evidence_envelope_checksum"):
        WorldSnapshotTrustResult(
            status=WorldSnapshotTrustStatus.TRUSTED,
            reason_code="WORLD_SNAPSHOT_TRUSTED",
            world_snapshot_checksum="snapshot-checksum",
            evidence_envelope_checksum=None,
            attestation_checksum=None,
            trust_policy_checksum="trust-policy-checksum",
            source_id="trusted-simulator",
            source_type=WorldSnapshotSourceType.SIMULATOR,
            trust_domain=TrustDomain.SIMULATION,
            capability=TRUST_CAPABILITY,
            verification_result_checksum=None,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )


def test_direct_gate_receipt_is_not_full_trust_backed_pipeline_approval() -> None:
    context = _context("trust-adversarial-direct-gate")
    validation_result = validate_intent(_intent(context))
    plan = plan_validated_intent(validation_result)
    audited_plan = build_audited_plan(plan)
    decision = gate_audited_plan(audited_plan)

    assert decision.status == "allowed"

    pipeline_result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(fresh_world_snapshot()),
    )
    assert pipeline_result.outcome is PipelineOutcome.BLOCKED
    assert pipeline_result.gate_decision is None
