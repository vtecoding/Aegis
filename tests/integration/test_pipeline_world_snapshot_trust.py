"""Integration tests for world snapshot trust enforcement in the pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import (
    PassingAttestationVerifier,
    trusted_attestation,
    trusted_evidence_envelope,
    trusted_pipeline_kwargs,
    trusted_world_snapshot_policy,
)

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.contracts.world_snapshot_trust import (
    WorldSnapshotAttestation,
    WorldSnapshotTrustStatus,
)
from aegis.pipeline import run_pipeline


def _context(request_id: str = "pipeline-trust") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy(max_mps: float = 1.0) -> Policy:
    return Policy(
        "pipeline-trust-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps})],
            )
        ],
    )


def _admission(snapshot) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def test_enforce_fresh_trusted_policy_allow_and_gate_allow_produces_allowed() -> None:
    context = _context("pipeline-trust-allow")
    snapshot = fresh_world_snapshot()
    admission = _admission(snapshot)

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.policy_admission.world_snapshot_trust_status == "TRUSTED"
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.world_snapshot_trust_status == "TRUSTED"
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.world_snapshot_trust_status == "TRUSTED"


def test_enforce_fresh_missing_evidence_blocks_before_policy_evaluation() -> None:
    context = _context("pipeline-trust-missing-evidence")
    snapshot = fresh_world_snapshot()

    with patch("aegis.pipeline.orchestrator.evaluate_policy") as evaluator:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            world_snapshot_trust_policy=trusted_world_snapshot_policy(),
            attestation_verifier=PassingAttestationVerifier(),
        )

    evaluator.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.world_snapshot_trust_status == (
        WorldSnapshotTrustStatus.MISSING_EVIDENCE.value
    )
    assert "WORLD_SNAPSHOT_EVIDENCE_MISSING" in result.policy_admission.reasons


def test_enforce_fresh_untrusted_attestation_blocks_before_policy_evaluation() -> None:
    context = _context("pipeline-trust-invalid-attestation")
    snapshot = fresh_world_snapshot()
    attestation = trusted_attestation(snapshot)
    tampered_attestation = WorldSnapshotAttestation(
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
        signature="tampered-fixture-signature",
        signed_payload_checksum=attestation.signed_payload_checksum,
    )

    with patch("aegis.pipeline.orchestrator.evaluate_policy") as evaluator:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            world_snapshot_evidence=trusted_evidence_envelope(
                snapshot, attestation=tampered_attestation
            ),
            world_snapshot_trust_policy=trusted_world_snapshot_policy(),
            attestation_verifier=PassingAttestationVerifier(),
        )

    evaluator.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.world_snapshot_trust_status == (
        WorldSnapshotTrustStatus.ATTESTATION_INVALID.value
    )


def test_enforce_trusted_snapshot_stale_still_blocks_before_trust_evaluation() -> None:
    context = _context("pipeline-trust-stale")
    snapshot = fresh_world_snapshot(observed_at_ms=FRESH_EVALUATION_TIME_MS - 2_000)

    with patch("aegis.pipeline.orchestrator.evaluate_world_snapshot_trust") as trust:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **trusted_pipeline_kwargs(snapshot),
        )

    trust.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.freshness_status == "STALE"
    assert result.policy_admission.world_snapshot_trust_status is None


def test_disabled_mode_does_not_claim_fake_trust() -> None:
    context = _context("pipeline-trust-disabled")
    snapshot = fresh_world_snapshot()

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.world_snapshot_trust_status is None
    assert result.policy_admission.admission_allowed is False
