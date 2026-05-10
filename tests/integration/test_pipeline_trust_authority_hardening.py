"""Integration tests for ADR-0010 trust authority hardening in the pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import FRESH_EVALUATION_TIME_MS, fresh_world_snapshot
from tests.policy_trust_fixtures import (
    PassingAttestationVerifier,
    trusted_evidence_envelope,
    trusted_world_snapshot_policy,
)

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def _context(request_id: str) -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy() -> Policy:
    return Policy(
        "trust-authority-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 1.0})],
            )
        ],
    )


def _admission(snapshot) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context={"world_snapshot_fresh": True},
    )


def test_pipeline_blocks_missing_verifier_before_trust_evaluation() -> None:
    context = _context("trust-authority-missing-verifier")
    snapshot = fresh_world_snapshot()

    with patch("aegis.pipeline.aegis_orchestrator.evaluate_world_snapshot_trust") as trust:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            world_snapshot_evidence=trusted_evidence_envelope(snapshot),
            world_snapshot_trust_policy=trusted_world_snapshot_policy(),
        )

    trust.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.verifier_certification_status == "MISSING_VERIFIER"
    assert "ATTESTATION_VERIFIER_MISSING" in result.policy_admission.reasons
    assert result.policy_admission.world_snapshot_trust_status is None


def test_pipeline_blocks_invalid_trust_policy_config_before_trust_evaluation() -> None:
    context = _context("trust-authority-invalid-config")
    snapshot = fresh_world_snapshot()

    with patch("aegis.pipeline.aegis_orchestrator.evaluate_world_snapshot_trust") as trust:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            world_snapshot_evidence=trusted_evidence_envelope(snapshot),
            world_snapshot_trust_policy=trusted_world_snapshot_policy(require_attestation=False),
            attestation_verifier=PassingAttestationVerifier(),
        )

    trust.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.verifier_certification_status == "CERTIFIED"
    assert (
        result.policy_admission.trust_policy_config_status
        == "ATTESTATION_REQUIRED_FALSE_IN_ENFORCE"
    )
    assert "TRUST_POLICY_ATTESTATION_REQUIRED_FALSE_IN_ENFORCE" in result.policy_admission.reasons
    assert result.policy_admission.world_snapshot_trust_status is None
