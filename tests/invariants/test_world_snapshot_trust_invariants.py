"""Phase 2 trust invariants for enforced pipeline approval."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
    fresh_world_snapshot_result,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs, trusted_world_snapshot_result

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyDecision, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.contracts.world_snapshot_trust import WorldSnapshotTrustStatus
from aegis.pipeline import run_pipeline

_VALID_COMMANDS = ("move", "stop", "inspect", "wait")


def _context() -> ExecutionContext:
    return ExecutionContext("trust-invariant", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(command: str, priority: int, context: ExecutionContext) -> RawIntent:
    parameters: dict[str, object] = {}
    if command == "move":
        parameters = {"target": {"x": 0, "y": 0}}
    if command == "wait":
        parameters = {"duration_ms": 200}
    if command == "inspect":
        parameters = {"target": "front_sensor"}
    return RawIntent(command, parameters, "trust-invariant", priority, context)


def _policy() -> Policy:
    return Policy(
        "trust-invariant-policy",
        "v1",
        [
            PolicyRule(
                "rule-1", "locomotion.translation", [Constraint("max_velocity", {"max_mps": 1.0})]
            )
        ],
    )


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=40)
def test_invariant_allowed_under_enforce_implies_trusted_world_snapshot(
    command: str,
    priority: int,
) -> None:
    context = _context()
    snapshot = fresh_world_snapshot()
    result = run_pipeline(
        _intent(command, priority, context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(),
            capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
            world_snapshot=snapshot,
            context=fresh_policy_context(),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(snapshot),
    )

    if result.outcome is not PipelineOutcome.ALLOWED:
        return

    trust_result = trusted_world_snapshot_result(snapshot)
    admission = result.policy_admission
    assert admission.policy_result is not None
    assert admission.safety_case is not None
    assert admission.policy_result.decision is PolicyDecision.ALLOW

    assert admission.world_snapshot_trust_status == WorldSnapshotTrustStatus.TRUSTED.value
    assert admission.world_snapshot_trust_result_checksum == trust_result.checksum
    assert admission.evidence_envelope_checksum == trust_result.evidence_envelope_checksum
    assert admission.trust_policy_checksum == trust_result.trust_policy_checksum
    assert admission.source_id == trust_result.source_id
    assert admission.source_type == trust_result.source_type.value
    assert admission.trust_domain == trust_result.trust_domain.value

    assert admission.policy_result.world_snapshot_trust_result_checksum == (
        admission.world_snapshot_trust_result_checksum
    )
    assert admission.safety_case.world_snapshot_trust_result_checksum == (
        admission.world_snapshot_trust_result_checksum
    )


@given(st.booleans(), st.text(max_size=12))
@settings(max_examples=30)
def test_invariant_metadata_does_not_make_missing_attestation_trusted(
    trusted_flag: bool,
    label: str,
) -> None:
    from aegis.contracts.world_snapshot_trust import (
        TrustDomain,
        WorldSnapshotEvidenceEnvelope,
        WorldSnapshotSourceType,
        evaluate_world_snapshot_trust,
    )

    snapshot = fresh_world_snapshot()
    envelope = WorldSnapshotEvidenceEnvelope(
        envelope_id="metadata-invariant-envelope",
        world_snapshot_checksum=snapshot.checksum or "",
        source_id="trusted-simulator",
        source_type=WorldSnapshotSourceType.SIMULATOR,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=FRESH_EVALUATION_TIME_MS,
        evidence_nonce="metadata-invariant-nonce",
        attestation=None,
        metadata={"trusted": trusted_flag, "label": label},
    )
    from tests.policy_trust_fixtures import TRUST_CAPABILITY, trusted_world_snapshot_policy

    trust_result = evaluate_world_snapshot_trust(
        world_snapshot=snapshot,
        freshness_result=fresh_world_snapshot_result(snapshot),
        evidence_envelope=envelope,
        trust_policy=trusted_world_snapshot_policy(),
        capability=TRUST_CAPABILITY,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert trust_result.status is not WorldSnapshotTrustStatus.TRUSTED
