"""Phase 2 Part 5 invariants for freshness-backed pipeline approval."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyDecision, PolicyRule
from aegis.contracts.policy_admission import (
    PolicyAdmissionInput,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    assert_policy_admission_integrity,
)
from aegis.contracts.world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    WorldSnapshotFreshnessStatus,
    assert_world_snapshot_freshness_integrity,
    validate_world_snapshot_freshness,
)
from aegis.pipeline import run_pipeline

_VALID_COMMANDS = ("move", "stop", "inspect", "wait")


def _context() -> ExecutionContext:
    return ExecutionContext("freshness-invariant", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(command: str, priority: int, context: ExecutionContext) -> RawIntent:
    parameters: dict[str, object] = {}
    if command == "move":
        parameters = {"target": {"x": 0, "y": 0}}
    if command == "wait":
        parameters = {"duration_ms": 200}
    if command == "inspect":
        parameters = {"target": "front_sensor"}
    return RawIntent(command, parameters, "freshness-invariant", priority, context)


def _policy() -> Policy:
    return Policy(
        "freshness-invariant-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 1.0})],
            )
        ],
    )


@given(st.sampled_from(_VALID_COMMANDS), st.integers(min_value=1, max_value=10))
@settings(max_examples=40)
def test_invariant_allowed_implies_freshness_backed_policy_admission(
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
    )

    if result.outcome is not PipelineOutcome.ALLOWED:
        return

    freshness_result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    assert_world_snapshot_freshness_integrity(
        snapshot=snapshot,
        freshness_result=freshness_result,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert freshness_result.status is WorldSnapshotFreshnessStatus.FRESH
    assert freshness_result.is_fresh is True
    assert freshness_result.age_ms <= freshness_result.max_allowed_age_ms

    assert result.audited_plan is not None
    assert result.gate_decision is not None
    assert result.gate_decision.status == "allowed"

    admission = result.policy_admission
    assert admission.mode is PolicyAdmissionMode.ENFORCE
    assert admission.integrity_status is PolicyAdmissionIntegrityStatus.PASSED
    assert admission.policy_result is not None
    assert admission.policy_result.decision is PolicyDecision.ALLOW
    assert admission.safety_case is not None

    assert admission.world_snapshot_id == snapshot.snapshot_id
    assert admission.world_snapshot_observed_at_ms == snapshot.captured_at_ms
    assert admission.freshness_status == freshness_result.status.value
    assert admission.freshness_result_checksum == freshness_result.checksum

    assert admission.policy_result.world_snapshot_id == admission.world_snapshot_id
    assert admission.policy_result.world_snapshot_observed_at_ms == (
        admission.world_snapshot_observed_at_ms
    )
    assert admission.policy_result.freshness_status == admission.freshness_status
    assert admission.policy_result.freshness_result_checksum == (
        admission.freshness_result_checksum
    )

    assert admission.safety_case.world_snapshot_id == admission.world_snapshot_id
    assert admission.safety_case.world_snapshot_observed_at_ms == (
        admission.world_snapshot_observed_at_ms
    )
    assert admission.safety_case.freshness_status == admission.freshness_status
    assert admission.safety_case.freshness_result_checksum == (admission.freshness_result_checksum)

    integrity = assert_policy_admission_integrity(result.audited_plan, admission)
    assert integrity.status is PolicyAdmissionIntegrityStatus.PASSED
