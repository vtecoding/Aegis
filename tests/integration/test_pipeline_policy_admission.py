"""Integration test for policy-enforced pipeline admission."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def test_policy_enforced_pipeline_with_world_snapshot_allows_then_gates() -> None:
    context = ExecutionContext(
        "policy-integration-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1"
    )
    intent = RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)
    policy = Policy(
        "policy-integration",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [
                    Constraint("requires_world_snapshot"),
                    Constraint("snapshot_freshness"),
                    Constraint("min_sensor_confidence", {"min_confidence": 0.8}),
                    Constraint("max_velocity", {"max_mps": 0.5}),
                ],
            )
        ],
    )
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=WorldSnapshotStub("snapshot-1", 100, 200, "fixture", 0.9),
        context={"requested_at_ms": 150},
    )

    result = run_pipeline(intent, context, policy_admission=admission)

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ALLOW
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.world_snapshot_id == "snapshot-1"
