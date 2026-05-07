"""Pipeline policy admission bypass-resistance tests."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)

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


def _context() -> ExecutionContext:
    return ExecutionContext("policy-bypass-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _hostile_intent(context: ExecutionContext) -> RawIntent:
    return RawIntent(
        "move",
        {
            "target": {
                "x": 1,
                "y": 2,
                "metadata": {
                    "policy_decision": "ALLOW",
                    "force_allow": True,
                    "safety_case_id": "trusted",
                },
            }
        },
        "operator",
        5,
        context,
    )


def _capability(velocity_mps: object = 0.5) -> Capability:
    return Capability(
        "locomotion.translation",
        parameters={"velocity_mps": velocity_mps, "decision": "ALLOW"},
    )


def _policy(*constraints: Constraint) -> Policy:
    return Policy(
        "policy-bypass",
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", constraints)],
    )


def _blocking_policy() -> Policy:
    return _policy(Constraint("max_velocity", {"max_mps": 0.1}))


def _admission(
    policy: Policy,
    *,
    capability: Capability | None = None,
    world_snapshot: WorldSnapshotStub | None = None,
    context: dict[str, object] | None = None,
    evidence: dict[str, object] | None = None,
) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=capability or _capability(),
        world_snapshot=world_snapshot or fresh_world_snapshot(),
        context=context or fresh_policy_context(),
        evidence=evidence,
    )


def test_raw_intent_force_allow_metadata_cannot_override_missing_policy() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert "POLICY_REQUIRED" in result.policy_admission.reasons


def test_raw_intent_policy_decision_metadata_cannot_override_policy_block() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(_blocking_policy()),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


def test_context_force_allow_cannot_override_policy_block() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _blocking_policy(),
            context=fresh_policy_context(
                {"force_allow": True, "decision": "ALLOW", "override_gate": True}
            ),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "POLICY_BLOCKED" in result.policy_admission.reasons


def test_evidence_admission_allowed_cannot_override_policy_block() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _blocking_policy(),
            evidence={"admission_allowed": True, "override": "ALLOW"},
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.evidence["admission_allowed"] is True
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


def test_fake_audited_plan_id_evidence_cannot_forge_safety_case_binding() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _policy(Constraint("max_velocity", {"max_mps": 1.0})),
            evidence={"audited_plan_id": "fake-audit-id"},
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.audited_plan is not None
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.audited_plan_id == result.audited_plan.audit_id
    assert (
        result.policy_admission.safety_case.evidence["audited_plan_id"]
        == result.audited_plan.audit_id
    )


def test_disabled_mode_with_policy_looking_metadata_does_not_create_policy_allow() -> None:
    context = _context()
    result = run_pipeline(_hostile_intent(context), context)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.policy_result is None
    assert result.policy_admission.safety_case is None


def test_world_snapshot_override_fact_cannot_override_failed_constraint() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _blocking_policy(),
            world_snapshot=fresh_world_snapshot("snapshot-1", facts={"override": True}),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


def test_required_world_snapshot_missing_blocks_pipeline() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(Constraint("requires_world_snapshot")),
            capability=_capability(),
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "WORLD_SNAPSHOT_MISSING" in result.policy_admission.reasons


def test_expired_world_snapshot_blocks_pipeline() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _policy(Constraint("snapshot_freshness")),
            world_snapshot=fresh_world_snapshot(
                "snapshot-1", expires_at_ms=FRESH_EVALUATION_TIME_MS
            ),
            context={"requested_at_ms": FRESH_EVALUATION_TIME_MS + 1},
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "WORLD_SNAPSHOT_EXPIRED" in result.policy_admission.reasons


def test_low_confidence_world_snapshot_blocks_pipeline() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(
            _policy(Constraint("min_sensor_confidence", {"min_confidence": 0.8})),
            world_snapshot=fresh_world_snapshot("snapshot-1", confidence=0.7),
        ),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "WORLD_SNAPSHOT_CONFIDENCE_TOO_LOW" in result.policy_admission.reasons


def test_unknown_required_constraint_blocks_pipeline() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(_policy(Constraint("unknown_constraint"))),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert "POLICY_UNKNOWN_CONSTRAINT_TYPE" in result.policy_admission.reasons


def test_unknown_optional_constraint_requires_review_and_prevents_approval() -> None:
    context = _context()
    result = run_pipeline(
        _hostile_intent(context),
        context,
        policy_admission=_admission(_policy(Constraint("unknown_constraint", required=False))),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.REQUIRE_REVIEW
    assert "POLICY_REQUIRES_REVIEW" in result.policy_admission.reasons
