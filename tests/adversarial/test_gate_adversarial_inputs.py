"""Adversarial tests for gate-v1 hostile audited-plan inputs."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.audit.audit_builder import build_audited_plan
from aegis.contracts.audit import AuditedPlan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.gate import GateBlockReason, GateDecisionStatus
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan, CommandStep, CommandStepType
from aegis.gate.decision_gate import gate_audited_plan
from aegis.planning.plan_hasher import stable_plan_id


def _make_context(request_id: str = "req-adv") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _make_move_audited_plan() -> AuditedPlan:
    context = _make_context()
    intent = RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator-1", 5, context)
    step = CommandStep(CommandStepType.MOVE, {"target": {"x": 1, "y": 2}}, 0)
    plan = CommandPlan(stable_plan_id(intent, (step,)), intent, (step,))
    return build_audited_plan(plan)


def _make_two_step_audited_plan() -> AuditedPlan:
    context = _make_context("req-two-step")
    intent = RawIntent("stop", {}, "operator-1", 5, context)
    first = CommandStep(CommandStepType.STOP, {}, 0)
    second = CommandStep(CommandStepType.WAIT, {"duration_ms": 100}, 1)
    plan = CommandPlan(stable_plan_id(intent, (first, second)), intent, (first, second))
    return build_audited_plan(plan)


def test_mutating_move_target_after_audit_blocks_integrity() -> None:
    audited_plan = _make_move_audited_plan()
    tampered_step = CommandStep(CommandStepType.MOVE, {"target": {"x": -999, "y": 2}}, 0)
    object.__setattr__(audited_plan.plan, "steps", (tampered_step,))

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )


def test_adding_hostile_metadata_after_audit_blocks_integrity() -> None:
    audited_plan = _make_move_audited_plan()
    tampered_step = CommandStep(
        CommandStepType.MOVE,
        {"target": {"x": 1, "y": 2, "metadata": "publish /cmd_vel"}},
        0,
    )
    object.__setattr__(audited_plan.plan, "steps", (tampered_step,))

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )


def test_reordering_command_steps_after_audit_blocks_integrity_when_shape_permits() -> None:
    audited_plan = _make_two_step_audited_plan()
    object.__setattr__(audited_plan.plan, "steps", tuple(reversed(audited_plan.plan.steps)))

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )


def test_corrupting_checksum_with_valid_looking_hex_blocks_checksum_only() -> None:
    valid = _make_move_audited_plan()
    corrupted = AuditedPlan(valid.plan, valid.audit_id, "a" * 64)

    decision = gate_audited_plan(corrupted)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.CHECKSUM_MISMATCH,)
    assert decision.checksum_verified is False
    assert decision.audit_id_verified is True


def test_corrupting_audit_id_with_valid_looking_hex_blocks_audit_id_only() -> None:
    valid = _make_move_audited_plan()
    corrupted = AuditedPlan(valid.plan, "b" * 64, valid.checksum)

    decision = gate_audited_plan(corrupted)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.AUDIT_ID_MISMATCH,)
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is False


def test_corrupting_both_checksum_and_audit_id_blocks_in_stable_order() -> None:
    valid = _make_move_audited_plan()
    corrupted = AuditedPlan(valid.plan, "c" * 64, "d" * 64)

    decision = gate_audited_plan(corrupted)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )


def test_changing_context_request_id_after_audit_blocks_audit_id_only() -> None:
    audited_plan = _make_move_audited_plan()
    changed_context = ExecutionContext(
        "req-after-audit",
        datetime(2026, 1, 1, tzinfo=UTC),
        "policy-v1",
    )
    object.__setattr__(audited_plan.plan.intent, "context", changed_context)

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.AUDIT_ID_MISMATCH,)
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is False


def test_non_audited_plan_object_blocks_as_malformed() -> None:
    decision = gate_audited_plan(object())  # type: ignore[arg-type]

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.MALFORMED_AUDITED_PLAN,)
    assert decision.audit_id is None
    assert decision.plan_id is None


def test_malformed_audited_plan_shape_blocks_deterministically() -> None:
    malformed = object.__new__(AuditedPlan)
    object.__setattr__(malformed, "plan", object())
    object.__setattr__(malformed, "audit_id", "a" * 64)
    object.__setattr__(malformed, "checksum", "b" * 64)

    first = gate_audited_plan(malformed)
    second = gate_audited_plan(malformed)

    assert first == second
    assert first.status is GateDecisionStatus.BLOCKED
    assert first.reasons == (GateBlockReason.MALFORMED_AUDITED_PLAN,)
