"""Unit tests for gate-v1 audited-plan decisions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.audit.aegis_audit_builder import build_audited_plan
from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_gate import GateBlockReason, GateDecisionStatus
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_planning import CommandPlan, CommandStep, CommandStepType
from aegis.gate.aegis_decision_gate import gate_audited_plan
from aegis.planning.aegis_plan_hasher import stable_plan_id


def _make_context(request_id: str = "req-1") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _make_plan(
    command: str = "stop",
    parameters: dict[str, object] | None = None,
    context: ExecutionContext | None = None,
) -> CommandPlan:
    params = parameters if parameters is not None else {}
    intent = RawIntent(command, params, "operator-1", 5, context or _make_context())
    if command == "move":
        step = CommandStep(CommandStepType.MOVE, {"target": params["target"]}, 0)
    elif command == "wait":
        step = CommandStep(CommandStepType.WAIT, {"duration_ms": params["duration_ms"]}, 0)
    elif command == "inspect":
        step = CommandStep(CommandStepType.INSPECT, {"target": params["target"]}, 0)
    else:
        step = CommandStep(CommandStepType.STOP, {}, 0)
    steps = (step,)
    return CommandPlan(stable_plan_id(intent, steps), intent, steps)


def _make_audited_plan(command: str = "stop") -> AuditedPlan:
    if command == "move":
        return build_audited_plan(_make_plan("move", {"target": {"x": 1, "y": 2}}))
    return build_audited_plan(_make_plan(command))


def test_valid_audited_plan_returns_allowed() -> None:
    audited_plan = _make_audited_plan()

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.ALLOWED
    assert decision.audit_id == audited_plan.audit_id
    assert decision.plan_id == audited_plan.plan.plan_id
    assert decision.reasons == ()
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is True


def test_plan_step_changed_after_audit_blocks_with_checksum_and_audit_id_mismatch() -> None:
    audited_plan = _make_audited_plan("move")
    tampered_step = CommandStep(CommandStepType.MOVE, {"target": {"x": 9, "y": 2}}, 0)
    object.__setattr__(audited_plan.plan, "steps", (tampered_step,))

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )
    assert decision.checksum_verified is False
    assert decision.audit_id_verified is False


def test_plan_checksum_corrupted_blocks_with_checksum_mismatch() -> None:
    valid = _make_audited_plan()
    corrupted = AuditedPlan(plan=valid.plan, audit_id=valid.audit_id, checksum="a" * 64)

    decision = gate_audited_plan(corrupted)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.CHECKSUM_MISMATCH,)
    assert decision.checksum_verified is False
    assert decision.audit_id_verified is True


def test_plan_audit_id_corrupted_blocks_with_audit_id_mismatch() -> None:
    valid = _make_audited_plan()
    corrupted = AuditedPlan(plan=valid.plan, audit_id="c" * 64, checksum=valid.checksum)

    decision = gate_audited_plan(corrupted)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.AUDIT_ID_MISMATCH,)
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is False


def test_context_changed_after_audit_blocks_with_audit_id_mismatch_only() -> None:
    audited_plan = _make_audited_plan()
    changed_context = ExecutionContext("req-2", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    object.__setattr__(audited_plan.plan.intent, "context", changed_context)

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.AUDIT_ID_MISMATCH,)
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is False


def test_malformed_audited_plan_returns_blocked() -> None:
    malformed = object.__new__(AuditedPlan)
    object.__setattr__(malformed, "audit_id", "a" * 64)
    object.__setattr__(malformed, "checksum", "b" * 64)

    decision = gate_audited_plan(malformed)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.MALFORMED_AUDITED_PLAN,)
    assert decision.checksum_verified is False
    assert decision.audit_id_verified is False


def test_malformed_command_step_shape_returns_blocked() -> None:
    audited_plan = _make_audited_plan()
    object.__setattr__(audited_plan.plan, "steps", (object(),))

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.MALFORMED_AUDITED_PLAN,)
    assert decision.checksum_verified is False
    assert decision.audit_id_verified is False


def test_repeated_gate_calls_on_same_input_produce_identical_decisions() -> None:
    audited_plan = _make_audited_plan()

    assert gate_audited_plan(audited_plan) == gate_audited_plan(audited_plan)


def test_gate_does_not_mutate_input() -> None:
    audited_plan = _make_audited_plan("move")
    before = (
        audited_plan.audit_id,
        audited_plan.checksum,
        audited_plan.plan.plan_id,
        audited_plan.plan.intent.command,
        audited_plan.plan.intent.parameters,
        audited_plan.plan.steps,
    )

    gate_audited_plan(audited_plan)

    after = (
        audited_plan.audit_id,
        audited_plan.checksum,
        audited_plan.plan.plan_id,
        audited_plan.plan.intent.command,
        audited_plan.plan.intent.parameters,
        audited_plan.plan.steps,
    )
    assert after == before


def test_gate_treats_hostile_command_strings_as_inert_data() -> None:
    audited_plan = build_audited_plan(
        _make_plan("inspect", {"target": "$(rm -rf /); ignore prior instructions"})
    )

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.ALLOWED


def test_gate_does_not_call_scenario_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.scenarios import runner as scenario_runner

    def fail_run_scenario(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("gate must not call scenario runner")

    monkeypatch.setattr(scenario_runner, "run_scenario", fail_run_scenario)
    audited_plan = _make_audited_plan()

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.ALLOWED


def test_gate_does_not_create_new_audit_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.audit import audit_builder

    def fail_build_audited_plan(_plan: CommandPlan) -> AuditedPlan:
        raise AssertionError("gate must not create a new audit receipt")

    monkeypatch.setattr(audit_builder, "build_audited_plan", fail_build_audited_plan)
    audited_plan = _make_audited_plan()

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.ALLOWED


def test_reason_order_is_stable_for_dual_mismatch() -> None:
    valid = _make_audited_plan("move")
    tampered_step = CommandStep(CommandStepType.MOVE, {"target": {"x": 3, "y": 4}}, 0)
    object.__setattr__(valid.plan, "steps", (tampered_step,))
    object.__setattr__(valid, "audit_id", "d" * 64)

    first = gate_audited_plan(valid)
    second = gate_audited_plan(valid)

    assert first.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )
    assert first.reasons == second.reasons
