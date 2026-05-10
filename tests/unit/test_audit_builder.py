"""Unit tests for audit_builder.build_audited_plan."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from aegis.audit.aegis_audit_builder import build_audited_plan
from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_planning import CommandPlan, CommandStep, CommandStepType
from aegis.planning.aegis_plan_hasher import stable_plan_id

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _make_plan(
    command: str = "stop",
    parameters: dict[str, object] | None = None,
    request_id: str = "req-1",
    policy: str = "policy-v1",
    source_id: str = "operator-1",
    priority: int = 5,
) -> CommandPlan:
    ctx = ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), policy)
    params = parameters or {}
    intent = RawIntent(command, params, source_id, priority, ctx)
    if command == "stop":
        step = CommandStep(CommandStepType.STOP, {}, 0)
    elif command == "wait":
        step = CommandStep(
            CommandStepType.WAIT, {"duration_ms": params.get("duration_ms", 1000)}, 0
        )
    elif command == "inspect":
        step = CommandStep(CommandStepType.INSPECT, {"target": params.get("target", "sensor")}, 0)
    else:
        step = CommandStep(CommandStepType.MOVE, {"target": {"x": 0.0, "y": 0.0}}, 0)
    steps = (step,)
    return CommandPlan(stable_plan_id(intent, steps), intent, steps)


class TestBuildAuditedPlan:
    def test_returns_audited_plan_instance(self) -> None:
        plan = _make_plan()
        result = build_audited_plan(plan)
        assert isinstance(result, AuditedPlan)

    def test_preserves_original_plan_reference(self) -> None:
        plan = _make_plan()
        result = build_audited_plan(plan)
        assert result.plan is plan

    def test_produces_non_empty_audit_id(self) -> None:
        result = build_audited_plan(_make_plan())
        assert result.audit_id != ""

    def test_produces_non_empty_checksum(self) -> None:
        result = build_audited_plan(_make_plan())
        assert result.checksum != ""

    def test_audit_id_is_64_char_lowercase_hex(self) -> None:
        result = build_audited_plan(_make_plan())
        assert _SHA256_HEX.match(result.audit_id)

    def test_checksum_is_64_char_lowercase_hex(self) -> None:
        result = build_audited_plan(_make_plan())
        assert _SHA256_HEX.match(result.checksum)

    def test_is_deterministic_for_same_plan(self) -> None:
        plan = _make_plan()
        r1 = build_audited_plan(plan)
        r2 = build_audited_plan(plan)
        assert r1 == r2

    def test_audit_id_and_checksum_are_different_values(self) -> None:
        result = build_audited_plan(_make_plan())
        assert result.audit_id != result.checksum

    def test_different_plans_produce_different_checksums(self) -> None:
        stop_plan = _make_plan("stop")
        wait_plan = _make_plan("wait", {"duration_ms": 500})
        r1 = build_audited_plan(stop_plan)
        r2 = build_audited_plan(wait_plan)
        assert r1.checksum != r2.checksum

    def test_different_plans_produce_different_audit_ids(self) -> None:
        stop_plan = _make_plan("stop")
        wait_plan = _make_plan("wait", {"duration_ms": 500})
        r1 = build_audited_plan(stop_plan)
        r2 = build_audited_plan(wait_plan)
        assert r1.audit_id != r2.audit_id

    def test_returned_audited_plan_is_frozen(self) -> None:
        result = build_audited_plan(_make_plan())
        try:
            result.audit_id = "tampered"  # type: ignore[misc]
            raised = False
        except (AttributeError, TypeError):
            raised = True
        assert raised, "AuditedPlan must be immutable"

    def test_different_contexts_produce_different_audit_ids(self) -> None:
        plan1 = _make_plan(request_id="req-A")
        plan2 = _make_plan(request_id="req-B")
        r1 = build_audited_plan(plan1)
        r2 = build_audited_plan(plan2)
        assert r1.audit_id != r2.audit_id
