"""Adversarial input tests for the audit layer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.audit.audit_builder import build_audited_plan
from aegis.contracts.audit import AuditedPlan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan, CommandStep, CommandStepType
from aegis.planning.plan_hasher import stable_plan_id


def _make_stop_plan(
    request_id: str = "req-1",
    policy: str = "policy-v1",
    source_id: str = "operator-1",
) -> CommandPlan:
    ctx = ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), policy)
    intent = RawIntent("stop", {}, source_id, 5, ctx)
    step = CommandStep(CommandStepType.STOP, {}, 0)
    steps = (step,)
    return CommandPlan(stable_plan_id(intent, steps), intent, steps)


class TestAuditedPlanAdversarialConstruction:
    @pytest.mark.parametrize("audit_id", ["", " ", "\t", "\n", "   "])
    def test_rejects_blank_audit_id(self, audit_id: str) -> None:
        plan = _make_stop_plan()
        with pytest.raises(ValueError, match="audit_id"):
            AuditedPlan(plan=plan, audit_id=audit_id, checksum="b" * 64)

    @pytest.mark.parametrize("checksum", ["", " ", "\t", "\n", "   "])
    def test_rejects_blank_checksum(self, checksum: str) -> None:
        plan = _make_stop_plan()
        with pytest.raises(ValueError, match="checksum"):
            AuditedPlan(plan=plan, audit_id="a" * 64, checksum=checksum)

    def test_unicode_source_id_does_not_crash_builder(self) -> None:
        ctx = ExecutionContext("req-u", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
        intent = RawIntent("stop", {}, "操作者-\U0001f916", 5, ctx)
        step = CommandStep(CommandStepType.STOP, {}, 0)
        steps = (step,)
        plan = CommandPlan(stable_plan_id(intent, steps), intent, steps)
        receipt = build_audited_plan(plan)
        assert len(receipt.checksum) == 64
        assert len(receipt.audit_id) == 64

    def test_unicode_policy_version_does_not_crash_builder(self) -> None:
        ctx = ExecutionContext("req-p", datetime(2026, 1, 1, tzinfo=UTC), "政策-v1")
        intent = RawIntent("stop", {}, "op-1", 5, ctx)
        step = CommandStep(CommandStepType.STOP, {}, 0)
        steps = (step,)
        plan = CommandPlan(stable_plan_id(intent, steps), intent, steps)
        receipt = build_audited_plan(plan)
        assert len(receipt.checksum) == 64

    def test_deeply_nested_parameters_do_not_crash_builder(self) -> None:
        # Build a deeply-nested-but-valid move plan manually
        ctx = ExecutionContext("req-deep", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
        params: dict[str, object] = {"target": {"x": 1.0, "y": 2.0, "extra": {"a": {"b": "c"}}}}
        intent = RawIntent("move", params, "op-1", 5, ctx)
        step = CommandStep(CommandStepType.MOVE, {"target": {"x": 1.0, "y": 2.0}}, 0)
        steps = (step,)
        plan = CommandPlan(stable_plan_id(intent, steps), intent, steps)
        receipt = build_audited_plan(plan)
        assert len(receipt.checksum) == 64
        assert len(receipt.audit_id) == 64

    def test_maximum_priority_and_minimum_priority_produce_different_checksums(self) -> None:
        ctx = ExecutionContext("req-p", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")

        intent_min = RawIntent("stop", {}, "op-1", 1, ctx)
        intent_max = RawIntent("stop", {}, "op-1", 10, ctx)
        step = CommandStep(CommandStepType.STOP, {}, 0)

        plan_min = CommandPlan(stable_plan_id(intent_min, (step,)), intent_min, (step,))
        plan_max = CommandPlan(stable_plan_id(intent_max, (step,)), intent_max, (step,))

        from aegis.audit.checksum import plan_checksum

        assert plan_checksum(plan_min) != plan_checksum(plan_max)

    def test_prompt_injection_in_request_id_does_not_affect_hash_structure(self) -> None:
        injection = "req; DROP TABLE plans; --"
        ctx = ExecutionContext(injection, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
        intent = RawIntent("stop", {}, "op-1", 5, ctx)
        step = CommandStep(CommandStepType.STOP, {}, 0)
        steps = (step,)
        plan = CommandPlan(stable_plan_id(intent, steps), intent, steps)
        receipt = build_audited_plan(plan)
        assert len(receipt.checksum) == 64
        assert len(receipt.audit_id) == 64

    def test_extremely_long_source_id_does_not_crash_builder(self) -> None:
        ctx = ExecutionContext("req-long", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
        long_source = "x" * 10_000
        intent = RawIntent("stop", {}, long_source, 5, ctx)
        step = CommandStep(CommandStepType.STOP, {}, 0)
        steps = (step,)
        plan = CommandPlan(stable_plan_id(intent, steps), intent, steps)
        receipt = build_audited_plan(plan)
        assert len(receipt.checksum) == 64
