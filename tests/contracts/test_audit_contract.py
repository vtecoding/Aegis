"""Contract conformance tests for AuditedPlan."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_planning import CommandPlan, CommandStep, CommandStepType
from aegis.planning.aegis_plan_hasher import stable_plan_id


def _make_plan(command: str = "stop") -> CommandPlan:
    context = ExecutionContext("req-1", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    intent = RawIntent(command, {}, "operator-1", 5, context)
    step = CommandStep(CommandStepType.STOP, {}, 0)
    steps = (step,)
    return CommandPlan(stable_plan_id(intent, steps), intent, steps)


def _make_audited_plan(plan: CommandPlan | None = None) -> AuditedPlan:
    resolved_plan = plan if plan is not None else _make_plan()
    return AuditedPlan(
        plan=resolved_plan,
        audit_id="a" * 64,
        checksum="b" * 64,
    )


class TestAuditedPlanConstruction:
    def test_construction_with_valid_inputs_succeeds(self) -> None:
        plan = _make_plan()
        receipt = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="b" * 64)

        assert receipt.plan is plan
        assert receipt.audit_id == "a" * 64
        assert receipt.checksum == "b" * 64

    def test_construction_strips_whitespace_from_audit_id(self) -> None:
        plan = _make_plan()
        receipt = AuditedPlan(plan=plan, audit_id="  " + "a" * 64 + "  ", checksum="b" * 64)
        assert receipt.audit_id == "a" * 64

    def test_construction_strips_whitespace_from_checksum(self) -> None:
        plan = _make_plan()
        receipt = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="  " + "b" * 64 + "  ")
        assert receipt.checksum == "b" * 64

    def test_empty_audit_id_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="audit_id"):
            AuditedPlan(plan=_make_plan(), audit_id="", checksum="b" * 64)

    def test_whitespace_only_audit_id_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="audit_id"):
            AuditedPlan(plan=_make_plan(), audit_id="   ", checksum="b" * 64)

    def test_empty_checksum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="checksum"):
            AuditedPlan(plan=_make_plan(), audit_id="a" * 64, checksum="")

    def test_whitespace_only_checksum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="checksum"):
            AuditedPlan(plan=_make_plan(), audit_id="a" * 64, checksum="   ")


class TestAuditedPlanImmutability:
    def test_audited_plan_is_frozen(self) -> None:
        receipt = _make_audited_plan()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            receipt.audit_id = "x" * 64  # type: ignore[misc]

    def test_audited_plan_is_a_dataclass(self) -> None:
        assert dataclasses.is_dataclass(AuditedPlan)

    def test_audited_plan_has_slots(self) -> None:
        assert hasattr(AuditedPlan, "__slots__")

    def test_audited_plan_has_three_fields(self) -> None:
        fields = dataclasses.fields(AuditedPlan)
        assert len(fields) == 3

    def test_audited_plan_field_names_and_types(self) -> None:
        field_map = {f.name: f.type for f in dataclasses.fields(AuditedPlan)}
        assert "plan" in field_map
        assert "audit_id" in field_map
        assert "checksum" in field_map

    def test_audited_plan_preserves_command_plan_reference(self) -> None:
        plan = _make_plan()
        receipt = _make_audited_plan(plan)
        assert receipt.plan is plan

    def test_equal_audited_plans_are_equal(self) -> None:
        plan = _make_plan()
        r1 = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="b" * 64)
        r2 = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="b" * 64)
        assert r1 == r2

    def test_different_audit_ids_are_not_equal(self) -> None:
        plan = _make_plan()
        r1 = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="b" * 64)
        r2 = AuditedPlan(plan=plan, audit_id="c" * 64, checksum="b" * 64)
        assert r1 != r2

    def test_different_checksums_are_not_equal(self) -> None:
        plan = _make_plan()
        r1 = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="b" * 64)
        r2 = AuditedPlan(plan=plan, audit_id="a" * 64, checksum="d" * 64)
        assert r1 != r2
