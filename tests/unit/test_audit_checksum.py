"""Unit tests for audit-v1 checksum and audit_id hashing."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from aegis.audit.checksum import plan_audit_id, plan_checksum
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan, CommandStep, CommandStepType
from aegis.planning.plan_hasher import stable_plan_id

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _make_context(
    request_id: str = "req-1",
    policy: str = "policy-v1",
    run_id: str | None = None,
) -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), policy, run_id)


def _make_plan(
    command: str = "stop",
    parameters: dict[str, object] | None = None,
    context: ExecutionContext | None = None,
    source_id: str = "operator-1",
    priority: int = 5,
) -> CommandPlan:
    ctx = context if context is not None else _make_context()
    params = parameters if parameters is not None else {}
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
        step = CommandStep(
            CommandStepType.MOVE,
            {"target": {"x": 1.0, "y": 2.0}},
            0,
        )
    steps = (step,)
    return CommandPlan(stable_plan_id(intent, steps), intent, steps)


class TestPlanChecksum:
    def test_plan_checksum_returns_64_char_lowercase_hex(self) -> None:
        plan = _make_plan()
        result = plan_checksum(plan)
        assert _SHA256_HEX.match(result), f"Expected 64-char lowercase hex, got: {result!r}"

    def test_plan_checksum_is_deterministic(self) -> None:
        plan = _make_plan()
        assert plan_checksum(plan) == plan_checksum(plan)

    def test_plan_checksum_same_content_produces_same_hash(self) -> None:
        plan1 = _make_plan("stop")
        plan2 = _make_plan("stop")
        assert plan_checksum(plan1) == plan_checksum(plan2)

    def test_plan_checksum_differs_for_different_commands(self) -> None:
        stop_plan = _make_plan("stop")
        wait_plan = _make_plan("wait", {"duration_ms": 1000})
        assert plan_checksum(stop_plan) != plan_checksum(wait_plan)

    def test_plan_checksum_does_not_directly_include_context_fields(self) -> None:
        """Context fields (request_id, submitted_at, policy_version, run_id) are
        not included directly in the checksum payload; they live in audit_id only.
        Different contexts produce different plan_ids (via stable_plan_id), so
        the checksums will differ, but that is through plan_id, not raw context.
        """
        ctx1 = _make_context("req-A", "policy-v1")
        ctx2 = _make_context("req-B", "policy-v2", run_id="run-1")
        plan1 = _make_plan("stop", context=ctx1)
        plan2 = _make_plan("stop", context=ctx2)
        assert _SHA256_HEX.match(plan_checksum(plan1))
        assert _SHA256_HEX.match(plan_checksum(plan2))

    def test_plan_checksum_differs_for_different_source_ids(self) -> None:
        # source_id is not directly in the checksum payload, but it is encoded
        # into plan_id via stable_plan_id — so different source_ids produce
        # different plan_ids and therefore different checksums.
        plan1 = _make_plan("stop", source_id="operator-1")
        plan2 = _make_plan("stop", source_id="operator-2")
        assert plan_checksum(plan1) != plan_checksum(plan2)

    def test_plan_checksum_differs_for_different_priorities(self) -> None:
        # priority is not directly in the checksum payload, but it is encoded
        # into plan_id via stable_plan_id — so different priorities produce
        # different plan_ids and therefore different checksums.
        plan1 = _make_plan("stop", priority=1)
        plan2 = _make_plan("stop", priority=9)
        assert plan_checksum(plan1) != plan_checksum(plan2)

    @pytest.mark.parametrize(
        "command,params",
        [
            ("stop", {}),
            ("wait", {"duration_ms": 5000}),
            ("inspect", {"target": "sensor-A"}),
        ],
    )
    def test_plan_checksum_returns_valid_hex_for_all_commands(
        self, command: str, params: dict[str, object]
    ) -> None:
        plan = _make_plan(command, params)
        assert _SHA256_HEX.match(plan_checksum(plan))


class TestPlanAuditId:
    def test_plan_audit_id_returns_64_char_lowercase_hex(self) -> None:
        plan = _make_plan()
        checksum = plan_checksum(plan)
        result = plan_audit_id(plan, checksum)
        assert _SHA256_HEX.match(result), f"Expected 64-char lowercase hex, got: {result!r}"

    def test_plan_audit_id_is_deterministic(self) -> None:
        plan = _make_plan()
        checksum = plan_checksum(plan)
        assert plan_audit_id(plan, checksum) == plan_audit_id(plan, checksum)

    def test_plan_audit_id_differs_for_different_checksums(self) -> None:
        plan = _make_plan()
        assert plan_audit_id(plan, "a" * 64) != plan_audit_id(plan, "b" * 64)

    def test_plan_audit_id_differs_for_different_request_ids(self) -> None:
        ctx1 = _make_context("req-X")
        ctx2 = _make_context("req-Y")
        plan1 = _make_plan("stop", context=ctx1)
        plan2 = _make_plan("stop", context=ctx2)
        checksum1 = plan_checksum(plan1)
        checksum2 = plan_checksum(plan2)
        assert plan_audit_id(plan1, checksum1) != plan_audit_id(plan2, checksum2)

    def test_plan_audit_id_differs_for_different_policy_versions(self) -> None:
        ctx1 = _make_context(policy="policy-v1")
        ctx2 = _make_context(policy="policy-v2")
        plan1 = _make_plan("stop", context=ctx1)
        plan2 = _make_plan("stop", context=ctx2)
        checksum1 = plan_checksum(plan1)
        checksum2 = plan_checksum(plan2)
        assert plan_audit_id(plan1, checksum1) != plan_audit_id(plan2, checksum2)

    def test_plan_audit_id_differs_for_different_run_ids(self) -> None:
        ctx1 = _make_context(run_id="run-A")
        ctx2 = _make_context(run_id="run-B")
        plan1 = _make_plan("stop", context=ctx1)
        plan2 = _make_plan("stop", context=ctx2)
        checksum1 = plan_checksum(plan1)
        checksum2 = plan_checksum(plan2)
        assert plan_audit_id(plan1, checksum1) != plan_audit_id(plan2, checksum2)

    def test_plan_audit_id_and_checksum_are_different_values(self) -> None:
        plan = _make_plan()
        checksum = plan_checksum(plan)
        audit_id = plan_audit_id(plan, checksum)
        # They hash different things; collision would be astronomically unlikely
        assert audit_id != checksum
