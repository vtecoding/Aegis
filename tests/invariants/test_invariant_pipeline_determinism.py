"""Invariant tests: run_pipeline is deterministic and respects pipeline-v1 invariants."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.pipeline import run_pipeline

_VALID_COMMANDS = ["stop", "wait", "inspect", "move"]
_INVALID_COMMANDS = ["launch", "explode", "STOP", "override_safety"]


def make_context() -> ExecutionContext:
    return ExecutionContext("inv-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _make_intent(command: str, context: ExecutionContext) -> RawIntent:
    params: dict = {}
    if command == "move":
        params = {"target": {"x": 0, "y": 0}}
    elif command == "wait":
        params = {"duration_ms": 200}
    elif command == "inspect":
        params = {"target": "front_sensor"}
    return RawIntent(
        command=command,
        parameters=params,
        source_id="invariant-test",
        priority=5,
        context=context,
    )


# ---------------------------------------------------------------------------
# Determinism invariants
# ---------------------------------------------------------------------------


@given(
    st.sampled_from(_VALID_COMMANDS),
    st.integers(min_value=1, max_value=10),
)
@settings(max_examples=40)
def test_invariant_pipeline_is_deterministic_for_valid_commands(
    command: str, priority: int
) -> None:
    """Same valid intent + context always produces the same PipelineResult."""
    context = make_context()
    params: dict = {}
    if command == "move":
        params = {"target": {"x": 0, "y": 0}}
    elif command == "wait":
        params = {"duration_ms": 200}
    elif command == "inspect":
        params = {"target": "front_sensor"}

    intent = RawIntent(
        command=command,
        parameters=params,
        source_id="inv-src",
        priority=priority,
        context=context,
    )
    result_a = run_pipeline(intent, context)
    result_b = run_pipeline(intent, context)
    assert result_a == result_b


@given(st.sampled_from(_INVALID_COMMANDS))
@settings(max_examples=30)
def test_invariant_pipeline_is_deterministic_for_invalid_commands(command: str) -> None:
    """Same invalid intent + context always produces the same INVALID result."""
    context = make_context()
    intent = RawIntent(
        command=command,
        parameters={},
        source_id="inv-src",
        priority=5,
        context=context,
    )
    result_a = run_pipeline(intent, context)
    result_b = run_pipeline(intent, context)
    assert result_a == result_b
    assert result_a.outcome == PipelineOutcome.INVALID


# ---------------------------------------------------------------------------
# Outcome invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", _VALID_COMMANDS)
def test_invariant_valid_commands_without_policy_never_approve(command: str) -> None:
    """Supported commands without policy admission must not produce ALLOWED."""
    context = make_context()
    intent = _make_intent(command, context)
    result = run_pipeline(intent, context)
    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.gate_decision is None


@pytest.mark.parametrize("command", _INVALID_COMMANDS)
def test_invariant_invalid_commands_always_produce_invalid(command: str) -> None:
    """Every unsupported command must produce INVALID."""
    context = make_context()
    intent = _make_intent(command, context)
    result = run_pipeline(intent, context)
    assert result.outcome == PipelineOutcome.INVALID


def test_invariant_disabled_blocked_still_populates_plan_and_audit() -> None:
    """Disabled policy mode blocks after audit while preserving observability."""
    context = make_context()
    intent = _make_intent("stop", context)
    result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.validation_result is not None
    assert result.plan is not None
    assert result.audited_plan is not None
    assert result.gate_decision is None


def test_invariant_invalid_implies_plan_and_gate_are_none() -> None:
    """INVALID outcome must never have plan, audited_plan, or gate_decision."""
    context = make_context()
    intent = _make_intent("launch", context)
    result = run_pipeline(intent, context)

    assert result.outcome == PipelineOutcome.INVALID
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_invariant_pipeline_does_not_mutate_intent() -> None:
    """run_pipeline must not mutate the raw_intent argument."""
    context = make_context()
    intent = _make_intent("stop", context)
    original_command = intent.command

    run_pipeline(intent, context)

    assert intent.command == original_command
