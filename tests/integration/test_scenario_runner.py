"""Integration tests: scenario runner runs all JSON fixtures end-to-end."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.contracts.aegis_context import ExecutionContext
from aegis.scenarios.aegis_models import ScenarioExpected, ScenarioFixture, ScenarioIntentFixture
from aegis.scenarios.aegis_runner import parse_scenario_fixture, run_scenario, run_scenarios

_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"


def make_context() -> ExecutionContext:
    """Return a deterministic execution context for integration tests."""
    return ExecutionContext("scenario-test-001", datetime(2026, 5, 1, tzinfo=UTC), "policy-v1")


def _load_all_fixtures() -> list[ScenarioFixture]:
    """Load and parse all JSON fixtures from the scenarios directory."""
    return [
        parse_scenario_fixture(json.loads(p.read_text(encoding="utf-8")))
        for p in sorted(_FIXTURES_DIR.glob("*.json"))
    ]


# ---------------------------------------------------------------------------
# Release gate
# ---------------------------------------------------------------------------


def test_all_fixture_scenarios_pass() -> None:
    """Every JSON scenario fixture must pass its own expectations."""
    fixtures = _load_all_fixtures()
    context = make_context()
    results, _ = run_scenarios(fixtures, context)

    failed = [r for r in results if r.status != "passed"]
    assert failed == [], f"Scenarios failed: {[r.scenario for r in failed]}"


def test_release_gate_metadata_leak_count_is_zero() -> None:
    fixtures = _load_all_fixtures()
    _, metrics = run_scenarios(fixtures, make_context())
    assert metrics.metadata_leak_count == 0


def test_release_gate_unexpected_exception_count_is_zero() -> None:
    fixtures = _load_all_fixtures()
    _, metrics = run_scenarios(fixtures, make_context())
    assert metrics.unexpected_exception_count == 0


def test_release_gate_deterministic_replay_failures_is_zero() -> None:
    fixtures = _load_all_fixtures()
    _, metrics = run_scenarios(fixtures, make_context())
    assert metrics.deterministic_replay_failures == 0


def test_release_gate_gate_integrity_mismatch_count_is_zero() -> None:
    """The gate must never report checksum or audit-id mismatches for legitimate plans."""
    fixtures = _load_all_fixtures()
    _, metrics = run_scenarios(fixtures, make_context())
    assert metrics.gate_integrity_mismatch_count == 0


# ---------------------------------------------------------------------------
# Safety invariants
# ---------------------------------------------------------------------------


def test_invalid_intents_are_never_planned() -> None:
    """Intents that fail validation must never reach the planning layer."""
    fixtures = _load_all_fixtures()
    results, _ = run_scenarios(fixtures, make_context())
    for result in results:
        if result.validation == "invalid":
            assert not result.planned, f"Invalid intent was planned: {result.scenario}"
        if result.validation == "error":
            assert not result.planned, f"Boundary-rejected intent was planned: {result.scenario}"


def test_valid_intents_produce_audit_receipts() -> None:
    """Intents that validate and plan must always produce an audit receipt."""
    fixtures = _load_all_fixtures()
    results, _ = run_scenarios(fixtures, make_context())
    for result in results:
        if result.planned:
            assert result.audited, f"Planned intent not audited: {result.scenario}"
            assert result.audit is not None
            assert result.audit.checksum != ""
            assert result.audit.audit_id != ""


def test_valid_intents_are_gate_allowed() -> None:
    """Intents that pass audit must be allowed by the gate."""
    fixtures = _load_all_fixtures()
    results, _ = run_scenarios(fixtures, make_context())
    for result in results:
        if result.audited:
            assert result.gate_status == "allowed", (
                f"Audited intent not gate-allowed: {result.scenario} "
                f"(gate_status={result.gate_status!r})"
            )


# ---------------------------------------------------------------------------
# Metric consistency
# ---------------------------------------------------------------------------


def test_metrics_counts_match_results() -> None:
    """Aggregate metrics must be consistent with the individual results."""
    fixtures = _load_all_fixtures()
    results, metrics = run_scenarios(fixtures, make_context())

    assert metrics.scenario_count == len(fixtures)
    assert metrics.valid_count == sum(1 for r in results if r.validation == "valid")
    assert metrics.invalid_count == sum(1 for r in results if r.validation == "invalid")
    assert metrics.planned_count == sum(1 for r in results if r.planned)
    assert metrics.audit_created_count == sum(1 for r in results if r.audited)
    assert metrics.gate_allowed_count == sum(1 for r in results if r.gate_status == "allowed")
    assert metrics.gate_blocked_count == sum(1 for r in results if r.gate_status == "blocked")
    assert metrics.gate_integrity_mismatch_count == sum(
        1 for r in results if r.gate_integrity_mismatch
    )


def test_fixture_count_matches_expected() -> None:
    """There must be exactly six fixture files."""
    fixtures = _load_all_fixtures()
    assert len(fixtures) == 6


# ---------------------------------------------------------------------------
# Hostile metadata scenario (the key demo)
# ---------------------------------------------------------------------------


def test_hostile_metadata_scenario_passes() -> None:
    context = make_context()
    fixture = parse_scenario_fixture(
        json.loads(
            (_FIXTURES_DIR / "llm_valid_move_with_hostile_metadata.json").read_text(
                encoding="utf-8"
            )
        )
    )
    result = run_scenario(fixture, context)

    assert result.status == "passed"
    assert result.validation == "valid"
    assert result.planned is True
    assert result.audited is True
    assert result.violations == ()
    assert result.failure_reason is None


def test_hostile_metadata_is_absent_from_plan_step() -> None:
    """The 'metadata' key from the LLM intent must not appear in the plan step."""
    context = make_context()
    fixture = parse_scenario_fixture(
        json.loads(
            (_FIXTURES_DIR / "llm_valid_move_with_hostile_metadata.json").read_text(
                encoding="utf-8"
            )
        )
    )
    result = run_scenario(fixture, context)

    assert result.plan_step is not None
    assert "metadata" not in result.plan_step.parameters, (
        "Hostile 'metadata' key leaked into plan step"
    )

    # The target must only contain x and y.
    target = result.plan_step.parameters.get("target")
    assert isinstance(target, Mapping)
    assert "metadata" not in target, "Hostile 'metadata' key survived inside target"
    assert "x" in target
    assert "y" in target


def test_hostile_metadata_audit_is_deterministic() -> None:
    """The audit receipt for the hostile metadata scenario must be stable."""
    context = make_context()
    fixture = parse_scenario_fixture(
        json.loads(
            (_FIXTURES_DIR / "llm_valid_move_with_hostile_metadata.json").read_text(
                encoding="utf-8"
            )
        )
    )
    result_a = run_scenario(fixture, context)
    result_b = run_scenario(fixture, context)

    assert result_a.audit is not None
    assert result_b.audit is not None
    assert result_a.audit.checksum == result_b.audit.checksum
    assert result_a.audit.audit_id == result_b.audit.audit_id


# ---------------------------------------------------------------------------
# parse_scenario_fixture validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_data",
    [
        [],
        "string",
        42,
        None,
        {},
        {"name": "x"},
        {"name": "x", "intent": {}},
        {
            "name": "x",
            "intent": {"command": "stop", "parameters": {}, "source_id": "s"},
            "expected": {},
        },
    ],
)
def test_parse_scenario_fixture_rejects_incomplete_data(bad_data: object) -> None:
    with pytest.raises(ValueError):
        parse_scenario_fixture(bad_data)


def test_parse_scenario_fixture_rejects_non_integer_priority() -> None:
    with pytest.raises(ValueError, match="priority"):
        parse_scenario_fixture(
            {
                "name": "bad",
                "intent": {
                    "command": "stop",
                    "parameters": {},
                    "source_id": "src",
                    "priority": "five",
                },
                "expected": {
                    "validation": "valid",
                    "planning": "valid",
                    "metadata_dropped": False,
                    "audit_created": True,
                },
            }
        )


def test_parse_scenario_fixture_rejects_bool_priority() -> None:
    with pytest.raises(ValueError, match="priority"):
        parse_scenario_fixture(
            {
                "name": "bad",
                "intent": {
                    "command": "stop",
                    "parameters": {},
                    "source_id": "src",
                    "priority": True,
                },
                "expected": {
                    "validation": "valid",
                    "planning": "valid",
                    "metadata_dropped": False,
                    "audit_created": True,
                },
            }
        )


# ---------------------------------------------------------------------------
# Inline fixture construction (no JSON files)
# ---------------------------------------------------------------------------


def test_run_scenario_with_inline_valid_stop() -> None:
    fixture = ScenarioFixture(
        name="inline_stop",
        intent=ScenarioIntentFixture(command="stop", parameters={}, source_id="test", priority=5),
        expected=ScenarioExpected(
            validation="valid", planning="valid", metadata_dropped=False, audit_created=True
        ),
    )
    result = run_scenario(fixture, make_context())
    assert result.status == "passed"
    assert result.planned is True
    assert result.audited is True


def test_run_scenario_with_inline_invalid_command() -> None:
    fixture = ScenarioFixture(
        name="inline_bad",
        intent=ScenarioIntentFixture(
            command="explode", parameters={}, source_id="test", priority=5
        ),
        expected=ScenarioExpected(
            validation="invalid", planning="skipped", metadata_dropped=False, audit_created=False
        ),
    )
    result = run_scenario(fixture, make_context())
    assert result.status == "passed"
    assert result.validation == "invalid"
    assert not result.planned


def test_run_scenarios_empty_list_produces_zero_metrics() -> None:
    _, metrics = run_scenarios([], make_context())
    assert metrics.scenario_count == 0
    assert metrics.valid_count == 0
    assert metrics.invalid_count == 0
    assert metrics.metadata_leak_count == 0
    assert metrics.unexpected_exception_count == 0
    assert metrics.deterministic_replay_failures == 0
    assert metrics.gate_allowed_count == 0
    assert metrics.gate_blocked_count == 0
    assert metrics.gate_integrity_mismatch_count == 0
