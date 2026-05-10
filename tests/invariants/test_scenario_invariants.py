"""Scenario runner invariants for ADR-0013."""

from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions
from aegis.scenarios.aegis_runner import run_pipeline_scenario, run_scenario_suite


def test_invariant_canonical_suite_result_is_deterministic() -> None:
    scenarios = canonical_scenario_definitions()

    first = run_scenario_suite("canonical-repeat", scenarios)
    second = run_scenario_suite("canonical-repeat", scenarios)

    assert first == second
    assert first.suite_checksum == second.suite_checksum


def test_invariant_each_scenario_result_checksum_is_deterministic() -> None:
    for scenario in canonical_scenario_definitions():
        first = run_pipeline_scenario(scenario)
        second = run_pipeline_scenario(scenario)

        assert first.pipeline_result_checksum == second.pipeline_result_checksum
        assert first.scenario_result_checksum == second.scenario_result_checksum


def test_invariant_allowed_scenario_implies_valid_full_receipt() -> None:
    result = run_pipeline_scenario(_scenario(ScenarioCategory.POSITIVE_ALLOWED))

    assert result.actual_outcome is PipelineOutcome.ALLOWED
    assert result.receipt_valid is True
    assert result.trace_valid is True
    assert result.terminal_stage == "gate_decision"


def test_invariant_duplicate_scenario_ids_are_rejected() -> None:
    scenario = canonical_scenario_definitions()[0]

    with pytest.raises(ValueError, match="duplicate scenario_id"):
        run_scenario_suite("duplicate-invariant", (scenario, replace(scenario, name="Duplicate")))


def _scenario(category: ScenarioCategory):
    return next(
        scenario for scenario in canonical_scenario_definitions() if scenario.category is category
    )
