"""Coverage gate tests for ADR-0013 scenarios."""

from __future__ import annotations

from aegis.scenarios.aegis_contracts import REQUIRED_SCENARIO_CATEGORIES, ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_coverage_gate_passes_for_canonical_matrix() -> None:
    scenarios = canonical_scenario_definitions()
    result = evaluate_scenario_coverage(scenarios)

    assert result.passed is True
    assert result.required_categories == REQUIRED_SCENARIO_CATEGORIES
    assert result.missing_categories == ()
    assert set(result.covered_categories) == set(REQUIRED_SCENARIO_CATEGORIES)
    assert all(count >= 1 for count in result.category_counts.values())


def test_coverage_gate_fails_when_required_category_is_missing() -> None:
    scenarios = tuple(
        scenario
        for scenario in canonical_scenario_definitions()
        if scenario.category is not ScenarioCategory.REPLAYED_RECEIPT
    )

    result = evaluate_scenario_coverage(scenarios)

    assert result.passed is False
    assert result.missing_categories == (ScenarioCategory.REPLAYED_RECEIPT,)
    assert result.category_counts[ScenarioCategory.REPLAYED_RECEIPT] == 0


def test_coverage_checksum_is_deterministic() -> None:
    scenarios = canonical_scenario_definitions()

    first = evaluate_scenario_coverage(scenarios)
    second = evaluate_scenario_coverage(scenarios)

    assert first.coverage_checksum == second.coverage_checksum
