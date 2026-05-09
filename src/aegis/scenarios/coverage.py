"""Coverage gate for deterministic scenario suites."""

from __future__ import annotations

from collections.abc import Iterable

from aegis.scenarios.contracts import (
    REQUIRED_SCENARIO_CATEGORIES,
    CoverageGateResult,
    ScenarioCategory,
    ScenarioDefinition,
    coverage_gate_checksum,
)


def evaluate_scenario_coverage(
    scenarios: Iterable[ScenarioDefinition],
    *,
    required_categories: tuple[ScenarioCategory, ...] = REQUIRED_SCENARIO_CATEGORIES,
) -> CoverageGateResult:
    """Evaluate whether a scenario collection covers every required category.

    Args:
        scenarios: Scenario definitions to count.
        required_categories: Categories that must be represented at least once.

    Returns:
        A deterministic coverage result with a checksum over the category matrix.
    """
    counts: dict[ScenarioCategory, int] = {category: 0 for category in required_categories}
    for scenario in tuple(scenarios):
        counts[scenario.category] = counts.get(scenario.category, 0) + 1

    covered = tuple(category for category in required_categories if counts.get(category, 0) > 0)
    missing = tuple(category for category in required_categories if counts.get(category, 0) == 0)
    passed = not missing
    checksum = coverage_gate_checksum(
        passed=passed,
        required_categories=required_categories,
        covered_categories=covered,
        missing_categories=missing,
        category_counts=counts,
    )
    return CoverageGateResult(
        passed=passed,
        required_categories=required_categories,
        covered_categories=covered,
        missing_categories=missing,
        category_counts=counts,
        coverage_checksum=checksum,
    )


__all__ = ["evaluate_scenario_coverage"]
