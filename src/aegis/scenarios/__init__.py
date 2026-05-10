"""Scenario runner v1: deterministic proof harness for the Aegis pipeline."""

from aegis.scenarios import aegis_runner as runner
from aegis.scenarios.aegis_contracts import (
    CoverageGateResult,
    EvilTwinMutation,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioExpectation,
    ScenarioRunResult,
    ScenarioSuiteResult,
    ScenarioViolation,
)
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import ScenarioFixtureFactory, canonical_scenario_definitions
from aegis.scenarios.aegis_models import (
    ScenarioAuditSummary,
    ScenarioExpected,
    ScenarioFixture,
    ScenarioIntentFixture,
    ScenarioMetrics,
    ScenarioPlanStep,
    ScenarioResult,
)
from aegis.scenarios.aegis_runner import (
    parse_scenario_fixture,
    run_canonical_scenario_suite,
    run_pipeline_scenario,
    run_scenario,
    run_scenario_suite,
    run_scenarios,
)

__all__ = [
    "CoverageGateResult",
    "EvilTwinMutation",
    "ScenarioCategory",
    "ScenarioDefinition",
    "ScenarioExpectation",
    "ScenarioFixtureFactory",
    "ScenarioAuditSummary",
    "ScenarioExpected",
    "ScenarioFixture",
    "ScenarioIntentFixture",
    "ScenarioMetrics",
    "ScenarioPlanStep",
    "ScenarioRunResult",
    "ScenarioResult",
    "ScenarioSuiteResult",
    "ScenarioViolation",
    "canonical_scenario_definitions",
    "evaluate_scenario_coverage",
    "parse_scenario_fixture",
    "run_canonical_scenario_suite",
    "run_pipeline_scenario",
    "runner",
    "run_scenario",
    "run_scenario_suite",
    "run_scenarios",
]
