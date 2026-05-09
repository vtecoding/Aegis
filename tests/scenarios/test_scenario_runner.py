"""Tests for the ADR-0013 deterministic scenario runner."""

from __future__ import annotations

import pytest

from aegis.contracts.decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.contracts.pipeline import PipelineOutcome
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.fixtures import canonical_scenario_definitions
from aegis.scenarios.runner import run_canonical_scenario_suite, run_pipeline_scenario


def test_canonical_scenario_suite_passes() -> None:
    suite = run_canonical_scenario_suite()

    assert suite.passed is True
    assert suite.total == len(tuple(ScenarioCategory))
    assert suite.passed_count == suite.total
    assert suite.failed_count == 0
    assert suite.coverage.passed is True


def test_positive_allowed_scenario_has_full_valid_receipt_path() -> None:
    scenario = _scenario(ScenarioCategory.POSITIVE_ALLOWED)
    result = run_pipeline_scenario(scenario)

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.ALLOWED
    assert result.actual_reason == "GATE_ALLOWED"
    assert result.terminal_stage == "gate_decision"
    assert result.receipt_valid is True
    assert result.trace_valid is True
    assert result.stage_path == DECISION_TRACE_STAGE_ORDER


@pytest.mark.parametrize(
    ("category", "terminal_stage", "reason"),
    [
        (
            ScenarioCategory.MISSING_WORLD_SNAPSHOT,
            "world_snapshot_admissibility",
            "WORLD_SNAPSHOT_MISSING",
        ),
        (
            ScenarioCategory.INADMISSIBLE_WORLD_SNAPSHOT,
            "world_snapshot_admissibility",
            "WORLD_SNAPSHOT_CHECKSUM_MISSING",
        ),
        (ScenarioCategory.STALE_WORLD_SNAPSHOT, "world_snapshot_freshness", "WORLD_SNAPSHOT_STALE"),
        (
            ScenarioCategory.FUTURE_DATED_WORLD_SNAPSHOT,
            "world_snapshot_freshness",
            "WORLD_SNAPSHOT_FUTURE_DATED",
        ),
        (
            ScenarioCategory.MISSING_EVIDENCE,
            "world_snapshot_trust",
            "WORLD_SNAPSHOT_EVIDENCE_MISSING",
        ),
        (
            ScenarioCategory.INVALID_ATTESTATION,
            "world_snapshot_trust",
            "WORLD_SNAPSHOT_ATTESTATION_INVALID",
        ),
        (
            ScenarioCategory.UNCERTIFIED_VERIFIER,
            "verifier_certification",
            "ATTESTATION_VERIFIER_MISSING",
        ),
        (
            ScenarioCategory.INVALID_TRUST_CONFIG,
            "trust_policy_config",
            "TRUST_POLICY_ATTESTATION_REQUIRED_FALSE_IN_ENFORCE",
        ),
        (
            ScenarioCategory.WRONG_CAPABILITY_SCOPE,
            "world_snapshot_admissibility",
            "WORLD_SNAPSHOT_CAPABILITY_SCOPE_MISMATCH",
        ),
        (ScenarioCategory.POLICY_DENIED, "policy_evaluation", "POLICY_BLOCKED"),
    ],
)
def test_blocked_scenarios_stop_at_expected_terminal_stage(
    category: ScenarioCategory,
    terminal_stage: str,
    reason: str,
) -> None:
    result = run_pipeline_scenario(_scenario(category))

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.BLOCKED
    assert result.terminal_stage == terminal_stage
    assert result.actual_reason == reason
    assert result.receipt_valid is True
    assert "gate_decision" not in result.stage_path


def _scenario(category: ScenarioCategory):
    return next(
        scenario for scenario in canonical_scenario_definitions() if scenario.category is category
    )
