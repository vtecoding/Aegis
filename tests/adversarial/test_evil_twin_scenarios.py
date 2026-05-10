"""Adversarial scenario tests for forged and replayed pipeline evidence."""

from __future__ import annotations

import pytest

from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions
from aegis.scenarios.aegis_runner import run_pipeline_scenario


@pytest.mark.parametrize(
    "category",
    [
        ScenarioCategory.SAFETY_CASE_FORGED,
        ScenarioCategory.ADMISSION_MISMATCH,
        ScenarioCategory.RECEIPT_FORGED,
        ScenarioCategory.REPLAYED_RECEIPT,
        ScenarioCategory.CHECKSUM_MISMATCH,
        ScenarioCategory.CONFUSABLE_STAGE_NAME,
        ScenarioCategory.PARTIAL_RECEIPT_OVERCLAIM,
    ],
)
def test_evil_twin_receipt_or_trace_scenarios_fail_closed(category: ScenarioCategory) -> None:
    result = run_pipeline_scenario(_scenario(category))

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.ERROR
    assert result.actual_reason == "APPROVAL_RECEIPT_INTEGRITY_FAILED"
    assert result.terminal_stage == "receipt_validation"
    assert result.receipt_valid is False
    assert not result.violations


def test_direct_gate_bypass_is_not_full_pipeline_approval() -> None:
    result = run_pipeline_scenario(_scenario(ScenarioCategory.DIRECT_GATE_BYPASS))

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.BLOCKED
    assert result.actual_reason == "DIRECT_GATE_BYPASS_REJECTED"
    assert result.terminal_stage == "direct_gate"
    assert result.receipt_valid is True
    assert "gate_decision" not in result.stage_path


def _scenario(category: ScenarioCategory):
    return next(
        scenario for scenario in canonical_scenario_definitions() if scenario.category is category
    )
