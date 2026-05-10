"""Integration tests binding pipeline receipts to scenario expectations."""

from __future__ import annotations

from aegis.contracts.aegis_decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions
from aegis.scenarios.aegis_runner import run_pipeline_scenario


def test_allowed_scenario_receipt_proves_full_path() -> None:
    result = run_pipeline_scenario(_scenario(ScenarioCategory.POSITIVE_ALLOWED))

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.ALLOWED
    assert result.stage_path == DECISION_TRACE_STAGE_ORDER
    assert result.receipt_valid is True
    assert result.trace_valid is True


def test_blocked_trust_scenario_receipt_has_no_late_approval_claims() -> None:
    result = run_pipeline_scenario(_scenario(ScenarioCategory.MISSING_EVIDENCE))

    assert result.passed is True
    assert result.actual_outcome is PipelineOutcome.BLOCKED
    assert result.terminal_stage == "world_snapshot_trust"
    assert "policy_evaluation" not in result.stage_path
    assert "safety_case" not in result.stage_path
    assert "gate_decision" not in result.stage_path


def test_allowed_and_blocked_scenario_checksums_are_stable() -> None:
    allowed = _scenario(ScenarioCategory.POSITIVE_ALLOWED)
    blocked = _scenario(ScenarioCategory.MISSING_EVIDENCE)

    allowed_first = run_pipeline_scenario(allowed)
    allowed_second = run_pipeline_scenario(allowed)
    blocked_first = run_pipeline_scenario(blocked)
    blocked_second = run_pipeline_scenario(blocked)

    assert allowed_first.pipeline_result_checksum == allowed_second.pipeline_result_checksum
    assert allowed_first.scenario_result_checksum == allowed_second.scenario_result_checksum
    assert blocked_first.pipeline_result_checksum == blocked_second.pipeline_result_checksum
    assert blocked_first.scenario_result_checksum == blocked_second.scenario_result_checksum


def _scenario(category: ScenarioCategory):
    return next(
        scenario for scenario in canonical_scenario_definitions() if scenario.category is category
    )
