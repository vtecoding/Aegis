"""Tests for ADR-0014 stage and scenario coverage sentinels."""

from __future__ import annotations

from aegis.contracts.aegis_decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.governance.aegis_coverage_sentinel import (
    assert_coverage_sentinel,
    evaluate_coverage_sentinel,
)


def test_coverage_sentinel_passes_for_registered_stage_and_category_sets() -> None:
    result = evaluate_coverage_sentinel()

    assert result.passed
    assert result.errors == ()
    assert_coverage_sentinel()


def test_coverage_sentinel_rejects_stage_registry_drift() -> None:
    drifted_stages = DECISION_TRACE_STAGE_ORDER + ("uncovered_authority_stage",)

    result = evaluate_coverage_sentinel(stage_registry=drifted_stages)

    assert not result.passed
    assert "DECISION_TRACE_STAGE_COVERAGE_DRIFT" in result.errors
