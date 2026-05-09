"""Regression: direct gate allow is not a full pipeline approval receipt."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.gate import gate_audited_plan
from aegis.planning import plan_validated_intent
from aegis.validation import validate_intent


def test_direct_gate_allow_cannot_claim_full_pipeline_approval_receipt() -> None:
    context = ExecutionContext(
        "direct-gate-regression",
        datetime(2026, 1, 1, tzinfo=UTC),
        "policy-v1",
    )
    validation_result = validate_intent(
        RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)
    )
    plan = plan_validated_intent(validation_result)
    audited_plan = build_audited_plan(plan)
    gate_decision = gate_audited_plan(audited_plan)

    with pytest.raises(ValueError, match="policy-backed|approval receipt"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=gate_decision,
        )
