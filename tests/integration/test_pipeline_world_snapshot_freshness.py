"""Integration tests for Phase 2 Part 5 pipeline freshness enforcement."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    FRESH_OBSERVED_AT_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline

_DEFAULT_SNAPSHOT = object()


def _context(request_id: str = "pipeline-freshness") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy(max_mps: float = 1.0) -> Policy:
    return Policy(
        "pipeline-freshness-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps})],
            )
        ],
    )


def _admission(*, world_snapshot: object = _DEFAULT_SNAPSHOT) -> PolicyAdmissionInput:
    snapshot = fresh_world_snapshot() if world_snapshot is _DEFAULT_SNAPSHOT else world_snapshot
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def test_fresh_snapshot_policy_allow_and_gate_allow_produces_allowed() -> None:
    context = _context("pipeline-freshness-allow")
    admission = _admission()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(admission.world_snapshot),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.policy_admission.freshness_status == "FRESH"


def test_stale_snapshot_blocks_before_final_gate() -> None:
    context = _context("pipeline-freshness-stale")
    stale_snapshot = fresh_world_snapshot(observed_at_ms=FRESH_OBSERVED_AT_MS - 2_000)

    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(world_snapshot=stale_snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.freshness_status == "STALE"
    assert "WORLD_SNAPSHOT_STALE" in result.policy_admission.reasons


def test_missing_snapshot_blocks_before_final_gate() -> None:
    context = _context("pipeline-freshness-missing-snapshot")

    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(world_snapshot=None),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.world_snapshot_admissibility_status == "SNAPSHOT_MISSING"


def test_missing_evaluation_time_blocks_before_final_gate() -> None:
    context = _context("pipeline-freshness-missing-eval")

    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(_intent(context), context, policy_admission=_admission())

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.freshness_status == "MISSING_EVALUATION_TIME"


def test_malformed_timestamp_returns_invalid_without_gate() -> None:
    context = _context("pipeline-freshness-malformed")
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "captured_at_ms", "bad")

    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=_admission(world_snapshot=snapshot),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.INVALID
    assert result.policy_admission.freshness_status == "INVALID_TIMESTAMP"


def test_evaluator_exception_after_freshness_pass_returns_error() -> None:
    context = _context("pipeline-freshness-evaluator-error")
    admission = _admission()

    with patch(
        "aegis.pipeline.aegis_orchestrator.evaluate_policy", side_effect=RuntimeError("boom")
    ):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **trusted_pipeline_kwargs(admission.world_snapshot),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert result.policy_admission.freshness_status == "FRESH"


def test_disabled_policy_mode_does_not_become_freshness_backed_approval() -> None:
    context = _context("pipeline-freshness-disabled")
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.admission_allowed is False
    assert result.policy_admission.freshness_status is None
