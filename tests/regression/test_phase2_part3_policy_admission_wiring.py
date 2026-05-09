"""Regression coverage for Phase 2 Part 3 policy admission wiring."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyDecision, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def _context() -> ExecutionContext:
    return ExecutionContext(
        "phase2-part3-regression",
        datetime(2026, 1, 1, tzinfo=UTC),
        "policy-v1",
    )


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy(max_mps: float) -> Policy:
    return Policy(
        "phase2-part3-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps})],
            )
        ],
    )


def _admission(max_mps: float) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(max_mps),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=fresh_world_snapshot(),
        context=fresh_policy_context(),
    )


def _trusted_kwargs(admission: PolicyAdmissionInput) -> dict[str, object]:
    assert admission.world_snapshot is not None
    return trusted_pipeline_kwargs(admission.world_snapshot)


def test_phase2_part3_policy_allow_still_runs_before_gate_approval() -> None:
    context = _context()
    admission = _admission(1.0)
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.ALLOW
    assert result.gate_decision is not None
    assert result.gate_decision.status == "allowed"


def test_phase2_part3_policy_block_still_prevents_gate_approval() -> None:
    context = _context()
    admission = _admission(0.1)
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK
    assert result.gate_decision is None


def test_phase2_part4_disabled_mode_is_observable_but_not_approved() -> None:
    context = _context()
    result = run_pipeline(_intent(context), context)

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.mode is PolicyAdmissionMode.DISABLED
    assert result.policy_admission.admission_allowed is False
    assert result.policy_admission.policy_result is None
    assert result.gate_decision is None
