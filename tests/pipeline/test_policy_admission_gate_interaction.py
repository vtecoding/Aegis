"""Pipeline tests for policy admission and final gate interaction."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def _context() -> ExecutionContext:
    return ExecutionContext("policy-gate-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _capability(velocity_mps: object = 0.2) -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def _policy(max_mps: float, *, required: bool = True) -> Policy:
    return Policy(
        "policy-gate",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps}, required=required)],
            )
        ],
    )


def _blocked_gate_decision() -> GateDecision:
    return GateDecision(
        GateDecisionStatus.BLOCKED,
        audit_id="audit-1",
        plan_id="plan-1",
        reasons=(GateBlockReason.CHECKSUM_MISMATCH,),
        checksum_verified=False,
        audit_id_verified=True,
    )


def _admission(
    policy: Policy, *, evidence: dict[str, object] | None = None
) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=_capability(),
        world_snapshot=fresh_world_snapshot(),
        context=fresh_policy_context(),
        evidence=evidence,
    )


def _trusted_kwargs(admission: PolicyAdmissionInput) -> dict[str, object]:
    assert admission.world_snapshot is not None
    return trusted_pipeline_kwargs(admission.world_snapshot)


def test_policy_allow_and_valid_gate_approves() -> None:
    context = _context()
    admission = _admission(_policy(0.5))
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **_trusted_kwargs(admission),
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.policy_admission.admission_allowed is True
    assert result.gate_decision is not None
    assert result.gate_decision.status is GateDecisionStatus.ALLOWED


def test_policy_allow_does_not_bypass_gate_integrity_failure() -> None:
    context = _context()
    with patch(
        "aegis.pipeline.aegis_orchestrator.gate_audited_plan", return_value=_blocked_gate_decision()
    ):
        admission = _admission(_policy(0.5))
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.admission_allowed is True
    assert result.gate_decision is not None
    assert result.gate_decision.status is GateDecisionStatus.BLOCKED
    assert result.gate_decision.reasons == (GateBlockReason.CHECKSUM_MISMATCH,)


def test_policy_block_prevents_otherwise_valid_gate_from_running() -> None:
    context = _context()
    admission = _admission(_policy(0.1))
    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None


def test_policy_review_prevents_otherwise_valid_gate_from_running() -> None:
    context = _context()
    admission = _admission(_policy(0.1, required=False))
    with patch("aegis.pipeline.aegis_orchestrator.gate_audited_plan") as gate:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    gate.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None


def test_safety_case_evidence_override_gate_cannot_bypass_gate_failure() -> None:
    context = _context()
    with patch(
        "aegis.pipeline.aegis_orchestrator.gate_audited_plan", return_value=_blocked_gate_decision()
    ):
        admission = _admission(_policy(0.5), evidence={"override_gate": True})
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.safety_case is not None
    assert result.policy_admission.safety_case.evidence["override_gate"] is True
    assert result.gate_decision is not None
    assert result.gate_decision.status is GateDecisionStatus.BLOCKED


def test_policy_and_gate_results_are_both_observable_when_gate_blocks() -> None:
    context = _context()
    with patch(
        "aegis.pipeline.aegis_orchestrator.gate_audited_plan", return_value=_blocked_gate_decision()
    ):
        admission = _admission(_policy(0.5))
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=admission,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            **_trusted_kwargs(admission),
        )

    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.safety_case is not None
    assert result.gate_decision is not None
    assert result.gate_decision.reasons == (GateBlockReason.CHECKSUM_MISMATCH,)
