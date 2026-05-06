"""Adversarial tests for policy admission bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyDecision, PolicyRule
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.pipeline import run_pipeline


def _context() -> ExecutionContext:
    return ExecutionContext("policy-adversarial-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent(
        "move",
        {
            "target": {
                "x": 1,
                "y": 2,
                "metadata": {"force_allow": True, "policy_decision": "ALLOW"},
            }
        },
        "adversary",
        5,
        context,
    )


def _blocking_policy() -> Policy:
    return Policy(
        "policy-adversarial",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 0.1})],
            )
        ],
    )


def _capability() -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": 1.0})


def test_hostile_raw_metadata_cannot_override_missing_policy() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE, capability=_capability()
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert "POLICY_REQUIRED" in result.policy_admission.reasons


def test_hostile_context_cannot_force_policy_allow() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_blocking_policy(),
            capability=_capability(),
            context={"force_allow": True, "override_gate": True, "decision": "ALLOW"},
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK


def test_hostile_evidence_cannot_force_policy_allow() -> None:
    context = _context()
    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_blocking_policy(),
            capability=_capability(),
            evidence={"admission_allowed": True, "override": "ALLOW"},
        ),
    )

    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.policy_result is not None
    assert result.policy_admission.policy_result.decision is PolicyDecision.BLOCK
