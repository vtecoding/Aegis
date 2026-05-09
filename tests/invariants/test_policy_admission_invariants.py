"""Phase 2 Part 4 invariants for policy-backed pipeline approval."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st
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
from aegis.contracts.policy_admission import (
    PolicyAdmissionInput,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    assert_policy_admission_integrity,
)
from aegis.pipeline import run_pipeline

_COMMANDS = ("move", "stop", "inspect", "wait", "unsupported")
_CASES = ("allow", "block", "review", "missing_policy", "missing_capability", "disabled")


def _context() -> ExecutionContext:
    return ExecutionContext(
        "policy-hardening-invariant",
        datetime(2026, 1, 1, tzinfo=UTC),
        "policy-v1",
    )


def _intent(command: str, priority: int, context: ExecutionContext) -> RawIntent:
    parameters: dict[str, object] = {}
    if command == "move":
        parameters = {"target": {"x": 0, "y": 0}}
    if command == "wait":
        parameters = {"duration_ms": 200}
    if command == "inspect":
        parameters = {"target": "front_sensor"}
    return RawIntent(command, parameters, "policy-hardening-invariant", priority, context)


def _policy(max_mps: float, *, required: bool = True) -> Policy:
    return Policy(
        "policy-hardening-invariant",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": max_mps}, required=required)],
            )
        ],
    )


def _capability(velocity_mps: float = 0.2) -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def _admission(case: str) -> PolicyAdmissionInput | None:
    if case == "allow":
        return PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(1.0),
            capability=_capability(),
            world_snapshot=fresh_world_snapshot(),
            context=fresh_policy_context(),
        )
    if case == "block":
        return PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(0.1),
            capability=_capability(),
            world_snapshot=fresh_world_snapshot(),
            context=fresh_policy_context(),
        )
    if case == "review":
        return PolicyAdmissionInput(
            PolicyAdmissionMode.ENFORCE,
            policy=_policy(0.1, required=False),
            capability=_capability(),
            world_snapshot=fresh_world_snapshot(),
            context=fresh_policy_context(),
        )
    if case == "missing_policy":
        return PolicyAdmissionInput(PolicyAdmissionMode.ENFORCE, capability=_capability())
    if case == "missing_capability":
        return PolicyAdmissionInput(PolicyAdmissionMode.ENFORCE, policy=_policy(1.0))
    return None


@given(st.sampled_from(_COMMANDS), st.integers(min_value=1, max_value=10), st.sampled_from(_CASES))
@settings(max_examples=120)
def test_invariant_allowed_implies_valid_policy_backed_approval(
    command: str,
    priority: int,
    case: str,
) -> None:
    context = _context()
    admission = _admission(case)
    trust_kwargs = (
        trusted_pipeline_kwargs(admission.world_snapshot)
        if admission is not None and admission.world_snapshot is not None
        else {}
    )
    result = run_pipeline(
        _intent(command, priority, context),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trust_kwargs,
    )

    if result.outcome is not PipelineOutcome.ALLOWED:
        assert result.gate_decision is None or result.gate_decision.status != "allowed"
        return

    assert result.audited_plan is not None
    assert result.gate_decision is not None
    assert result.gate_decision.status == "allowed"
    assert result.gate_decision.audit_id == result.audited_plan.audit_id
    assert result.gate_decision.plan_id == result.audited_plan.plan.plan_id

    admission = result.policy_admission
    assert admission.mode is PolicyAdmissionMode.ENFORCE
    assert admission.enforced is True
    assert admission.admission_allowed is True
    assert admission.integrity_status is PolicyAdmissionIntegrityStatus.PASSED
    assert admission.exception_reason is None

    assert admission.policy_result is not None
    assert admission.policy_result.decision is PolicyDecision.ALLOW
    assert admission.policy_result.failed_constraints == ()
    assert admission.policy_result.freshness_status == "FRESH"
    assert admission.policy_result.freshness_result_checksum is not None
    assert admission.policy_result.world_snapshot_trust_status == "TRUSTED"
    assert admission.policy_result.world_snapshot_trust_result_checksum is not None

    assert admission.safety_case is not None
    assert admission.safety_case.audited_plan_id == result.audited_plan.audit_id
    assert admission.safety_case.plan_id == result.audited_plan.plan.plan_id
    assert admission.safety_case.plan_checksum == result.audited_plan.checksum
    assert admission.safety_case.freshness_status == "FRESH"
    assert admission.safety_case.freshness_result_checksum == (
        admission.policy_result.freshness_result_checksum
    )
    assert admission.safety_case.world_snapshot_trust_status == "TRUSTED"
    assert admission.safety_case.world_snapshot_trust_result_checksum == (
        admission.policy_result.world_snapshot_trust_result_checksum
    )
    assert admission.audit_id == result.audited_plan.audit_id
    assert admission.plan_id == result.audited_plan.plan.plan_id
    assert admission.plan_checksum == result.audited_plan.checksum
    assert admission.freshness_status == "FRESH"
    assert admission.world_snapshot_trust_status == "TRUSTED"
    assert admission.freshness_result_checksum == admission.policy_result.freshness_result_checksum
    assert admission.world_snapshot_observed_at_ms == (
        admission.policy_result.world_snapshot_observed_at_ms
    )
    assert admission.reasons.count("POLICY_ALLOWED") == 1

    integrity = assert_policy_admission_integrity(result.audited_plan, admission)
    assert integrity.status is PolicyAdmissionIntegrityStatus.PASSED
