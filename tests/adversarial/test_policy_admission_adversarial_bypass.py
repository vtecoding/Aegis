"""Adversarial tests for policy admission bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.contracts.policy_admission import (
    PolicyAdmissionInput,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    is_policy_backed_approval,
)
from aegis.errors import PolicyAdmissionIntegrityError
from aegis.gate import gate_audited_plan
from aegis.pipeline import run_pipeline
from aegis.planning import plan_validated_intent
from aegis.policy import build_safety_case
from aegis.validation import validate_intent


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


def _allowing_policy(policy_id: str = "policy-adversarial") -> Policy:
    return Policy(
        policy_id,
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 2.0})],
            )
        ],
    )


def _capability() -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": 1.0})


def _audited_plan(request_id: str = "policy-adversarial-001"):
    context = ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    validation_result = validate_intent(_intent(context))
    plan = plan_validated_intent(validation_result)
    return build_audited_plan(plan)


def _allow_result(policy_id: str = "policy-adversarial") -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        PolicyDecision.ALLOW,
        policy_id,
        ["rule-1"],
        ["rule-1:0:max_velocity"],
        [],
        ["POLICY_ALLOWED"],
    )


def _allowed_record(
    *,
    audited_plan,
    policy_result: PolicyEvaluationResult | None = None,
    world_snapshot: WorldSnapshotStub | None = None,
) -> PolicyAdmissionRecord:
    result = policy_result or _allow_result()
    safety_case = build_safety_case(
        policy_result=result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=world_snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
    )
    return PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
    )


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


def test_forged_admission_missing_safety_case_is_rejected() -> None:
    audited_plan = _audited_plan()
    result = _allow_result()

    with pytest.raises(ValueError, match="safety_case"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=None,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id=audited_plan.audit_id,
            plan_id=audited_plan.plan.plan_id,
            plan_checksum=audited_plan.checksum,
            capability_name="locomotion.translation",
            capability_version="v1",
        )


def test_stale_safety_case_reuse_fails_integrity() -> None:
    first_plan = _audited_plan("policy-adversarial-a")
    second_plan = _audited_plan("policy-adversarial-b")
    record = _allowed_record(audited_plan=first_plan)

    with pytest.raises(PolicyAdmissionIntegrityError):
        assert_policy_admission_integrity(second_plan, record)


def test_audit_id_plan_id_and_checksum_mismatches_fail_integrity() -> None:
    audited_plan = _audited_plan()

    for field_name, value in (
        ("audit_id", "tampered-audit"),
        ("plan_id", "tampered-plan"),
        ("plan_checksum", "tampered-checksum"),
    ):
        forged = _allowed_record(audited_plan=audited_plan)
        object.__setattr__(forged, field_name, value)
        with pytest.raises(PolicyAdmissionIntegrityError):
            assert_policy_admission_integrity(audited_plan, forged)


def test_policy_swap_and_evaluation_swap_are_rejected() -> None:
    audited_plan = _audited_plan()
    first_result = _allow_result("policy-a")
    second_result = _allow_result("policy-b")
    safety_case = build_safety_case(
        policy_result=first_result,
        audited_plan_id=audited_plan.audit_id,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
    )

    with pytest.raises(ValueError, match="explain"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=second_result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id=audited_plan.audit_id,
            plan_id=audited_plan.plan.plan_id,
            plan_checksum=audited_plan.checksum,
            capability_name="locomotion.translation",
            capability_version="v1",
        )

    record = _allowed_record(audited_plan=audited_plan)
    object.__setattr__(record, "policy_result_checksum", "tampered-result")
    with pytest.raises(PolicyAdmissionIntegrityError):
        assert_policy_admission_integrity(audited_plan, record)


def test_world_snapshot_swap_is_rejected() -> None:
    audited_plan = _audited_plan()
    snapshot = WorldSnapshotStub("snapshot-a", 0, 10, "fixture", 1.0, checksum="checksum-a")
    record = _allowed_record(audited_plan=audited_plan, world_snapshot=snapshot)
    object.__setattr__(record, "world_snapshot_id", "snapshot-b")

    with pytest.raises(PolicyAdmissionIntegrityError):
        assert_policy_admission_integrity(audited_plan, record)


def test_unknown_and_confusable_decision_values_fail_closed() -> None:
    audited_plan = _audited_plan()
    record = _allowed_record(audited_plan=audited_plan)
    object.__setattr__(record, "admission_decision", "ALLOW")

    with pytest.raises(PolicyAdmissionIntegrityError):
        assert_policy_admission_integrity(audited_plan, record)

    for value in ("ALLOW\u200b", "allow", "ALLOW ", "\uff21\uff2c\uff2c\uff2f\uff37"):
        with pytest.raises(ValueError):
            PolicyEvaluationResult(value, "policy-1", ["rule-1"], ["c"], [], ["POLICY_ALLOWED"])


def test_direct_gate_approval_is_not_policy_backed_approval() -> None:
    audited_plan = _audited_plan()
    decision = gate_audited_plan(audited_plan)

    assert decision.status == "allowed"
    assert not is_policy_backed_approval(audited_plan, None, decision)


def test_monkeypatched_evaluator_returning_malformed_result_fails_closed() -> None:
    context = _context()
    with patch("aegis.pipeline.orchestrator.evaluate_policy", return_value=object()):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allowing_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None


def test_monkeypatched_safety_case_builder_missing_case_fails_closed() -> None:
    context = _context()
    with patch("aegis.pipeline.orchestrator.build_safety_case", return_value=None):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allowing_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert "POLICY_ADMISSION_RECORD_FAILED" in result.policy_admission.reasons


def test_monkeypatched_integrity_check_exception_fails_closed() -> None:
    context = _context()
    integrity_error = PolicyAdmissionIntegrityError(
        "forced integrity failure",
        "policy",
        {"reason": "test"},
    )
    with patch(
        "aegis.pipeline.orchestrator.assert_policy_admission_integrity",
        side_effect=integrity_error,
    ):
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_allowing_policy(),
                capability=_capability(),
            ),
        )

    assert result.outcome is PipelineOutcome.ERROR
    assert result.gate_decision is None
    assert "POLICY_ADMISSION_INTEGRITY_FAILED" in result.policy_admission.reasons
