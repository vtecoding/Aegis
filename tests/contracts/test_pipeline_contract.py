"""Contract tests: PipelineResult and PipelineOutcome conform to their typed contracts."""

from __future__ import annotations

import pytest
from tests.policy_freshness_fixtures import (
    bind_policy_result_to_freshness,
    fresh_world_snapshot,
    fresh_world_snapshot_result,
)
from tests.policy_trust_fixtures import bind_policy_result_to_trust, trusted_world_snapshot_result

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.planning import CommandPlan
from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
)
from aegis.contracts.policy_admission import PolicyAdmissionMode, PolicyAdmissionRecord
from aegis.contracts.validation import ValidationResult, Violation
from aegis.contracts.world_snapshot_trust import WorldSnapshotTrustResult
from aegis.governance.context_authority import ContextAuthority
from aegis.pipeline.approval_receipt import build_approval_receipt, validate_approval_receipt
from aegis.pipeline.decision_trace import build_decision_trace
from aegis.policy import build_safety_case

# ---------------------------------------------------------------------------
# PipelineOutcome
# ---------------------------------------------------------------------------


def test_pipeline_outcome_values_are_stable() -> None:
    assert PipelineOutcome.ALLOWED == "allowed"
    assert PipelineOutcome.BLOCKED == "blocked"
    assert PipelineOutcome.INVALID == "invalid"
    assert PipelineOutcome.ERROR == "error"


def test_pipeline_outcome_is_str_enum() -> None:
    assert isinstance(PipelineOutcome.ALLOWED, str)


# ---------------------------------------------------------------------------
# PipelineResult — ALLOWED
# ---------------------------------------------------------------------------


def _make_allowed_result(
    validation_result: ValidationResult,
    plan: CommandPlan,
    audited_plan: AuditedPlan,
    gate_decision: GateDecision,
) -> PipelineResult:
    policy_record = _allowed_policy_record(audited_plan)
    decision_trace = build_decision_trace(
        raw_intent=validation_result.intent,
        context=validation_result.intent.context,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=gate_decision,
        policy_admission=policy_record,
    )
    approval_receipt = build_approval_receipt(
        pipeline_outcome=PipelineOutcome.ALLOWED.value,
        raw_intent=validation_result.intent,
        decision_trace=decision_trace,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=gate_decision,
        policy_admission=policy_record,
    )
    return PipelineResult(
        outcome=PipelineOutcome.ALLOWED,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=gate_decision,
        policy_admission=policy_record,
        decision_trace=decision_trace,
        approval_receipt=approval_receipt,
        receipt_validation=validate_approval_receipt(approval_receipt, decision_trace),
    )


def _allowed_policy_record(audited_plan: AuditedPlan) -> PolicyAdmissionRecord:
    snapshot = fresh_world_snapshot()
    freshness_result = fresh_world_snapshot_result(snapshot)
    trust_result = trusted_world_snapshot_result(snapshot)
    policy = Policy(
        "policy-1",
        "v1",
        (PolicyRule("rule-1", "locomotion.translation", (Constraint("max_velocity"),)),),
    )
    authority = _context_authority()
    policy_result = bind_policy_result_to_trust(
        bind_policy_result_to_freshness(
            PolicyEvaluationResult(
                PolicyDecision.ALLOW,
                "policy-1",
                ["rule-1"],
                ["rule-1:0:max_velocity"],
                [],
                ["POLICY_ALLOWED"],
                policy_version=policy.policy_version,
                policy_schema_version=policy.policy_schema_version,
                policy_checksum=policy.policy_checksum,
                policy_authority=policy.policy_authority,
                context_authority_checksum=authority.context_checksum,
            ),
            freshness_result,
        ),
        trust_result,
    )
    safety_case = build_safety_case(
        policy_result=policy_result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=Capability("locomotion.translation"),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
        trust_result=trust_result,
    )
    return PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=policy_result,
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
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
        **_context_authority_kwargs(),
        **_trusted_record_kwargs(trust_result),
    )


def _context_authority() -> ContextAuthority:
    return ContextAuthority(
        context_id="pipeline-contract-context",
        request_id="pipeline-contract-request",
        evaluation_time_ms=1_000_500,
        caller_authority="pytest",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )


def _context_authority_kwargs() -> dict[str, object]:
    authority = _context_authority()
    return {
        "context_authority_checksum": authority.context_checksum,
        "context_id": authority.context_id,
        "caller_authority": authority.caller_authority,
        "deployment_domain": authority.deployment_domain,
        "context_schema_version": authority.context_schema_version,
        "context_evaluation_time_ms": authority.evaluation_time_ms,
    }


def _trusted_record_kwargs(trust_result: WorldSnapshotTrustResult) -> dict[str, object]:
    return {
        "world_snapshot_trust_status": trust_result.status.value,
        "world_snapshot_trust_reason_code": trust_result.reason_code,
        "world_snapshot_trust_result_checksum": trust_result.checksum,
        "evidence_envelope_checksum": trust_result.evidence_envelope_checksum,
        "attestation_checksum": trust_result.attestation_checksum,
        "trust_policy_checksum": trust_result.trust_policy_checksum,
        "verifier_certification_status": "CERTIFIED",
        "verifier_certification_reason_code": "ATTESTATION_VERIFIER_CERTIFIED",
        "verifier_certification_checksum": trust_result.verifier_certification_checksum,
        "verifier_id": trust_result.verifier_id,
        "verifier_metadata_checksum": trust_result.verifier_metadata_checksum,
        "trust_policy_config_status": "VALID",
        "trust_policy_config_reason_code": "TRUST_POLICY_CONFIG_VALID",
        "trust_policy_config_validation_checksum": (
            trust_result.trust_policy_config_validation_checksum
        ),
        "source_id": trust_result.source_id,
        "source_type": trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        "trust_domain": trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
    }


def test_pipeline_result_allowed_requires_allowed_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    result = _make_allowed_result(
        make_validation_result, make_command_plan, make_audited_plan, make_allowed_gate_decision
    )
    assert result.outcome == PipelineOutcome.ALLOWED
    assert result.gate_decision is not None
    assert result.gate_decision.status == GateDecisionStatus.ALLOWED


def test_pipeline_result_allowed_rejects_missing_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=None,
        )


def test_pipeline_result_allowed_rejects_blocked_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_blocked_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_blocked_gate_decision,
        )


def test_pipeline_result_allowed_rejects_missing_core_fields(
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="validation, plan, and audited_plan"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=make_allowed_gate_decision,
        )


def test_pipeline_result_allowed_rejects_missing_policy_admission(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="policy-backed"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_allowed_gate_decision,
        )


def test_pipeline_result_allowed_rejects_mismatched_policy_admission(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    policy_record = _allowed_policy_record(make_audited_plan)
    tampered_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=policy_record.policy_result,
        safety_case=policy_record.safety_case,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_ADMISSION_INTEGRITY_FAILED",),
        audit_id="different-audit",
        plan_id=policy_record.plan_id,
        plan_checksum=policy_record.plan_checksum,
        capability_name=policy_record.capability_name,
        capability_version=policy_record.capability_version,
    )

    with pytest.raises(ValueError, match="policy-backed"):
        PipelineResult(
            outcome=PipelineOutcome.ALLOWED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_allowed_gate_decision,
            policy_admission=tampered_record,
        )


# ---------------------------------------------------------------------------
# PipelineResult — BLOCKED
# ---------------------------------------------------------------------------


def test_pipeline_result_blocked_requires_blocked_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_blocked_gate_decision: GateDecision,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.BLOCKED,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=make_blocked_gate_decision,
    )
    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.gate_decision is not None
    assert result.gate_decision.status == GateDecisionStatus.BLOCKED


def test_pipeline_result_blocked_accepts_denied_policy_without_gate(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    policy_record = PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_REQUIRED",),
    )

    result = PipelineResult(
        outcome=PipelineOutcome.BLOCKED,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=None,
        policy_admission=policy_record,
    )

    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.reasons == ("POLICY_REQUIRED",)


def test_pipeline_result_blocked_accepts_disabled_policy_without_gate(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.BLOCKED,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=None,
    )

    assert result.outcome == PipelineOutcome.BLOCKED
    assert result.gate_decision is None
    assert result.policy_admission.mode is PolicyAdmissionMode.DISABLED


def test_pipeline_result_blocked_rejects_allowed_gate_decision(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.BLOCKED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=make_allowed_gate_decision,
        )


def test_pipeline_result_blocked_rejects_no_blocking_evidence(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="blocked gate_decision"):
        PipelineResult(
            outcome=PipelineOutcome.BLOCKED,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=make_audited_plan,
            gate_decision=None,
            policy_admission=_allowed_policy_record(make_audited_plan),
        )


# ---------------------------------------------------------------------------
# PipelineResult — INVALID
# ---------------------------------------------------------------------------


def test_pipeline_result_invalid_accepts_none_fields() -> None:
    from datetime import UTC, datetime

    from aegis.contracts.context import ExecutionContext
    from aegis.contracts.intent import RawIntent

    ctx = ExecutionContext("test", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    intent = RawIntent(
        command="launch_missiles",
        parameters={},
        source_id="test",
        priority=5,
        context=ctx,
    )
    vr = ValidationResult(
        is_valid=False,
        intent=intent,
        violations=(
            Violation(
                code="UNSUPPORTED_COMMAND",
                field="command",
                reason="not a supported command",
                layer="validation",
            ),
        ),
    )
    result = PipelineResult(
        outcome=PipelineOutcome.INVALID,
        validation_result=vr,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.INVALID
    assert result.plan is None
    assert result.audited_plan is None
    assert result.gate_decision is None


def test_pipeline_result_invalid_rejects_non_none_plan(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
) -> None:
    with pytest.raises(ValueError, match="plan=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=make_command_plan,
            audited_plan=None,
            gate_decision=None,
        )


def test_pipeline_result_invalid_rejects_non_none_audited_plan(
    make_validation_result: ValidationResult,
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="audited_plan=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=None,
            audited_plan=make_audited_plan,
            gate_decision=None,
        )


def test_pipeline_result_invalid_rejects_non_none_gate_decision(
    make_validation_result: ValidationResult,
    make_allowed_gate_decision: GateDecision,
) -> None:
    with pytest.raises(ValueError, match="gate_decision=None"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=make_validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=make_allowed_gate_decision,
        )


def test_pipeline_result_invalid_accepts_policy_invalid_after_audit(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
) -> None:
    policy_result = PolicyEvaluationResult(
        PolicyDecision.INVALID,
        "policy-1",
        [],
        [],
        [],
        ["POLICY_EVALUATION_CONTEXT_INVALID"],
    )
    safety_case = build_safety_case(
        policy_result=policy_result,
        audited_plan_id=make_audited_plan.audit_id,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
    )
    policy_record = PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=policy_result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_INVALID",),
    )

    result = PipelineResult(
        outcome=PipelineOutcome.INVALID,
        validation_result=make_validation_result,
        plan=make_command_plan,
        audited_plan=make_audited_plan,
        gate_decision=None,
        policy_admission=policy_record,
    )

    assert result.outcome == PipelineOutcome.INVALID
    assert result.plan is make_command_plan
    assert result.audited_plan is make_audited_plan


def test_pipeline_result_invalid_rejects_policy_approval() -> None:
    policy_record = PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_REQUIRED",),
    )
    object.__setattr__(policy_record, "admission_allowed", True)

    with pytest.raises(ValueError, match="approval"):
        PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=policy_record,
        )


# ---------------------------------------------------------------------------
# PipelineResult — ERROR
# ---------------------------------------------------------------------------


def test_pipeline_result_error_accepts_all_none_fields() -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.ERROR,
        validation_result=None,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.ERROR


def test_pipeline_result_error_accepts_partial_fields(
    make_validation_result: ValidationResult,
) -> None:
    result = PipelineResult(
        outcome=PipelineOutcome.ERROR,
        validation_result=make_validation_result,
        plan=None,
        audited_plan=None,
        gate_decision=None,
    )
    assert result.outcome == PipelineOutcome.ERROR
    assert result.validation_result is not None


def test_pipeline_result_error_rejects_approval_state(
    make_audited_plan: AuditedPlan,
) -> None:
    with pytest.raises(ValueError, match="approval"):
        PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=_allowed_policy_record(make_audited_plan),
        )


# ---------------------------------------------------------------------------
# PipelineResult — immutability
# ---------------------------------------------------------------------------


def test_pipeline_result_is_frozen(
    make_validation_result: ValidationResult,
    make_command_plan: CommandPlan,
    make_audited_plan: AuditedPlan,
    make_allowed_gate_decision: GateDecision,
) -> None:
    result = _make_allowed_result(
        make_validation_result, make_command_plan, make_audited_plan, make_allowed_gate_decision
    )
    with pytest.raises((AttributeError, TypeError)):
        result.outcome = PipelineOutcome.BLOCKED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Fixtures (scoped to this module via conftest below — defined inline here)
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_validation_result() -> ValidationResult:
    from datetime import UTC, datetime

    from aegis.contracts.context import ExecutionContext
    from aegis.contracts.intent import RawIntent

    ctx = ExecutionContext("test-001", datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")
    intent = RawIntent(
        command="stop",
        parameters={},
        source_id="test",
        priority=5,
        context=ctx,
    )
    return ValidationResult(is_valid=True, intent=intent, violations=())


@pytest.fixture()
def make_command_plan(make_validation_result: ValidationResult) -> CommandPlan:
    from aegis.planning import plan_validated_intent

    return plan_validated_intent(make_validation_result)


@pytest.fixture()
def make_audited_plan(make_command_plan: CommandPlan) -> AuditedPlan:
    from aegis.audit import build_audited_plan

    return build_audited_plan(make_command_plan)


@pytest.fixture()
def make_allowed_gate_decision(make_audited_plan: AuditedPlan) -> GateDecision:
    from aegis.gate import gate_audited_plan

    decision = gate_audited_plan(make_audited_plan)
    assert decision.status == GateDecisionStatus.ALLOWED
    return decision


@pytest.fixture()
def make_blocked_gate_decision() -> GateDecision:
    return GateDecision(
        status=GateDecisionStatus.BLOCKED,
        audit_id="aaa",
        plan_id="bbb",
        reasons=(GateBlockReason.CHECKSUM_MISMATCH,),
        checksum_verified=False,
        audit_id_verified=False,
    )
