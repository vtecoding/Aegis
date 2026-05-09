"""Build approval receipts for deterministic pipeline results."""

from __future__ import annotations

from aegis.contracts.approval_receipt import (
    ApprovalReceipt,
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    ApprovalReceiptValidationResult,
    pipeline_result_id_checksum,
    validate_approval_receipt,
)
from aegis.contracts.audit import AuditedPlan
from aegis.contracts.decision_trace import (
    DecisionTrace,
    command_plan_identity_checksum,
    gate_decision_identity_checksum,
    policy_admission_record_identity_checksum,
    policy_result_identity_checksum,
    raw_intent_identity_checksum,
    safety_case_identity_checksum,
    validation_result_identity_checksum,
)
from aegis.contracts.gate import GateDecision
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan
from aegis.contracts.policy_admission import PolicyAdmissionRecord
from aegis.contracts.validation import ValidationResult


def build_approval_receipt(
    *,
    pipeline_outcome: str,
    raw_intent: RawIntent,
    decision_trace: DecisionTrace,
    validation_result: ValidationResult | None,
    plan: CommandPlan | None,
    audited_plan: AuditedPlan | None,
    gate_decision: GateDecision | None,
    policy_admission: PolicyAdmissionRecord,
) -> ApprovalReceipt:
    """Build a deterministic receipt bound to the supplied pipeline artifacts."""
    present_stages = {step.stage_name for step in decision_trace.steps}
    raw_intent_checksum = raw_intent_identity_checksum(raw_intent)
    validation_checksum = (
        validation_result_identity_checksum(validation_result)
        if validation_result is not None
        else None
    )
    plan_checksum = command_plan_identity_checksum(plan) if plan is not None else None
    audit_id = audited_plan.audit_id if audited_plan is not None else None
    audited_plan_checksum = audited_plan.checksum if audited_plan is not None else None
    policy_admission_checksum = (
        policy_admission_record_identity_checksum(policy_admission)
        if "policy_admission" in present_stages
        else None
    )
    gate_decision_checksum = (
        gate_decision_identity_checksum(gate_decision) if gate_decision is not None else None
    )
    pipeline_result_id = pipeline_result_id_checksum(
        pipeline_outcome=pipeline_outcome,
        raw_intent_checksum=raw_intent_checksum,
        validation_checksum=validation_checksum,
        plan_checksum=plan_checksum,
        audit_id=audit_id,
        audited_plan_checksum=audited_plan_checksum,
        policy_admission_checksum=policy_admission_checksum,
        gate_decision_checksum=gate_decision_checksum,
    )
    return ApprovalReceipt(
        status=ApprovalReceiptStatus.VALID,
        reason=ApprovalReceiptReason.APPROVAL_RECEIPT_VALID,
        pipeline_result_id=pipeline_result_id,
        pipeline_outcome=pipeline_outcome,
        raw_intent_checksum=raw_intent_checksum,
        validation_checksum=validation_checksum,
        plan_checksum=plan_checksum,
        audit_id=audit_id,
        audited_plan_checksum=audited_plan_checksum,
        world_snapshot_checksum=policy_admission.world_snapshot_checksum
        if "world_snapshot_admissibility" in present_stages
        else None,
        admissibility_checksum=policy_admission.world_snapshot_admissibility_result_checksum
        if "world_snapshot_admissibility" in present_stages
        else None,
        freshness_checksum=policy_admission.freshness_result_checksum
        if "world_snapshot_freshness" in present_stages
        else None,
        verifier_certification_checksum=policy_admission.verifier_certification_checksum
        if "verifier_certification" in present_stages
        else None,
        trust_policy_config_checksum=policy_admission.trust_policy_config_validation_checksum
        if "trust_policy_config" in present_stages
        else None,
        trust_result_checksum=policy_admission.world_snapshot_trust_result_checksum
        if "world_snapshot_trust" in present_stages
        else None,
        policy_checksum=policy_admission.policy_checksum
        if "policy_evaluation" in present_stages
        else None,
        context_authority_checksum=policy_admission.context_authority_checksum
        if "policy_evaluation" in present_stages
        else None,
        policy_result_checksum=policy_result_identity_checksum(policy_admission.policy_result)
        if "policy_evaluation" in present_stages
        else None,
        safety_case_checksum=safety_case_identity_checksum(policy_admission.safety_case)
        if "safety_case" in present_stages
        else None,
        policy_admission_checksum=policy_admission_checksum,
        gate_decision_checksum=gate_decision_checksum,
        decision_trace_checksum=decision_trace.trace_checksum,
    )


__all__ = [
    "ApprovalReceiptValidationResult",
    "build_approval_receipt",
    "validate_approval_receipt",
]
