"""Contract tests for deterministic approval receipts."""

from __future__ import annotations

from aegis.contracts.approval_receipt import (
    ApprovalReceipt,
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    pipeline_result_id_checksum,
    validate_approval_receipt,
)
from aegis.contracts.decision_trace import (
    ALLOW_REQUIRED_STAGE_CHAIN,
    DecisionTrace,
    DecisionTraceStep,
)


def _allowed_trace() -> DecisionTrace:
    steps: list[DecisionTraceStep] = []
    input_checksum = "context-checksum"
    predecessor_checksum: str | None = None
    for stage_name in ALLOW_REQUIRED_STAGE_CHAIN:
        output_checksum = f"{stage_name}-checksum"
        step = DecisionTraceStep(
            stage_name=stage_name,
            stage_status="OK",
            stage_reason=f"{stage_name.upper()}_OK",
            input_checksum=input_checksum,
            output_checksum=output_checksum,
            predecessor_checksum=predecessor_checksum,
            metadata={"stage": stage_name},
        )
        steps.append(step)
        input_checksum = output_checksum
        predecessor_checksum = step.stage_checksum
    return DecisionTrace(steps)


def _partial_trace() -> DecisionTrace:
    raw = DecisionTraceStep(
        stage_name="raw_intent",
        stage_status="OK",
        stage_reason="RAW_INTENT_OK",
        input_checksum="context-checksum",
        output_checksum="raw_intent-checksum",
        predecessor_checksum=None,
    )
    validation = DecisionTraceStep(
        stage_name="validation",
        stage_status="INVALID",
        stage_reason="VALIDATION_FAILED",
        input_checksum=raw.output_checksum,
        output_checksum="validation-checksum",
        predecessor_checksum=raw.stage_checksum,
    )
    return DecisionTrace((raw, validation))


def _receipt_for_trace(
    trace: DecisionTrace,
    *,
    pipeline_outcome: str = "allowed",
    trust_result_checksum: str | None = "world_snapshot_trust-checksum",
) -> ApprovalReceipt:
    stage_outputs = {step.stage_name: step.output_checksum for step in trace.steps}
    validation_checksum = stage_outputs.get("validation")
    plan_checksum = stage_outputs.get("planning")
    audited_plan_checksum = stage_outputs.get("audit")
    policy_admission_checksum = stage_outputs.get("policy_admission")
    gate_decision_checksum = stage_outputs.get("gate_decision")
    pipeline_result_id = pipeline_result_id_checksum(
        pipeline_outcome=pipeline_outcome,
        raw_intent_checksum=stage_outputs["raw_intent"],
        validation_checksum=validation_checksum,
        plan_checksum=plan_checksum,
        audit_id="audit-id" if audited_plan_checksum is not None else None,
        audited_plan_checksum=audited_plan_checksum,
        policy_admission_checksum=policy_admission_checksum,
        gate_decision_checksum=gate_decision_checksum,
    )
    return ApprovalReceipt(
        status=ApprovalReceiptStatus.VALID,
        reason=ApprovalReceiptReason.APPROVAL_RECEIPT_VALID,
        pipeline_result_id=pipeline_result_id,
        pipeline_outcome=pipeline_outcome,
        raw_intent_checksum=stage_outputs["raw_intent"],
        validation_checksum=validation_checksum,
        plan_checksum=plan_checksum,
        audit_id="audit-id" if audited_plan_checksum is not None else None,
        audited_plan_checksum=audited_plan_checksum,
        world_snapshot_checksum="world-snapshot-checksum"
        if "world_snapshot_admissibility" in stage_outputs
        else None,
        admissibility_checksum=stage_outputs.get("world_snapshot_admissibility"),
        freshness_checksum=stage_outputs.get("world_snapshot_freshness"),
        verifier_certification_checksum=stage_outputs.get("verifier_certification"),
        trust_policy_config_checksum=stage_outputs.get("trust_policy_config"),
        trust_result_checksum=trust_result_checksum
        if "world_snapshot_trust" in stage_outputs
        else None,
        policy_checksum="policy-checksum" if "policy_evaluation" in stage_outputs else None,
        context_authority_checksum="context-authority-checksum"
        if "policy_evaluation" in stage_outputs
        else None,
        policy_result_checksum=stage_outputs.get("policy_evaluation"),
        safety_case_checksum=stage_outputs.get("safety_case"),
        policy_admission_checksum=policy_admission_checksum,
        gate_decision_checksum=gate_decision_checksum,
        decision_trace_checksum=trace.trace_checksum,
    )


def test_allowed_approval_receipt_validates_full_stage_chain() -> None:
    trace = _allowed_trace()
    receipt = _receipt_for_trace(trace)

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.VALID
    assert validation.reason is ApprovalReceiptReason.APPROVAL_RECEIPT_VALID


def test_allowed_approval_receipt_rejects_missing_required_field() -> None:
    trace = _allowed_trace()
    receipt = _receipt_for_trace(trace, trust_result_checksum=None)

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.APPROVAL_RECEIPT_STAGE_BINDING_MISMATCH
    assert "trust_result_checksum" in validation.failed_fields


def test_approval_receipt_rejects_manual_receipt_checksum_replacement() -> None:
    trace = _allowed_trace()
    receipt = _receipt_for_trace(trace)
    object.__setattr__(receipt, "approval_receipt_checksum", "forged-receipt-checksum")

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.APPROVAL_RECEIPT_CHECKSUM_MISMATCH


def test_approval_receipt_rejects_manual_trace_checksum_replacement() -> None:
    trace = _allowed_trace()
    receipt = _receipt_for_trace(trace)
    object.__setattr__(receipt, "decision_trace_checksum", "forged-trace-checksum")

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.DECISION_TRACE_CHECKSUM_MISMATCH


def test_approval_receipt_rejects_fake_policy_binding_without_stage() -> None:
    trace = _partial_trace()
    receipt = _receipt_for_trace(trace, pipeline_outcome="invalid")
    object.__setattr__(receipt, "policy_result_checksum", "fake-policy-result")
    object.__setattr__(
        receipt,
        "approval_receipt_checksum",
        ApprovalReceipt(
            status=receipt.status,
            reason=receipt.reason,
            pipeline_result_id=receipt.pipeline_result_id,
            pipeline_outcome=receipt.pipeline_outcome,
            raw_intent_checksum=receipt.raw_intent_checksum,
            validation_checksum=receipt.validation_checksum,
            plan_checksum=receipt.plan_checksum,
            audit_id=receipt.audit_id,
            audited_plan_checksum=receipt.audited_plan_checksum,
            world_snapshot_checksum=receipt.world_snapshot_checksum,
            admissibility_checksum=receipt.admissibility_checksum,
            freshness_checksum=receipt.freshness_checksum,
            verifier_certification_checksum=receipt.verifier_certification_checksum,
            trust_policy_config_checksum=receipt.trust_policy_config_checksum,
            trust_result_checksum=receipt.trust_result_checksum,
            policy_result_checksum="fake-policy-result",
            safety_case_checksum=receipt.safety_case_checksum,
            policy_admission_checksum=receipt.policy_admission_checksum,
            gate_decision_checksum=receipt.gate_decision_checksum,
            decision_trace_checksum=receipt.decision_trace_checksum,
        ).approval_receipt_checksum,
    )

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.APPROVAL_RECEIPT_FAKE_STAGE_BINDING
    assert "policy_result_checksum" in validation.failed_fields


def test_approval_receipt_rejects_mutated_trace_step() -> None:
    trace = _allowed_trace()
    receipt = _receipt_for_trace(trace)
    object.__setattr__(trace.steps[4], "output_checksum", "forged-admissibility")

    validation = validate_approval_receipt(receipt, trace)

    assert validation.status is ApprovalReceiptStatus.INVALID
    assert validation.reason is ApprovalReceiptReason.DECISION_TRACE_INVALID
