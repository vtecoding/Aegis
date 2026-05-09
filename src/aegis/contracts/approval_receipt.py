"""Approval receipt contracts for tamper-evident pipeline decisions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.decision_trace import (
    ALLOW_REQUIRED_STAGE_CHAIN,
    DecisionTrace,
    command_plan_identity_checksum,
    decision_trace_checksum,
    decision_trace_integrity_errors,
    gate_decision_identity_checksum,
    policy_admission_record_identity_checksum,
    policy_result_identity_checksum,
    raw_intent_identity_checksum,
    safety_case_identity_checksum,
    validation_result_identity_checksum,
)
from aegis.contracts.gate import GateDecision
from aegis.contracts.planning import CommandPlan
from aegis.contracts.policy_admission import PolicyAdmissionRecord
from aegis.contracts.validation import ValidationResult

type CanonicalReceiptValue = (
    str | int | float | bool | None | list[CanonicalReceiptValue] | dict[str, CanonicalReceiptValue]
)


class ApprovalReceiptStatus(StrEnum):
    """Approval receipt validation status values."""

    VALID = "VALID"
    INVALID = "INVALID"


class ApprovalReceiptReason(StrEnum):
    """Stable approval receipt validation reason codes."""

    APPROVAL_RECEIPT_VALID = "APPROVAL_RECEIPT_VALID"
    APPROVAL_RECEIPT_DECLARED_INVALID = "APPROVAL_RECEIPT_DECLARED_INVALID"
    DECISION_TRACE_INVALID = "DECISION_TRACE_INVALID"
    DECISION_TRACE_CHECKSUM_MISMATCH = "DECISION_TRACE_CHECKSUM_MISMATCH"
    APPROVAL_RECEIPT_CHECKSUM_MISMATCH = "APPROVAL_RECEIPT_CHECKSUM_MISMATCH"
    APPROVAL_RECEIPT_REQUIRED_FIELD_MISSING = "APPROVAL_RECEIPT_REQUIRED_FIELD_MISSING"
    APPROVAL_RECEIPT_STAGE_CHAIN_INCOMPLETE = "APPROVAL_RECEIPT_STAGE_CHAIN_INCOMPLETE"
    APPROVAL_RECEIPT_STAGE_BINDING_MISMATCH = "APPROVAL_RECEIPT_STAGE_BINDING_MISMATCH"
    APPROVAL_RECEIPT_FAKE_STAGE_BINDING = "APPROVAL_RECEIPT_FAKE_STAGE_BINDING"
    APPROVAL_RECEIPT_PIPELINE_BINDING_MISMATCH = "APPROVAL_RECEIPT_PIPELINE_BINDING_MISMATCH"


@dataclass(frozen=True, slots=True, init=False)
class ApprovalReceipt:
    """Immutable end-to-end receipt for one pipeline decision.

    Args:
        status: Declared receipt status. Valid receipts must declare ``VALID``.
        reason: Stable receipt reason code.
        pipeline_result_id: Deterministic identity for this pipeline outcome.
        pipeline_outcome: Final pipeline outcome value.
        raw_intent_checksum: Raw intent identity consumed by validation.
        validation_checksum: Validation result identity when validation completed.
        plan_checksum: Command plan identity when planning completed.
        audit_id: Audit identifier when audit completed.
        audited_plan_checksum: Audited executable plan checksum when audit completed.
        world_snapshot_checksum: Snapshot checksum consumed by admission, when any.
        admissibility_checksum: World snapshot admissibility result checksum, when any.
        freshness_checksum: World snapshot freshness result checksum, when any.
        verifier_certification_checksum: Verifier certification checksum, when any.
        trust_policy_config_checksum: Trust policy configuration checksum, when any.
        trust_result_checksum: World snapshot trust result checksum, when any.
        policy_result_checksum: Policy evaluation result checksum, when any.
        safety_case_checksum: SafetyCase deterministic identity, when any.
        policy_admission_checksum: PolicyAdmissionRecord identity, when any.
        gate_decision_checksum: GateDecision identity, when gate executed.
        decision_trace_checksum: DecisionTrace checksum bound by this receipt.
        approval_receipt_checksum: Optional supplied checksum; must match recomputation.

    Raises:
        ValueError: If required receipt identity fields are empty or checksum
            recomputation fails.
    """

    status: ApprovalReceiptStatus
    reason: ApprovalReceiptReason
    pipeline_result_id: str
    pipeline_outcome: str
    raw_intent_checksum: str
    validation_checksum: str | None
    plan_checksum: str | None
    audit_id: str | None
    audited_plan_checksum: str | None
    world_snapshot_checksum: str | None
    admissibility_checksum: str | None
    freshness_checksum: str | None
    verifier_certification_checksum: str | None
    trust_policy_config_checksum: str | None
    trust_result_checksum: str | None
    policy_checksum: str | None
    context_authority_checksum: str | None
    policy_result_checksum: str | None
    safety_case_checksum: str | None
    policy_admission_checksum: str | None
    gate_decision_checksum: str | None
    decision_trace_checksum: str
    approval_receipt_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason: object,
        pipeline_result_id: str,
        pipeline_outcome: str,
        raw_intent_checksum: str,
        validation_checksum: str | None,
        plan_checksum: str | None,
        audit_id: str | None,
        audited_plan_checksum: str | None,
        world_snapshot_checksum: str | None,
        admissibility_checksum: str | None,
        freshness_checksum: str | None,
        verifier_certification_checksum: str | None,
        trust_policy_config_checksum: str | None,
        trust_result_checksum: str | None,
        policy_checksum: str | None = None,
        context_authority_checksum: str | None = None,
        policy_result_checksum: str | None,
        safety_case_checksum: str | None,
        policy_admission_checksum: str | None,
        gate_decision_checksum: str | None,
        decision_trace_checksum: str,
        approval_receipt_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason)
        normalized_pipeline_result_id = _normalize_required_text(
            pipeline_result_id, "pipeline_result_id"
        )
        normalized_pipeline_outcome = _normalize_required_text(pipeline_outcome, "pipeline_outcome")
        normalized_raw_intent_checksum = _normalize_required_text(
            raw_intent_checksum, "raw_intent_checksum"
        )
        normalized_decision_trace_checksum = _normalize_required_text(
            decision_trace_checksum, "decision_trace_checksum"
        )
        normalized_fields = {
            "validation_checksum": _normalize_optional_text(
                validation_checksum, "validation_checksum"
            ),
            "plan_checksum": _normalize_optional_text(plan_checksum, "plan_checksum"),
            "audit_id": _normalize_optional_text(audit_id, "audit_id"),
            "audited_plan_checksum": _normalize_optional_text(
                audited_plan_checksum, "audited_plan_checksum"
            ),
            "world_snapshot_checksum": _normalize_optional_text(
                world_snapshot_checksum, "world_snapshot_checksum"
            ),
            "admissibility_checksum": _normalize_optional_text(
                admissibility_checksum, "admissibility_checksum"
            ),
            "freshness_checksum": _normalize_optional_text(
                freshness_checksum, "freshness_checksum"
            ),
            "verifier_certification_checksum": _normalize_optional_text(
                verifier_certification_checksum, "verifier_certification_checksum"
            ),
            "trust_policy_config_checksum": _normalize_optional_text(
                trust_policy_config_checksum, "trust_policy_config_checksum"
            ),
            "trust_result_checksum": _normalize_optional_text(
                trust_result_checksum, "trust_result_checksum"
            ),
            "policy_checksum": _normalize_optional_text(policy_checksum, "policy_checksum"),
            "context_authority_checksum": _normalize_optional_text(
                context_authority_checksum, "context_authority_checksum"
            ),
            "policy_result_checksum": _normalize_optional_text(
                policy_result_checksum, "policy_result_checksum"
            ),
            "safety_case_checksum": _normalize_optional_text(
                safety_case_checksum, "safety_case_checksum"
            ),
            "policy_admission_checksum": _normalize_optional_text(
                policy_admission_checksum, "policy_admission_checksum"
            ),
            "gate_decision_checksum": _normalize_optional_text(
                gate_decision_checksum, "gate_decision_checksum"
            ),
        }
        computed_checksum = compute_approval_receipt_checksum(
            status=normalized_status,
            reason=normalized_reason,
            pipeline_result_id=normalized_pipeline_result_id,
            pipeline_outcome=normalized_pipeline_outcome,
            raw_intent_checksum=normalized_raw_intent_checksum,
            decision_trace_checksum=normalized_decision_trace_checksum,
            **normalized_fields,
        )
        normalized_receipt_checksum = _normalize_supplied_checksum(
            approval_receipt_checksum, computed_checksum, "approval_receipt_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "pipeline_result_id", normalized_pipeline_result_id)
        object.__setattr__(self, "pipeline_outcome", normalized_pipeline_outcome)
        object.__setattr__(self, "raw_intent_checksum", normalized_raw_intent_checksum)
        for field_name, field_value in normalized_fields.items():
            object.__setattr__(self, field_name, field_value)
        object.__setattr__(self, "decision_trace_checksum", normalized_decision_trace_checksum)
        object.__setattr__(self, "approval_receipt_checksum", normalized_receipt_checksum)


@dataclass(frozen=True, slots=True, init=False)
class ApprovalReceiptValidationResult:
    """Machine-checkable validation result for an approval receipt."""

    status: ApprovalReceiptStatus
    reason: ApprovalReceiptReason
    approval_receipt_checksum: str
    decision_trace_checksum: str
    failed_fields: tuple[str, ...]

    def __init__(
        self,
        *,
        status: ApprovalReceiptStatus,
        reason: ApprovalReceiptReason,
        approval_receipt_checksum: str,
        decision_trace_checksum: str,
        failed_fields: Iterable[str] = (),
    ) -> None:
        normalized_fields = tuple(
            _normalize_required_text(field, "failed_fields") for field in failed_fields
        )
        object.__setattr__(self, "status", _normalize_status(status))
        object.__setattr__(self, "reason", _normalize_reason(reason))
        object.__setattr__(
            self,
            "approval_receipt_checksum",
            _normalize_required_text(approval_receipt_checksum, "approval_receipt_checksum"),
        )
        object.__setattr__(
            self,
            "decision_trace_checksum",
            _normalize_required_text(decision_trace_checksum, "decision_trace_checksum"),
        )
        object.__setattr__(self, "failed_fields", normalized_fields)


def approval_receipt_checksum(
    *,
    status: ApprovalReceiptStatus,
    reason: ApprovalReceiptReason,
    pipeline_result_id: str,
    pipeline_outcome: str,
    raw_intent_checksum: str,
    validation_checksum: str | None,
    plan_checksum: str | None,
    audit_id: str | None,
    audited_plan_checksum: str | None,
    world_snapshot_checksum: str | None,
    admissibility_checksum: str | None,
    freshness_checksum: str | None,
    verifier_certification_checksum: str | None,
    trust_policy_config_checksum: str | None,
    trust_result_checksum: str | None,
    policy_checksum: str | None,
    context_authority_checksum: str | None,
    policy_result_checksum: str | None,
    safety_case_checksum: str | None,
    policy_admission_checksum: str | None,
    gate_decision_checksum: str | None,
    decision_trace_checksum: str,
) -> str:
    """Return the deterministic checksum for an approval receipt."""
    return compute_approval_receipt_checksum(
        status=status,
        reason=reason,
        pipeline_result_id=pipeline_result_id,
        pipeline_outcome=pipeline_outcome,
        raw_intent_checksum=raw_intent_checksum,
        validation_checksum=validation_checksum,
        plan_checksum=plan_checksum,
        audit_id=audit_id,
        audited_plan_checksum=audited_plan_checksum,
        world_snapshot_checksum=world_snapshot_checksum,
        admissibility_checksum=admissibility_checksum,
        freshness_checksum=freshness_checksum,
        verifier_certification_checksum=verifier_certification_checksum,
        trust_policy_config_checksum=trust_policy_config_checksum,
        trust_result_checksum=trust_result_checksum,
        policy_checksum=policy_checksum,
        context_authority_checksum=context_authority_checksum,
        policy_result_checksum=policy_result_checksum,
        safety_case_checksum=safety_case_checksum,
        policy_admission_checksum=policy_admission_checksum,
        gate_decision_checksum=gate_decision_checksum,
        decision_trace_checksum=decision_trace_checksum,
    )


def compute_approval_receipt_checksum(
    *,
    status: ApprovalReceiptStatus,
    reason: ApprovalReceiptReason,
    pipeline_result_id: str,
    pipeline_outcome: str,
    raw_intent_checksum: str,
    validation_checksum: str | None,
    plan_checksum: str | None,
    audit_id: str | None,
    audited_plan_checksum: str | None,
    world_snapshot_checksum: str | None,
    admissibility_checksum: str | None,
    freshness_checksum: str | None,
    verifier_certification_checksum: str | None,
    trust_policy_config_checksum: str | None,
    trust_result_checksum: str | None,
    policy_checksum: str | None,
    context_authority_checksum: str | None,
    policy_result_checksum: str | None,
    safety_case_checksum: str | None,
    policy_admission_checksum: str | None,
    gate_decision_checksum: str | None,
    decision_trace_checksum: str,
) -> str:
    """Return the deterministic checksum for an approval receipt."""
    return _sha256(
        {
            "status": status.value,
            "reason": reason.value,
            "pipeline_result_id": pipeline_result_id,
            "pipeline_outcome": pipeline_outcome,
            "raw_intent_checksum": raw_intent_checksum,
            "validation_checksum": validation_checksum,
            "plan_checksum": plan_checksum,
            "audit_id": audit_id,
            "audited_plan_checksum": audited_plan_checksum,
            "world_snapshot_checksum": world_snapshot_checksum,
            "admissibility_checksum": admissibility_checksum,
            "freshness_checksum": freshness_checksum,
            "verifier_certification_checksum": verifier_certification_checksum,
            "trust_policy_config_checksum": trust_policy_config_checksum,
            "trust_result_checksum": trust_result_checksum,
            "policy_checksum": policy_checksum,
            "context_authority_checksum": context_authority_checksum,
            "policy_result_checksum": policy_result_checksum,
            "safety_case_checksum": safety_case_checksum,
            "policy_admission_checksum": policy_admission_checksum,
            "gate_decision_checksum": gate_decision_checksum,
            "decision_trace_checksum": decision_trace_checksum,
        }
    )


def pipeline_result_id_checksum(
    *,
    pipeline_outcome: str,
    raw_intent_checksum: str,
    validation_checksum: str | None,
    plan_checksum: str | None,
    audit_id: str | None,
    audited_plan_checksum: str | None,
    policy_admission_checksum: str | None,
    gate_decision_checksum: str | None,
) -> str:
    """Return a deterministic identity for a PipelineResult without receipt fields."""
    return _sha256(
        {
            "pipeline_outcome": pipeline_outcome,
            "raw_intent_checksum": raw_intent_checksum,
            "validation_checksum": validation_checksum,
            "plan_checksum": plan_checksum,
            "audit_id": audit_id,
            "audited_plan_checksum": audited_plan_checksum,
            "policy_admission_checksum": policy_admission_checksum,
            "gate_decision_checksum": gate_decision_checksum,
        }
    )


def validate_approval_receipt(
    receipt: ApprovalReceipt,
    decision_trace: DecisionTrace,
) -> ApprovalReceiptValidationResult:
    """Validate an approval receipt against its decision trace."""
    trace_errors = decision_trace_integrity_errors(decision_trace)
    if trace_errors:
        return _invalid_result(
            receipt, decision_trace, ApprovalReceiptReason.DECISION_TRACE_INVALID, trace_errors
        )
    recomputed_trace_checksum = decision_trace_checksum(decision_trace.steps)
    if receipt.decision_trace_checksum != recomputed_trace_checksum:
        return _invalid_result(
            receipt,
            decision_trace,
            ApprovalReceiptReason.DECISION_TRACE_CHECKSUM_MISMATCH,
            ("decision_trace_checksum",),
        )
    if receipt.status is not ApprovalReceiptStatus.VALID:
        return _invalid_result(
            receipt,
            decision_trace,
            ApprovalReceiptReason.APPROVAL_RECEIPT_DECLARED_INVALID,
            ("status",),
        )
    if _receipt_checksum_mismatch(receipt):
        return _invalid_result(
            receipt,
            decision_trace,
            ApprovalReceiptReason.APPROVAL_RECEIPT_CHECKSUM_MISMATCH,
            ("approval_receipt_checksum",),
        )
    stage_binding_errors = _stage_binding_errors(receipt, decision_trace)
    if stage_binding_errors:
        return _invalid_result(
            receipt,
            decision_trace,
            ApprovalReceiptReason.APPROVAL_RECEIPT_STAGE_BINDING_MISMATCH,
            stage_binding_errors,
        )
    if receipt.pipeline_outcome == "allowed":
        missing_required_fields = _missing_allowed_fields(receipt)
        if missing_required_fields:
            return _invalid_result(
                receipt,
                decision_trace,
                ApprovalReceiptReason.APPROVAL_RECEIPT_REQUIRED_FIELD_MISSING,
                missing_required_fields,
            )
        observed_chain = tuple(step.stage_name for step in decision_trace.steps)
        if observed_chain != ALLOW_REQUIRED_STAGE_CHAIN:
            return _invalid_result(
                receipt,
                decision_trace,
                ApprovalReceiptReason.APPROVAL_RECEIPT_STAGE_CHAIN_INCOMPLETE,
                ("decision_trace.steps",),
            )
    fake_binding_errors = _fake_stage_binding_errors(receipt, decision_trace)
    if fake_binding_errors:
        return _invalid_result(
            receipt,
            decision_trace,
            ApprovalReceiptReason.APPROVAL_RECEIPT_FAKE_STAGE_BINDING,
            fake_binding_errors,
        )
    return ApprovalReceiptValidationResult(
        status=ApprovalReceiptStatus.VALID,
        reason=ApprovalReceiptReason.APPROVAL_RECEIPT_VALID,
        approval_receipt_checksum=receipt.approval_receipt_checksum,
        decision_trace_checksum=decision_trace.trace_checksum,
    )


def approval_receipt_matches_pipeline_fields(
    *,
    receipt: ApprovalReceipt,
    decision_trace: DecisionTrace,
    receipt_validation: ApprovalReceiptValidationResult,
    pipeline_outcome: str,
    validation_result: ValidationResult | None,
    plan: CommandPlan | None,
    audited_plan: AuditedPlan | None,
    gate_decision: GateDecision | None,
    policy_admission: PolicyAdmissionRecord,
) -> bool:
    """Return whether a receipt matches the concrete PipelineResult fields."""
    if receipt_validation.status is not ApprovalReceiptStatus.VALID:
        return False
    if receipt.pipeline_outcome != pipeline_outcome:
        return False
    if receipt.decision_trace_checksum != decision_trace.trace_checksum:
        return False
    if validation_result is None:
        return False
    expected_raw = raw_intent_identity_checksum(validation_result.intent)
    expected_validation = validation_result_identity_checksum(validation_result)
    expected_plan = command_plan_identity_checksum(plan) if plan is not None else None
    expected_audit_id = audited_plan.audit_id if audited_plan is not None else None
    expected_audited_plan = audited_plan.checksum if audited_plan is not None else None
    expected_policy_admission = policy_admission_record_identity_checksum(policy_admission)
    expected_gate = (
        gate_decision_identity_checksum(gate_decision) if gate_decision is not None else None
    )
    expected_policy_result = policy_result_identity_checksum(policy_admission.policy_result)
    expected_safety_case = safety_case_identity_checksum(policy_admission.safety_case)
    return receipt_matches_expected_bindings(
        receipt=receipt,
        raw_intent_checksum=expected_raw,
        validation_checksum=expected_validation,
        plan_checksum=expected_plan,
        audit_id=expected_audit_id,
        audited_plan_checksum=expected_audited_plan,
        world_snapshot_checksum=policy_admission.world_snapshot_checksum,
        admissibility_checksum=policy_admission.world_snapshot_admissibility_result_checksum,
        freshness_checksum=policy_admission.freshness_result_checksum,
        verifier_certification_checksum=policy_admission.verifier_certification_checksum,
        trust_policy_config_checksum=policy_admission.trust_policy_config_validation_checksum,
        trust_result_checksum=policy_admission.world_snapshot_trust_result_checksum,
        policy_checksum=policy_admission.policy_checksum,
        context_authority_checksum=policy_admission.context_authority_checksum,
        policy_result_checksum=expected_policy_result,
        safety_case_checksum=expected_safety_case,
        policy_admission_checksum=expected_policy_admission,
        gate_decision_checksum=expected_gate,
    )


def receipt_matches_expected_bindings(
    *,
    receipt: ApprovalReceipt,
    raw_intent_checksum: str,
    validation_checksum: str | None,
    plan_checksum: str | None,
    audit_id: str | None,
    audited_plan_checksum: str | None,
    world_snapshot_checksum: str | None,
    admissibility_checksum: str | None,
    freshness_checksum: str | None,
    verifier_certification_checksum: str | None,
    trust_policy_config_checksum: str | None,
    trust_result_checksum: str | None,
    policy_checksum: str | None,
    context_authority_checksum: str | None,
    policy_result_checksum: str | None,
    safety_case_checksum: str | None,
    policy_admission_checksum: str | None,
    gate_decision_checksum: str | None,
) -> bool:
    """Return whether a receipt's binding fields equal supplied identities."""
    return (
        receipt.raw_intent_checksum == raw_intent_checksum
        and receipt.validation_checksum == validation_checksum
        and receipt.plan_checksum == plan_checksum
        and receipt.audit_id == audit_id
        and receipt.audited_plan_checksum == audited_plan_checksum
        and receipt.world_snapshot_checksum == world_snapshot_checksum
        and receipt.admissibility_checksum == admissibility_checksum
        and receipt.freshness_checksum == freshness_checksum
        and receipt.verifier_certification_checksum == verifier_certification_checksum
        and receipt.trust_policy_config_checksum == trust_policy_config_checksum
        and receipt.trust_result_checksum == trust_result_checksum
        and receipt.policy_checksum == policy_checksum
        and receipt.context_authority_checksum == context_authority_checksum
        and receipt.policy_result_checksum == policy_result_checksum
        and receipt.safety_case_checksum == safety_case_checksum
        and receipt.policy_admission_checksum == policy_admission_checksum
        and receipt.gate_decision_checksum == gate_decision_checksum
    )


def _missing_allowed_fields(receipt: ApprovalReceipt) -> tuple[str, ...]:
    field_names = (
        "raw_intent_checksum",
        "validation_checksum",
        "plan_checksum",
        "audit_id",
        "audited_plan_checksum",
        "world_snapshot_checksum",
        "admissibility_checksum",
        "freshness_checksum",
        "verifier_certification_checksum",
        "trust_policy_config_checksum",
        "trust_result_checksum",
        "policy_checksum",
        "context_authority_checksum",
        "policy_result_checksum",
        "safety_case_checksum",
        "policy_admission_checksum",
        "gate_decision_checksum",
        "decision_trace_checksum",
    )
    return tuple(field_name for field_name in field_names if getattr(receipt, field_name) is None)


def _stage_binding_errors(
    receipt: ApprovalReceipt,
    decision_trace: DecisionTrace,
) -> tuple[str, ...]:
    stage_outputs = {step.stage_name: step.output_checksum for step in decision_trace.steps}
    expected_bindings = {
        "raw_intent": ("raw_intent_checksum", receipt.raw_intent_checksum),
        "validation": ("validation_checksum", receipt.validation_checksum),
        "planning": ("plan_checksum", receipt.plan_checksum),
        "audit": ("audited_plan_checksum", receipt.audited_plan_checksum),
        "world_snapshot_admissibility": ("admissibility_checksum", receipt.admissibility_checksum),
        "world_snapshot_freshness": ("freshness_checksum", receipt.freshness_checksum),
        "verifier_certification": (
            "verifier_certification_checksum",
            receipt.verifier_certification_checksum,
        ),
        "trust_policy_config": (
            "trust_policy_config_checksum",
            receipt.trust_policy_config_checksum,
        ),
        "world_snapshot_trust": ("trust_result_checksum", receipt.trust_result_checksum),
        "policy_evaluation": ("policy_result_checksum", receipt.policy_result_checksum),
        "safety_case": ("safety_case_checksum", receipt.safety_case_checksum),
        "policy_admission": ("policy_admission_checksum", receipt.policy_admission_checksum),
        "gate_decision": ("gate_decision_checksum", receipt.gate_decision_checksum),
    }
    errors: list[str] = []
    for stage_name, (field_name, field_value) in expected_bindings.items():
        if stage_name in stage_outputs and field_value != stage_outputs[stage_name]:
            errors.append(field_name)
    return tuple(errors)


def _fake_stage_binding_errors(
    receipt: ApprovalReceipt,
    decision_trace: DecisionTrace,
) -> tuple[str, ...]:
    present_stages = {step.stage_name for step in decision_trace.steps}
    stage_fields = {
        "validation": ("validation_checksum", receipt.validation_checksum),
        "planning": ("plan_checksum", receipt.plan_checksum),
        "audit": ("audited_plan_checksum", receipt.audited_plan_checksum),
        "world_snapshot_admissibility": ("admissibility_checksum", receipt.admissibility_checksum),
        "world_snapshot_freshness": ("freshness_checksum", receipt.freshness_checksum),
        "verifier_certification": (
            "verifier_certification_checksum",
            receipt.verifier_certification_checksum,
        ),
        "trust_policy_config": (
            "trust_policy_config_checksum",
            receipt.trust_policy_config_checksum,
        ),
        "world_snapshot_trust": ("trust_result_checksum", receipt.trust_result_checksum),
        "policy_evaluation": ("policy_result_checksum", receipt.policy_result_checksum),
        "safety_case": ("safety_case_checksum", receipt.safety_case_checksum),
        "policy_admission": ("policy_admission_checksum", receipt.policy_admission_checksum),
        "gate_decision": ("gate_decision_checksum", receipt.gate_decision_checksum),
    }
    errors: list[str] = []
    for stage_name, (field_name, field_value) in stage_fields.items():
        if stage_name not in present_stages and field_value is not None:
            errors.append(field_name)
    return tuple(errors)


def _receipt_checksum_mismatch(receipt: ApprovalReceipt) -> bool:
    return receipt.approval_receipt_checksum != approval_receipt_checksum(
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
        policy_result_checksum=receipt.policy_result_checksum,
        policy_checksum=receipt.policy_checksum,
        context_authority_checksum=receipt.context_authority_checksum,
        safety_case_checksum=receipt.safety_case_checksum,
        policy_admission_checksum=receipt.policy_admission_checksum,
        gate_decision_checksum=receipt.gate_decision_checksum,
        decision_trace_checksum=receipt.decision_trace_checksum,
    )


def _invalid_result(
    receipt: ApprovalReceipt,
    decision_trace: DecisionTrace,
    reason: ApprovalReceiptReason,
    failed_fields: Iterable[str],
) -> ApprovalReceiptValidationResult:
    return ApprovalReceiptValidationResult(
        status=ApprovalReceiptStatus.INVALID,
        reason=reason,
        approval_receipt_checksum=receipt.approval_receipt_checksum,
        decision_trace_checksum=decision_trace.trace_checksum,
        failed_fields=failed_fields,
    )


def _sha256(payload: Mapping[str, CanonicalReceiptValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_status(status: object) -> ApprovalReceiptStatus:
    if not isinstance(status, ApprovalReceiptStatus):
        raise ValueError("status must be an ApprovalReceiptStatus")
    return status


def _normalize_reason(reason: object) -> ApprovalReceiptReason:
    if not isinstance(reason, ApprovalReceiptReason):
        raise ValueError("reason must be an ApprovalReceiptReason")
    return reason


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_optional_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    if supplied_checksum is None:
        return computed_checksum
    normalized = _normalize_required_text(supplied_checksum, field_name)
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


__all__ = [
    "ApprovalReceipt",
    "ApprovalReceiptReason",
    "ApprovalReceiptStatus",
    "ApprovalReceiptValidationResult",
    "approval_receipt_checksum",
    "approval_receipt_matches_pipeline_fields",
    "compute_approval_receipt_checksum",
    "pipeline_result_id_checksum",
    "receipt_matches_expected_bindings",
    "validate_approval_receipt",
]
