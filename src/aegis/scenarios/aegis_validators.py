"""Scenario expectation validation against pipeline receipts and traces."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping

from aegis.contracts.aegis_approval_receipt import (
    ApprovalReceipt,
    ApprovalReceiptStatus,
    ApprovalReceiptValidationResult,
    validate_approval_receipt,
)
from aegis.contracts.aegis_decision_trace import (
    DecisionTrace,
    decision_trace_checksum,
    decision_trace_integrity_errors,
    policy_admission_record_identity_checksum,
)
from aegis.contracts.aegis_pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.aegis_policy_admission import PolicyAdmissionMode
from aegis.scenarios.aegis_contracts import (
    ScenarioDefinition,
    ScenarioRunResult,
    ScenarioViolation,
    scenario_run_result_checksum,
)

type _ChecksumValue = (
    str | int | float | bool | None | list[_ChecksumValue] | dict[str, _ChecksumValue]
)

_CERTIFIED = "CERTIFIED"
_VALID = "VALID"
_FRESH = "FRESH"
_TRUSTED = "TRUSTED"


def validate_scenario_result(
    scenario: ScenarioDefinition,
    pipeline_result: PipelineResult,
    *,
    decision_trace: DecisionTrace | None = None,
    approval_receipt: ApprovalReceipt | None = None,
    forced_outcome: PipelineOutcome | None = None,
    forced_reason: str | None = None,
    forced_terminal_stage: str | None = None,
) -> ScenarioRunResult:
    """Validate a PipelineResult against a scenario expectation.

    Args:
        scenario: Immutable scenario definition.
        pipeline_result: Result returned by the real orchestrated pipeline.
        decision_trace: Optional trace override for evil-twin validation.
        approval_receipt: Optional receipt override for evil-twin validation.
        forced_outcome: Optional scenario-layer outcome for rejected evil twins.
        forced_reason: Optional scenario-layer reason for rejected evil twins.
        forced_terminal_stage: Optional scenario-layer terminal stage.

    Returns:
        A checksum-bound ScenarioRunResult.
    """
    trace = decision_trace if decision_trace is not None else pipeline_result.decision_trace
    receipt = approval_receipt if approval_receipt is not None else pipeline_result.approval_receipt
    receipt_validation = _revalidate_receipt(receipt, trace)
    stage_path = tuple(step.stage_name for step in trace.steps) if trace is not None else ()
    trace_valid = _trace_valid(trace)
    receipt_valid = (
        receipt_validation.status is ApprovalReceiptStatus.VALID
        if receipt_validation is not None
        else False
    )
    terminal_stage = forced_terminal_stage or _semantic_terminal_stage(pipeline_result, stage_path)
    actual_outcome = forced_outcome or pipeline_result.outcome
    actual_reason = forced_reason or _actual_reason(pipeline_result, terminal_stage, stage_path)
    expected = scenario.expected

    violations: list[ScenarioViolation] = []
    _append_if(
        violations,
        actual_outcome is not expected.expected_outcome,
        "SCENARIO_OUTCOME_MISMATCH",
        f"expected {expected.expected_outcome.value}, got {actual_outcome.value}",
        "actual_outcome",
    )
    _append_if(
        violations,
        actual_reason != expected.expected_reason,
        "SCENARIO_REASON_MISMATCH",
        f"expected {expected.expected_reason}, got {actual_reason}",
        "actual_reason",
    )
    _append_if(
        violations,
        terminal_stage != expected.expected_terminal_stage,
        "SCENARIO_TERMINAL_STAGE_MISMATCH",
        f"expected {expected.expected_terminal_stage}, got {terminal_stage}",
        "terminal_stage",
    )
    if expected.receipt_must_be_valid:
        missing_required = tuple(
            stage
            for stage in expected.required_stages
            if stage not in stage_path and stage not in {terminal_stage}
        )
        if missing_required:
            violations.append(
                ScenarioViolation(
                    "SCENARIO_REQUIRED_STAGE_MISSING",
                    f"missing required stages: {','.join(missing_required)}",
                    "stage_path",
                )
            )
        forbidden_present = tuple(
            stage for stage in expected.forbidden_stages if stage in stage_path
        )
        if forbidden_present:
            violations.append(
                ScenarioViolation(
                    "SCENARIO_FORBIDDEN_STAGE_PRESENT",
                    f"forbidden stages present: {','.join(forbidden_present)}",
                    "stage_path",
                )
            )
    _append_if(
        violations,
        receipt_valid is not expected.receipt_must_be_valid,
        "SCENARIO_RECEIPT_VALIDITY_MISMATCH",
        f"expected receipt_valid={expected.receipt_must_be_valid}, got {receipt_valid}",
        "receipt_valid",
    )
    _append_if(
        violations,
        expected.approval_receipt_required and receipt is None,
        "SCENARIO_APPROVAL_RECEIPT_MISSING",
        "approval receipt is required",
        "approval_receipt",
    )
    _append_if(
        violations,
        expected.receipt_must_be_valid and not trace_valid,
        "SCENARIO_TRACE_INVALID",
        "decision trace checksum or links did not recompute",
        "decision_trace",
    )
    if expected.receipt_must_be_valid and not expected.allow_late_stage_artifacts:
        violations.extend(
            _late_stage_artifact_violations(expected.forbidden_stages, pipeline_result, receipt)
        )

    pipeline_checksum = pipeline_result_checksum(
        pipeline_result,
        decision_trace=trace,
        approval_receipt=receipt,
        receipt_validation=receipt_validation,
        actual_outcome=actual_outcome,
        actual_reason=actual_reason,
        terminal_stage=terminal_stage,
    )
    passed = not violations
    result_checksum = scenario_run_result_checksum(
        scenario_id=scenario.scenario_id,
        passed=passed,
        actual_outcome=actual_outcome,
        actual_reason=actual_reason,
        expected_outcome=expected.expected_outcome,
        expected_reason=expected.expected_reason,
        terminal_stage=terminal_stage,
        receipt_valid=receipt_valid,
        trace_valid=trace_valid,
        stage_path=stage_path,
        violations=violations,
        pipeline_result_checksum=pipeline_checksum,
    )
    return ScenarioRunResult(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        passed=passed,
        actual_outcome=actual_outcome,
        actual_reason=actual_reason,
        expected_outcome=expected.expected_outcome,
        expected_reason=expected.expected_reason,
        terminal_stage=terminal_stage,
        receipt_valid=receipt_valid,
        trace_valid=trace_valid,
        stage_path=stage_path,
        violations=tuple(violations),
        pipeline_result_checksum=pipeline_checksum,
        scenario_result_checksum=result_checksum,
    )


def pipeline_result_checksum(
    pipeline_result: PipelineResult,
    *,
    decision_trace: DecisionTrace | None,
    approval_receipt: ApprovalReceipt | None,
    receipt_validation: ApprovalReceiptValidationResult | None,
    actual_outcome: PipelineOutcome,
    actual_reason: str,
    terminal_stage: str | None,
) -> str:
    """Return a deterministic checksum for the scenario-observed pipeline evidence."""
    return _sha256(
        {
            "pipeline_outcome": pipeline_result.outcome.value,
            "actual_outcome": actual_outcome.value,
            "actual_reason": actual_reason,
            "terminal_stage": terminal_stage,
            "validation_present": pipeline_result.validation_result is not None,
            "plan_id": pipeline_result.plan.plan_id if pipeline_result.plan is not None else None,
            "audit_id": pipeline_result.audited_plan.audit_id
            if pipeline_result.audited_plan is not None
            else None,
            "policy_admission_checksum": policy_admission_record_identity_checksum(
                pipeline_result.policy_admission
            ),
            "gate_status": pipeline_result.gate_decision.status.value
            if pipeline_result.gate_decision is not None
            else None,
            "decision_trace_checksum": decision_trace.trace_checksum
            if decision_trace is not None
            else None,
            "approval_receipt_checksum": approval_receipt.approval_receipt_checksum
            if approval_receipt is not None
            else None,
            "receipt_validation_status": receipt_validation.status.value
            if receipt_validation is not None
            else None,
            "receipt_validation_reason": receipt_validation.reason.value
            if receipt_validation is not None
            else None,
            "stage_path": [step.stage_name for step in decision_trace.steps]
            if decision_trace is not None
            else [],
        }
    )


def _revalidate_receipt(
    receipt: ApprovalReceipt | None,
    trace: DecisionTrace | None,
) -> ApprovalReceiptValidationResult | None:
    if receipt is None or trace is None:
        return None
    return validate_approval_receipt(receipt, trace)


def _trace_valid(trace: DecisionTrace | None) -> bool:
    if trace is None:
        return False
    return not decision_trace_integrity_errors(
        trace
    ) and trace.trace_checksum == decision_trace_checksum(trace.steps)


def _semantic_terminal_stage(
    pipeline_result: PipelineResult,
    stage_path: tuple[str, ...],
) -> str | None:
    record = pipeline_result.policy_admission
    if pipeline_result.outcome is PipelineOutcome.INVALID and stage_path == (
        "raw_intent",
        "validation",
    ):
        return "validation"
    if _status_not(record.world_snapshot_admissibility_status, "ADMISSIBLE"):
        return "world_snapshot_admissibility"
    if _status_not(record.freshness_status, _FRESH):
        return "world_snapshot_freshness"
    if _status_not(record.verifier_certification_status, _CERTIFIED):
        return "verifier_certification"
    if _status_not(record.trust_policy_config_status, _VALID):
        return "trust_policy_config"
    if _status_not(record.world_snapshot_trust_status, _TRUSTED):
        return "world_snapshot_trust"
    if record.policy_result is not None and record.policy_result.decision.value != "ALLOW":
        return "policy_evaluation"
    if record.mode is PolicyAdmissionMode.DISABLED or record.exception_reason is not None:
        return "policy_admission"
    if pipeline_result.gate_decision is not None:
        return "gate_decision"
    return stage_path[-1] if stage_path else None


def _actual_reason(
    pipeline_result: PipelineResult,
    terminal_stage: str | None,
    stage_path: tuple[str, ...],
) -> str:
    if terminal_stage == "gate_decision" and pipeline_result.gate_decision is not None:
        if pipeline_result.gate_decision.status.value == "allowed":
            return "GATE_ALLOWED"
        if pipeline_result.gate_decision.reasons:
            return pipeline_result.gate_decision.reasons[0].value
        return "GATE_BLOCKED"
    if terminal_stage == "validation" and pipeline_result.validation_result is not None:
        if pipeline_result.validation_result.violations:
            return pipeline_result.validation_result.violations[0].code.upper()
        return "VALIDATION_PASSED"
    if pipeline_result.policy_admission.reasons:
        return pipeline_result.policy_admission.reasons[-1]
    if pipeline_result.decision_trace is not None and stage_path:
        last_step = pipeline_result.decision_trace.steps[-1]
        return last_step.stage_reason or last_step.stage_status
    return pipeline_result.outcome.value.upper()


def _status_not(value: str | None, expected: str) -> bool:
    return value is not None and value != expected


def _late_stage_artifact_violations(
    forbidden_stages: Iterable[str],
    pipeline_result: PipelineResult,
    receipt: ApprovalReceipt | None,
) -> tuple[ScenarioViolation, ...]:
    violations: list[ScenarioViolation] = []
    for stage in forbidden_stages:
        if _stage_artifact_present(stage, pipeline_result, receipt):
            violations.append(
                ScenarioViolation(
                    "SCENARIO_FORBIDDEN_ARTIFACT_PRESENT",
                    f"forbidden artifact present for stage {stage}",
                    stage,
                )
            )
    return tuple(violations)


def _stage_artifact_present(
    stage: str,
    pipeline_result: PipelineResult,
    receipt: ApprovalReceipt | None,
) -> bool:
    record = pipeline_result.policy_admission
    if stage == "world_snapshot_freshness":
        return record.freshness_result_checksum is not None or _receipt_field(
            receipt, "freshness_checksum"
        )
    if stage == "verifier_certification":
        return record.verifier_certification_checksum is not None or _receipt_field(
            receipt, "verifier_certification_checksum"
        )
    if stage == "trust_policy_config":
        return record.trust_policy_config_validation_checksum is not None or _receipt_field(
            receipt, "trust_policy_config_checksum"
        )
    if stage == "world_snapshot_trust":
        return record.world_snapshot_trust_result_checksum is not None or _receipt_field(
            receipt, "trust_result_checksum"
        )
    if stage == "policy_evaluation":
        return record.policy_result is not None or _receipt_field(receipt, "policy_result_checksum")
    if stage == "safety_case":
        return record.safety_case is not None or _receipt_field(receipt, "safety_case_checksum")
    if stage == "gate_decision":
        return pipeline_result.gate_decision is not None or _receipt_field(
            receipt, "gate_decision_checksum"
        )
    return False


def _receipt_field(receipt: ApprovalReceipt | None, field_name: str) -> bool:
    if receipt is None:
        return False
    return getattr(receipt, field_name) is not None


def _append_if(
    violations: list[ScenarioViolation],
    condition: bool,
    code: str,
    message: str,
    field: str,
) -> None:
    if condition:
        violations.append(ScenarioViolation(code, message, field))


def _sha256(payload: Mapping[str, _ChecksumValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["pipeline_result_checksum", "validate_scenario_result"]
