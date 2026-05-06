"""Deterministic pipeline orchestrator with optional policy admission."""

from __future__ import annotations

from aegis.audit import build_audited_plan
from aegis.constants import GATE_VERSION, PIPELINE_VERSION
from aegis.contracts.audit import AuditedPlan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.policy import PolicyDecision, PolicyEvaluationResult, SafetyCase
from aegis.contracts.policy_admission import (
    PolicyAdmissionDecision,
    PolicyAdmissionInput,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    disabled_policy_admission_record,
    is_policy_backed_approval,
)
from aegis.errors import AegisError, PolicyAdmissionIntegrityError
from aegis.gate import gate_audited_plan
from aegis.planning import plan_validated_intent
from aegis.policy import build_safety_case, evaluate_policy
from aegis.validation import validate_intent


def run_pipeline(
    raw_intent: RawIntent,
    context: ExecutionContext,
    *,
    policy_admission: PolicyAdmissionInput | None = None,
) -> PipelineResult:
    """Run raw intent through the Aegis pipeline.

    Composes ``validate_intent`` -> ``plan_validated_intent`` ->
    ``build_audited_plan`` -> optional policy admission ->
    ``gate_audited_plan`` deterministically.

    ``AegisError`` subclasses (``ValidationError``, ``PlanningError``,
    ``AuditError``, ``GateError``) propagate to the caller unchanged.

    Only unexpected non-``AegisError`` exceptions are caught and returned
    as ``PipelineOutcome.ERROR`` with the fields populated up to the point
    of failure.  This narrow boundary mirrors the scenario runner harness
    policy and must not be copied into layer implementations.

    Args:
        raw_intent: Validated boundary object carrying raw intent data.
        context: Injected execution context for deterministic replay.
        policy_admission: Optional explicit Policy-v1 admission input. ``None``
            preserves legacy disabled-mode gate behaviour.

    Returns:
        A ``PipelineResult`` with outcome ``ALLOWED``, ``BLOCKED``,
        ``INVALID``, or ``ERROR``.
    """
    admission_input = _normalize_policy_admission(policy_admission)
    return _run(raw_intent, context, admission_input)


def _run(
    raw_intent: RawIntent,
    context: ExecutionContext,
    policy_admission: PolicyAdmissionInput,
) -> PipelineResult:
    """Inner pipeline composition — separated for testability."""
    initial_policy_record = _not_run_policy_record(policy_admission)

    # Step 1: Validate — always runs; produces ValidationResult.
    try:
        validation_result = validate_intent(raw_intent)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        # validate_intent is a pure function with no expected exceptions beyond
        # AegisError; any non-AegisError here is a framework-level failure.
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=initial_policy_record,
        )

    if not validation_result.is_valid:
        return PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=initial_policy_record,
        )

    # Step 2: Plan — only when validation passed.
    # PlanningError propagates to caller.
    try:
        plan = plan_validated_intent(validation_result)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=initial_policy_record,
        )

    # Step 3: Audit — produces AuditedPlan.
    # AuditError propagates to caller.
    try:
        audited_plan = build_audited_plan(plan)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=None,
            gate_decision=None,
            policy_admission=initial_policy_record,
        )

    # Step 4: Optional policy admission — only after audit, before gate.
    policy_record, blocked_outcome = _evaluate_policy_admission(
        policy_admission=policy_admission,
        audited_plan=audited_plan,
    )
    if blocked_outcome is not None:
        return PipelineResult(
            outcome=blocked_outcome,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
            policy_admission=policy_record,
        )

    # Step 5: Gate — final deterministic gate over an already policy-admitted plan.
    # GateError propagates to caller.
    try:
        decision = gate_audited_plan(audited_plan)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
            policy_admission=_error_policy_record(policy_record, "GATE_DECISION_FAILED"),
        )

    if decision.status == "allowed" and not is_policy_backed_approval(
        audited_plan, policy_record, decision
    ):
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
            policy_admission=_integrity_failed_policy_record(policy_record),
        )

    outcome = PipelineOutcome.ALLOWED if decision.status == "allowed" else PipelineOutcome.BLOCKED
    return PipelineResult(
        outcome=outcome,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=decision,
        policy_admission=policy_record,
    )


def _normalize_policy_admission(
    policy_admission: PolicyAdmissionInput | None,
) -> PolicyAdmissionInput:
    if policy_admission is None:
        return PolicyAdmissionInput(mode=PolicyAdmissionMode.DISABLED)
    return policy_admission


def _not_run_policy_record(policy_admission: PolicyAdmissionInput) -> PolicyAdmissionRecord:
    if policy_admission.mode is PolicyAdmissionMode.DISABLED:
        return disabled_policy_admission_record()
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_ADMISSION_NOT_RUN",),
        admission_decision=PolicyAdmissionDecision.NOT_RUN,
    )


def _evaluate_policy_admission(
    *,
    policy_admission: PolicyAdmissionInput,
    audited_plan: AuditedPlan,
) -> tuple[PolicyAdmissionRecord, PipelineOutcome | None]:
    if policy_admission.mode is PolicyAdmissionMode.DISABLED:
        return disabled_policy_admission_record(), PipelineOutcome.BLOCKED

    if policy_admission.policy is None:
        return _denied_policy_record("POLICY_REQUIRED"), PipelineOutcome.BLOCKED
    if policy_admission.capability is None:
        return _denied_policy_record("CAPABILITY_REQUIRED"), PipelineOutcome.BLOCKED

    try:
        policy_result = evaluate_policy(
            policy=policy_admission.policy,
            capability=policy_admission.capability,
            world_snapshot=policy_admission.world_snapshot,
            context=policy_admission.context,
        )
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return (
            _denied_policy_record(
                "POLICY_EVALUATION_FAILED",
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="POLICY_EVALUATION_FAILED",
            ),
            PipelineOutcome.ERROR,
        )

    try:
        safety_case = build_safety_case(
            policy_result=policy_result,
            audited_plan_id=audited_plan.audit_id,
            world_snapshot=policy_admission.world_snapshot,
            evidence=_safety_case_evidence(policy_admission, audited_plan),
            plan_id=audited_plan.plan.plan_id,
            plan_checksum=audited_plan.checksum,
            capability=policy_admission.capability,
        )
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return (
            _denied_policy_record(
                "SAFETY_CASE_BUILD_FAILED",
                policy_result=_policy_result_or_none(policy_result),
                safety_case=None,
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="SAFETY_CASE_BUILD_FAILED",
            ),
            PipelineOutcome.ERROR,
        )

    policy_record: PolicyAdmissionRecord | None = None
    try:
        policy_record = _policy_record_from_result(policy_result, safety_case, audited_plan)
        if policy_record.admission_allowed:
            assert_policy_admission_integrity(audited_plan, policy_record)
    except PolicyAdmissionIntegrityError:
        if policy_record is None:
            return (
                _denied_policy_record(
                    "POLICY_ADMISSION_INTEGRITY_FAILED",
                    policy_result=_policy_result_or_none(policy_result),
                    safety_case=safety_case,
                    admission_decision=PolicyAdmissionDecision.ERROR,
                    integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                    exception_reason="POLICY_ADMISSION_INTEGRITY_FAILED",
                ),
                PipelineOutcome.ERROR,
            )
        return _integrity_failed_policy_record(policy_record), PipelineOutcome.ERROR
    except Exception:  # noqa: BLE001
        return (
            _denied_policy_record(
                "POLICY_ADMISSION_RECORD_FAILED",
                policy_result=_policy_result_or_none(policy_result),
                safety_case=safety_case,
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="POLICY_ADMISSION_RECORD_FAILED",
            ),
            PipelineOutcome.ERROR,
        )
    assert policy_record is not None
    if policy_record.admission_allowed:
        return policy_record, None
    return policy_record, _blocked_policy_outcome(policy_result)


def _denied_policy_record(
    reason: str,
    *,
    policy_result: PolicyEvaluationResult | None = None,
    safety_case: SafetyCase | None = None,
    admission_decision: PolicyAdmissionDecision | None = None,
    integrity_status: PolicyAdmissionIntegrityStatus | None = None,
    exception_reason: str | None = None,
) -> PolicyAdmissionRecord:
    reasons = (reason,) if policy_result is None else _with_reason(policy_result.reasons, reason)
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=policy_result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=False,
        reasons=reasons,
        admission_decision=admission_decision,
        integrity_status=integrity_status,
        exception_reason=exception_reason,
    )


def _policy_result_or_none(value: object) -> PolicyEvaluationResult | None:
    if isinstance(value, PolicyEvaluationResult):
        return value
    return None


def _policy_record_from_result(
    policy_result: PolicyEvaluationResult,
    safety_case: SafetyCase,
    audited_plan: AuditedPlan,
) -> PolicyAdmissionRecord:
    admission_allowed = policy_result.decision is PolicyDecision.ALLOW
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=policy_result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=admission_allowed,
        reasons=_with_reason(
            policy_result.reasons, _policy_decision_reason(policy_result.decision)
        ),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
        admission_decision=PolicyAdmissionDecision(policy_result.decision.value),
        integrity_status=(
            PolicyAdmissionIntegrityStatus.PASSED
            if admission_allowed
            else PolicyAdmissionIntegrityStatus.NOT_CHECKED
        ),
    )


def _integrity_failed_policy_record(policy_record: PolicyAdmissionRecord) -> PolicyAdmissionRecord:
    return _error_policy_record(policy_record, "POLICY_ADMISSION_INTEGRITY_FAILED")


def _error_policy_record(
    policy_record: PolicyAdmissionRecord,
    reason: str,
) -> PolicyAdmissionRecord:
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.ENFORCE,
        policy_result=policy_record.policy_result,
        safety_case=policy_record.safety_case,
        enforced=True,
        admission_allowed=False,
        reasons=_with_reason(policy_record.reasons, reason),
        audit_id=policy_record.audit_id,
        plan_id=policy_record.plan_id,
        plan_checksum=policy_record.plan_checksum,
        policy_id=policy_record.policy_id,
        policy_result_checksum=policy_record.policy_result_checksum,
        safety_case_id=policy_record.safety_case_id,
        world_snapshot_id=policy_record.world_snapshot_id,
        world_snapshot_checksum=policy_record.world_snapshot_checksum,
        capability_name=policy_record.capability_name,
        capability_version=policy_record.capability_version,
        admission_decision=PolicyAdmissionDecision.ERROR,
        integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
        exception_reason=reason,
    )


def _blocked_policy_outcome(policy_result: PolicyEvaluationResult) -> PipelineOutcome:
    if policy_result.decision is PolicyDecision.INVALID:
        return PipelineOutcome.INVALID
    if policy_result.decision is PolicyDecision.ERROR:
        return PipelineOutcome.ERROR
    return PipelineOutcome.BLOCKED


def _policy_decision_reason(decision: PolicyDecision) -> str:
    if decision is PolicyDecision.ALLOW:
        return "POLICY_ALLOWED"
    if decision is PolicyDecision.BLOCK:
        return "POLICY_BLOCKED"
    if decision is PolicyDecision.REQUIRE_REVIEW:
        return "POLICY_REQUIRES_REVIEW"
    if decision is PolicyDecision.INVALID:
        return "POLICY_INVALID"
    return "POLICY_ERROR"


def _with_reason(reasons: tuple[str, ...], reason: str) -> tuple[str, ...]:
    if reason in reasons:
        return reasons
    return (*reasons, reason)


def _safety_case_evidence(
    policy_admission: PolicyAdmissionInput,
    audited_plan: AuditedPlan,
) -> dict[str, object]:
    evidence: dict[str, object] = {key: value for key, value in policy_admission.evidence.items()}
    capability = policy_admission.capability
    if capability is not None:
        evidence["capability_name"] = capability.name
        evidence["capability_version"] = capability.version
    evidence["pipeline_stage"] = "policy_admission"
    evidence["pipeline_version"] = PIPELINE_VERSION
    evidence["gate_version"] = GATE_VERSION
    evidence["audit_id"] = audited_plan.audit_id
    evidence["audited_plan_id"] = audited_plan.audit_id
    evidence["plan_id"] = audited_plan.plan.plan_id
    return evidence
