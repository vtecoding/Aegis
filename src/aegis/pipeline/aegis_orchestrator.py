"""Deterministic pipeline orchestrator with optional policy admission."""

from __future__ import annotations

from typing import TypedDict

from aegis.aegis_constants import GATE_VERSION, PIPELINE_VERSION
from aegis.aegis_errors import AegisError, PolicyAdmissionIntegrityError
from aegis.audit import build_audited_plan
from aegis.contracts.aegis_approval_receipt import ApprovalReceiptStatus
from aegis.contracts.aegis_attestation_verifier import (
    VerifierAdapterCertificationResult,
    VerifierCertificationStatus,
    certify_attestation_verifier_adapter,
)
from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_gate import GateDecision
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.aegis_planning import CommandPlan
from aegis.contracts.aegis_policy import PolicyDecision, PolicyEvaluationResult, SafetyCase
from aegis.contracts.aegis_policy_admission import (
    PolicyAdmissionDecision,
    PolicyAdmissionInput,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    disabled_policy_admission_record,
    is_policy_backed_approval,
)
from aegis.contracts.aegis_trust_policy_config import (
    TrustPolicyConfigStatus,
    TrustPolicyConfigValidationResult,
    validate_trust_policy_config,
)
from aegis.contracts.aegis_validation import ValidationResult
from aegis.contracts.aegis_world_snapshot_admissibility import (
    WorldSnapshotAdmissibilityStatus,
    validate_world_snapshot_admissibility,
)
from aegis.contracts.aegis_world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    FreshnessPolicy,
    WorldSnapshotFreshnessResult,
    WorldSnapshotFreshnessStatus,
    validate_world_snapshot_freshness,
)
from aegis.contracts.aegis_world_snapshot_trust import (
    AttestationVerifier,
    TrustDomain,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotTrustPolicy,
    WorldSnapshotTrustResult,
    WorldSnapshotTrustStatus,
    evaluate_world_snapshot_trust,
)
from aegis.gate import gate_audited_plan
from aegis.governance.aegis_context_authority import ContextAuthority
from aegis.pipeline.aegis_approval_receipt import build_approval_receipt, validate_approval_receipt
from aegis.pipeline.aegis_decision_trace import build_decision_trace
from aegis.planning import plan_validated_intent
from aegis.policy import build_safety_case, evaluate_policy
from aegis.validation import validate_intent


class _TrustRecordKwargs(TypedDict, total=False):
    world_snapshot_admissibility_status: str | None
    world_snapshot_admissibility_reason_code: str | None
    world_snapshot_admissibility_result_checksum: str | None
    world_snapshot_trust_status: str
    world_snapshot_trust_reason_code: str
    world_snapshot_trust_result_checksum: str
    evidence_envelope_checksum: str | None
    attestation_checksum: str | None
    trust_policy_checksum: str | None
    verifier_certification_status: str | None
    verifier_certification_reason_code: str | None
    verifier_certification_checksum: str | None
    verifier_id: str | None
    verifier_metadata_checksum: str | None
    trust_policy_config_status: str | None
    trust_policy_config_reason_code: str | None
    trust_policy_config_validation_checksum: str | None
    source_id: str | None
    source_type: str | None
    trust_domain: str | None


def run_pipeline(
    raw_intent: RawIntent,
    context: ExecutionContext,
    *,
    policy_admission: PolicyAdmissionInput | None = None,
    context_authority: ContextAuthority | None = None,
    evaluation_time_ms: int | None = None,
    freshness_policy: FreshnessPolicy = DEFAULT_FRESHNESS_POLICY,
    world_snapshot_evidence: WorldSnapshotEvidenceEnvelope | None = None,
    world_snapshot_trust_policy: WorldSnapshotTrustPolicy | None = None,
    attestation_verifier: AttestationVerifier | None = None,
    runtime_trust_domain: TrustDomain = TrustDomain.SIMULATION,
) -> PipelineResult:
    """Run raw intent through the Aegis pipeline.

    Composes ``validate_intent`` -> ``plan_validated_intent`` ->
    ``build_audited_plan`` -> optional world snapshot freshness gate ->
    optional policy admission -> ``gate_audited_plan`` deterministically.

    ``AegisError`` subclasses (``ValidationError``, ``PlanningError``,
    ``AuditError``, ``GateError``) propagate to the caller unchanged.

    Only unexpected non-``AegisError`` exceptions are caught and returned
    as ``PipelineOutcome.ERROR`` with the fields populated up to the point
    of failure.

    Phase 2 Part 5: when policy admission is enforced, the world snapshot must
    pass deterministic freshness validation against ``evaluation_time_ms``
    before policy evaluation. Stale, missing, malformed, or freshness-unchecked
    snapshots fail closed and cannot produce ``PipelineOutcome.ALLOWED``.

    Phase 2 Part 6: enforced admission also requires deterministic world
    snapshot trust evaluation after freshness and before policy evaluation.
    Fresh but untrusted evidence fails closed before policy evaluation.

    Args:
        raw_intent: Validated boundary object carrying raw intent data.
        context: Injected execution context for deterministic replay.
        policy_admission: Optional explicit Policy-v1 admission input. ``None``
            preserves legacy disabled-mode gate behaviour.
        evaluation_time_ms: Caller-supplied evaluation time in milliseconds for
            the freshness gate. Required for ENFORCE mode with a snapshot.
            Never derived from system time.
        freshness_policy: Caller-supplied freshness policy. Defaults to
            ``DEFAULT_FRESHNESS_POLICY``.
        world_snapshot_evidence: Optional provenance envelope for the supplied
            world snapshot. Required for enforced approval.
        world_snapshot_trust_policy: Optional deterministic source/domain/
            capability trust policy. Required for enforced approval.
        attestation_verifier: Optional deterministic verifier used when the
            trust policy requires attestation.
        runtime_trust_domain: Caller-supplied runtime domain for deterministic
            verifier and trust-policy configuration certification.

    Returns:
        A ``PipelineResult`` with outcome ``ALLOWED``, ``BLOCKED``,
        ``INVALID``, or ``ERROR``.
    """
    admission_input = _normalize_policy_admission(policy_admission)
    return _run(
        raw_intent,
        context,
        admission_input,
        context_authority,
        evaluation_time_ms,
        freshness_policy,
        world_snapshot_evidence,
        world_snapshot_trust_policy,
        attestation_verifier,
        runtime_trust_domain,
    )


def _run(
    raw_intent: RawIntent,
    context: ExecutionContext,
    policy_admission: PolicyAdmissionInput,
    context_authority: ContextAuthority | None,
    evaluation_time_ms: int | None,
    freshness_policy: FreshnessPolicy,
    world_snapshot_evidence: WorldSnapshotEvidenceEnvelope | None,
    world_snapshot_trust_policy: WorldSnapshotTrustPolicy | None,
    attestation_verifier: AttestationVerifier | None,
    runtime_trust_domain: TrustDomain,
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
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
            outcome=PipelineOutcome.ERROR,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=None,
            policy_admission=initial_policy_record,
        )

    if not validation_result.is_valid:
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
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
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
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
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
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
        context_authority=context_authority,
        evaluation_time_ms=evaluation_time_ms,
        freshness_policy=freshness_policy,
        world_snapshot_evidence=world_snapshot_evidence,
        world_snapshot_trust_policy=world_snapshot_trust_policy,
        attestation_verifier=attestation_verifier,
        runtime_trust_domain=runtime_trust_domain,
    )
    if blocked_outcome is not None:
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
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
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
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
        return _pipeline_result(
            raw_intent=raw_intent,
            context=context,
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
            policy_admission=_integrity_failed_policy_record(policy_record),
        )

    outcome = PipelineOutcome.ALLOWED if decision.status == "allowed" else PipelineOutcome.BLOCKED
    return _pipeline_result(
        raw_intent=raw_intent,
        context=context,
        outcome=outcome,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=decision,
        policy_admission=policy_record,
    )


def _pipeline_result(
    *,
    raw_intent: RawIntent,
    context: ExecutionContext,
    outcome: PipelineOutcome,
    validation_result: object,
    plan: CommandPlan | None,
    audited_plan: AuditedPlan | None,
    gate_decision: object,
    policy_admission: PolicyAdmissionRecord,
) -> PipelineResult:
    typed_validation_result = (
        validation_result if isinstance(validation_result, ValidationResult) else None
    )
    typed_gate_decision = gate_decision if isinstance(gate_decision, GateDecision) else None
    decision_trace = build_decision_trace(
        raw_intent=raw_intent,
        context=context,
        validation_result=typed_validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=typed_gate_decision,
        policy_admission=policy_admission,
    )
    approval_receipt = build_approval_receipt(
        pipeline_outcome=outcome.value,
        raw_intent=raw_intent,
        decision_trace=decision_trace,
        validation_result=typed_validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=typed_gate_decision,
        policy_admission=policy_admission,
    )
    receipt_validation = validate_approval_receipt(approval_receipt, decision_trace)
    if (
        outcome is PipelineOutcome.ALLOWED
        and receipt_validation.status is not ApprovalReceiptStatus.VALID
    ):
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=typed_validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
            policy_admission=_error_policy_record(
                policy_admission, "APPROVAL_RECEIPT_INTEGRITY_FAILED"
            ),
            decision_trace=decision_trace,
            approval_receipt=approval_receipt,
            receipt_validation=receipt_validation,
        )
    return PipelineResult(
        outcome=outcome,
        validation_result=typed_validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=typed_gate_decision,
        policy_admission=policy_admission,
        decision_trace=decision_trace,
        approval_receipt=approval_receipt,
        receipt_validation=receipt_validation,
    )


def _normalize_policy_admission(
    policy_admission: PolicyAdmissionInput | None,
) -> PolicyAdmissionInput:
    if policy_admission is None:
        return PolicyAdmissionInput(mode=PolicyAdmissionMode.DISABLED)
    return policy_admission


def _observed_at_or_none(result: WorldSnapshotFreshnessResult) -> int | None:
    """Convert the freshness result observed_at sentinel ``-1`` to ``None``."""
    return result.observed_at_ms if result.observed_at_ms >= 0 else None


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
    context_authority: ContextAuthority | None,
    evaluation_time_ms: int | None,
    freshness_policy: FreshnessPolicy,
    world_snapshot_evidence: WorldSnapshotEvidenceEnvelope | None,
    world_snapshot_trust_policy: WorldSnapshotTrustPolicy | None,
    attestation_verifier: AttestationVerifier | None,
    runtime_trust_domain: TrustDomain,
) -> tuple[PolicyAdmissionRecord, PipelineOutcome | None]:
    if policy_admission.mode is PolicyAdmissionMode.DISABLED:
        return disabled_policy_admission_record(), PipelineOutcome.BLOCKED

    if policy_admission.policy is None:
        return _denied_policy_record("POLICY_REQUIRED"), PipelineOutcome.BLOCKED
    if policy_admission.capability is None:
        return _denied_policy_record("CAPABILITY_REQUIRED"), PipelineOutcome.BLOCKED

    admissibility_result = validate_world_snapshot_admissibility(
        policy_admission.world_snapshot,
        requested_capability=policy_admission.capability.name,
    )
    if admissibility_result.status is not WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
        return (
            _denied_policy_record(
                _admissibility_block_reason(admissibility_result.status),
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
            ),
            PipelineOutcome.BLOCKED,
        )

    # Phase 2 Part 5: deterministic world snapshot freshness gate.
    try:
        freshness_result = validate_world_snapshot_freshness(
            policy_admission.world_snapshot,
            evaluation_time_ms=evaluation_time_ms,
            freshness_policy=freshness_policy,
            admissibility_result=admissibility_result,
        )
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return (
            _denied_policy_record(
                "WORLD_SNAPSHOT_FRESHNESS_FAILED",
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="WORLD_SNAPSHOT_FRESHNESS_FAILED",
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
            ),
            PipelineOutcome.ERROR,
        )

    if freshness_result.status is not WorldSnapshotFreshnessStatus.FRESH:
        reason, outcome = _freshness_block_reason_and_outcome(freshness_result.status)
        return (
            _denied_policy_record(
                reason,
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
            ),
            outcome,
        )

    verifier_certification = certify_attestation_verifier_adapter(
        attestation_verifier,
        enforce_mode=True,
        runtime_domain=runtime_trust_domain,
    )
    if verifier_certification.status is not VerifierCertificationStatus.CERTIFIED:
        return (
            _denied_policy_record(
                verifier_certification.reason_code,
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
                verifier_certification=verifier_certification,
            ),
            PipelineOutcome.BLOCKED,
        )

    verifier_metadata = attestation_verifier.metadata if attestation_verifier is not None else None
    trust_policy_config_validation = validate_trust_policy_config(
        world_snapshot_trust_policy,
        verifier_metadata=verifier_metadata,
        runtime_domain=runtime_trust_domain,
        capability=policy_admission.capability.name,
        enforce_mode=True,
    )
    if trust_policy_config_validation.status is not TrustPolicyConfigStatus.VALID:
        return (
            _denied_policy_record(
                trust_policy_config_validation.reason_code,
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.BLOCKED,
        )

    try:
        trust_result = evaluate_world_snapshot_trust(
            world_snapshot=policy_admission.world_snapshot,
            freshness_result=freshness_result,
            evidence_envelope=world_snapshot_evidence,
            trust_policy=world_snapshot_trust_policy,
            capability=policy_admission.capability.name,
            evaluation_time_ms=evaluation_time_ms,
            admissibility_result=admissibility_result,
            attestation_verifier=attestation_verifier,
            verifier_certification=verifier_certification,
            trust_policy_config_validation=trust_policy_config_validation,
        )
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return (
            _denied_policy_record(
                "WORLD_SNAPSHOT_TRUST_FAILED",
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="WORLD_SNAPSHOT_TRUST_FAILED",
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                world_snapshot_admissibility_status=admissibility_result.status.value,
                world_snapshot_admissibility_reason_code=admissibility_result.reason_code,
                world_snapshot_admissibility_result_checksum=admissibility_result.checksum,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.ERROR,
        )

    if trust_result.status is not WorldSnapshotTrustStatus.TRUSTED:
        reason, outcome = _trust_block_reason_and_outcome(trust_result.status)
        return (
            _denied_policy_record(
                reason,
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                trust_result=trust_result,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            outcome,
        )

    try:
        policy_result = _policy_result_or_none(
            evaluate_policy(
                policy=policy_admission.policy,
                capability=policy_admission.capability,
                world_snapshot=policy_admission.world_snapshot,
                context=policy_admission.context,
                freshness_result=freshness_result,
                trust_result=trust_result,
                context_authority_checksum=context_authority.context_checksum
                if context_authority is not None
                else None,
            )
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
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                trust_result=trust_result,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.ERROR,
        )

    if policy_result is None:
        return (
            _denied_policy_record(
                "POLICY_EVALUATION_FAILED",
                admission_decision=PolicyAdmissionDecision.ERROR,
                integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
                exception_reason="POLICY_EVALUATION_FAILED",
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                trust_result=trust_result,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.ERROR,
        )

    if policy_result.decision is PolicyDecision.ALLOW:
        if context_authority is None:
            return (
                _denied_policy_record(
                    "CONTEXT_AUTHORITY_REQUIRED",
                    policy_result=_policy_result_or_none(policy_result),
                    trust_result=trust_result,
                    verifier_certification=verifier_certification,
                    trust_policy_config_validation=trust_policy_config_validation,
                ),
                PipelineOutcome.BLOCKED,
            )
        if evaluation_time_ms != context_authority.evaluation_time_ms:
            return (
                _denied_policy_record(
                    "CONTEXT_AUTHORITY_EVALUATION_TIME_MISMATCH",
                    policy_result=_policy_result_or_none(policy_result),
                    trust_result=trust_result,
                    verifier_certification=verifier_certification,
                    trust_policy_config_validation=trust_policy_config_validation,
                ),
                PipelineOutcome.BLOCKED,
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
            world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
            freshness_result_checksum=freshness_result.checksum,
            freshness_status=freshness_result.status.value,
            trust_result=trust_result,
            context_authority_checksum=context_authority.context_checksum
            if context_authority is not None
            else None,
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
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                trust_result=trust_result,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.ERROR,
        )

    policy_record: PolicyAdmissionRecord | None = None
    try:
        policy_record = _policy_record_from_result(
            policy_result,
            safety_case,
            audited_plan,
            freshness_result,
            trust_result,
            verifier_certification,
            trust_policy_config_validation,
            context_authority,
        )
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
                    world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                    freshness_result_checksum=freshness_result.checksum,
                    freshness_status=freshness_result.status.value,
                    trust_result=trust_result,
                    verifier_certification=verifier_certification,
                    trust_policy_config_validation=trust_policy_config_validation,
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
                world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
                freshness_result_checksum=freshness_result.checksum,
                freshness_status=freshness_result.status.value,
                trust_result=trust_result,
                verifier_certification=verifier_certification,
                trust_policy_config_validation=trust_policy_config_validation,
            ),
            PipelineOutcome.ERROR,
        )
    assert policy_record is not None
    if policy_record.admission_allowed:
        return policy_record, None
    return policy_record, _blocked_policy_outcome(policy_result)


def _freshness_block_reason_and_outcome(
    status: WorldSnapshotFreshnessStatus,
) -> tuple[str, PipelineOutcome]:
    if status is WorldSnapshotFreshnessStatus.STALE:
        return "WORLD_SNAPSHOT_STALE", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.MISSING_SNAPSHOT:
        return "WORLD_SNAPSHOT_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.MISSING_TIMESTAMP:
        return "WORLD_SNAPSHOT_MISSING_TIMESTAMP", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.MISSING_EVALUATION_TIME:
        return "WORLD_SNAPSHOT_MISSING_EVALUATION_TIME", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.FUTURE_DATED:
        return "WORLD_SNAPSHOT_FUTURE_DATED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.SNAPSHOT_ID_MISSING:
        return "WORLD_SNAPSHOT_ID_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotFreshnessStatus.CONTRADICTORY_METADATA:
        return "WORLD_SNAPSHOT_CONTRADICTORY_METADATA", PipelineOutcome.INVALID
    if status is WorldSnapshotFreshnessStatus.INVALID_MAX_AGE:
        return "WORLD_SNAPSHOT_INVALID_MAX_AGE", PipelineOutcome.INVALID
    if status is WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP:
        return "WORLD_SNAPSHOT_INVALID_TIMESTAMP", PipelineOutcome.INVALID
    if status is WorldSnapshotFreshnessStatus.NOT_CHECKED:
        return "WORLD_SNAPSHOT_NOT_CHECKED", PipelineOutcome.BLOCKED
    return "WORLD_SNAPSHOT_FRESHNESS_ERROR", PipelineOutcome.ERROR


def _admissibility_block_reason(status: WorldSnapshotAdmissibilityStatus) -> str:
    if status is WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING:
        return "WORLD_SNAPSHOT_MISSING"
    if status is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED:
        return "WORLD_SNAPSHOT_MALFORMED"
    if status is WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_MISSING:
        return "WORLD_SNAPSHOT_CHECKSUM_MISSING"
    if status is WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_EMPTY:
        return "WORLD_SNAPSHOT_CHECKSUM_EMPTY"
    if status is WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISMATCH:
        return "WORLD_SNAPSHOT_CAPABILITY_SCOPE_MISMATCH"
    if status is WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISSING:
        return "WORLD_SNAPSHOT_CAPABILITY_SCOPE_MISSING"
    if status is WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_EMPTY:
        return "WORLD_SNAPSHOT_CAPABILITY_SCOPE_EMPTY"
    if status is WorldSnapshotAdmissibilityStatus.DECLARED_FACT_KEY_MISSING:
        return "WORLD_SNAPSHOT_DECLARED_FACT_KEY_MISSING"
    if status is WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_MISSING:
        return "WORLD_SNAPSHOT_REQUIRED_FACT_KEY_MISSING"
    if status is WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_UNDECLARED:
        return "WORLD_SNAPSHOT_REQUIRED_FACT_KEY_UNDECLARED"
    if status is WorldSnapshotAdmissibilityStatus.CONTRADICTORY_SNAPSHOT_EVIDENCE:
        return "WORLD_SNAPSHOT_CONTRADICTORY_EVIDENCE"
    return "WORLD_SNAPSHOT_NOT_ADMISSIBLE"


def _trust_block_reason_and_outcome(
    status: WorldSnapshotTrustStatus,
) -> tuple[str, PipelineOutcome]:
    if status is WorldSnapshotTrustStatus.MISSING_EVIDENCE:
        return "WORLD_SNAPSHOT_EVIDENCE_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.MISSING_TRUST_POLICY:
        return "WORLD_SNAPSHOT_TRUST_POLICY_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.MISSING_VERIFIER:
        return "WORLD_SNAPSHOT_ATTESTATION_VERIFIER_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.MALFORMED_EVIDENCE:
        return "WORLD_SNAPSHOT_TRUST_MALFORMED_EVIDENCE", PipelineOutcome.INVALID
    if status is WorldSnapshotTrustStatus.CONTRADICTORY_EVIDENCE:
        return "WORLD_SNAPSHOT_TRUST_CONTRADICTORY_EVIDENCE", PipelineOutcome.INVALID
    if status is WorldSnapshotTrustStatus.SNAPSHOT_CHECKSUM_MISMATCH:
        return "WORLD_SNAPSHOT_TRUST_CHECKSUM_MISMATCH", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.SOURCE_NOT_ALLOWED:
        return "WORLD_SNAPSHOT_SOURCE_NOT_ALLOWED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.SOURCE_TYPE_NOT_ALLOWED:
        return "WORLD_SNAPSHOT_SOURCE_TYPE_NOT_ALLOWED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.TRUST_DOMAIN_NOT_ALLOWED:
        return "WORLD_SNAPSHOT_TRUST_DOMAIN_NOT_ALLOWED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.CAPABILITY_NOT_ALLOWED:
        return "WORLD_SNAPSHOT_CAPABILITY_NOT_ALLOWED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.ATTESTATION_MISSING:
        return "WORLD_SNAPSHOT_ATTESTATION_MISSING", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.ATTESTATION_EXPIRED:
        return "WORLD_SNAPSHOT_ATTESTATION_EXPIRED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.ATTESTATION_NOT_YET_VALID:
        return "WORLD_SNAPSHOT_ATTESTATION_NOT_YET_VALID", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.UNSUPPORTED_ATTESTATION_ALGORITHM:
        return "WORLD_SNAPSHOT_ATTESTATION_ALGORITHM_UNSUPPORTED", PipelineOutcome.BLOCKED
    if status is WorldSnapshotTrustStatus.ATTESTATION_INVALID:
        return "WORLD_SNAPSHOT_ATTESTATION_INVALID", PipelineOutcome.BLOCKED
    return "WORLD_SNAPSHOT_UNTRUSTED", PipelineOutcome.BLOCKED


def _denied_policy_record(
    reason: str,
    *,
    policy_result: PolicyEvaluationResult | None = None,
    safety_case: SafetyCase | None = None,
    admission_decision: PolicyAdmissionDecision | None = None,
    integrity_status: PolicyAdmissionIntegrityStatus | None = None,
    exception_reason: str | None = None,
    world_snapshot_observed_at_ms: int | None = None,
    freshness_result_checksum: str | None = None,
    freshness_status: str | None = None,
    world_snapshot_admissibility_status: str | None = None,
    world_snapshot_admissibility_reason_code: str | None = None,
    world_snapshot_admissibility_result_checksum: str | None = None,
    trust_result: WorldSnapshotTrustResult | None = None,
    verifier_certification: VerifierAdapterCertificationResult | None = None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None = None,
) -> PolicyAdmissionRecord:
    reasons = (reason,) if policy_result is None else _with_reason(policy_result.reasons, reason)
    trust_kwargs = _record_binding_kwargs(
        trust_result, verifier_certification, trust_policy_config_validation
    )
    if world_snapshot_admissibility_status is not None:
        trust_kwargs["world_snapshot_admissibility_status"] = world_snapshot_admissibility_status
    if world_snapshot_admissibility_reason_code is not None:
        trust_kwargs["world_snapshot_admissibility_reason_code"] = (
            world_snapshot_admissibility_reason_code
        )
    if world_snapshot_admissibility_result_checksum is not None:
        trust_kwargs["world_snapshot_admissibility_result_checksum"] = (
            world_snapshot_admissibility_result_checksum
        )
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
        world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
        freshness_result_checksum=freshness_result_checksum,
        freshness_status=freshness_status,
        **trust_kwargs,
    )


def _policy_result_or_none(value: object) -> PolicyEvaluationResult | None:
    if isinstance(value, PolicyEvaluationResult):
        return value
    return None


def _policy_record_from_result(
    policy_result: PolicyEvaluationResult,
    safety_case: SafetyCase,
    audited_plan: AuditedPlan,
    freshness_result: WorldSnapshotFreshnessResult,
    trust_result: WorldSnapshotTrustResult,
    verifier_certification: VerifierAdapterCertificationResult,
    trust_policy_config_validation: TrustPolicyConfigValidationResult,
    context_authority: ContextAuthority | None,
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
        policy_version=policy_result.policy_version,
        policy_schema_version=policy_result.policy_schema_version,
        policy_checksum=policy_result.policy_checksum,
        policy_authority=policy_result.policy_authority,
        context_authority_checksum=context_authority.context_checksum
        if context_authority is not None
        else None,
        context_id=context_authority.context_id if context_authority is not None else None,
        caller_authority=context_authority.caller_authority
        if context_authority is not None
        else None,
        deployment_domain=context_authority.deployment_domain
        if context_authority is not None
        else None,
        context_schema_version=context_authority.context_schema_version
        if context_authority is not None
        else None,
        context_evaluation_time_ms=context_authority.evaluation_time_ms
        if context_authority is not None
        else None,
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
        world_snapshot_observed_at_ms=_observed_at_or_none(freshness_result),
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
        world_snapshot_admissibility_status=trust_result.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=(
            trust_result.world_snapshot_admissibility_reason_code
        ),
        world_snapshot_admissibility_result_checksum=(
            trust_result.world_snapshot_admissibility_result_checksum
        ),
        world_snapshot_trust_status=trust_result.status.value,
        world_snapshot_trust_reason_code=trust_result.reason_code,
        world_snapshot_trust_result_checksum=trust_result.checksum,
        evidence_envelope_checksum=trust_result.evidence_envelope_checksum,
        attestation_checksum=trust_result.attestation_checksum,
        trust_policy_checksum=trust_result.trust_policy_checksum,
        verifier_certification_status=verifier_certification.status.value,
        verifier_certification_reason_code=verifier_certification.reason_code,
        verifier_certification_checksum=verifier_certification.checksum,
        verifier_id=verifier_certification.verifier_id,
        verifier_metadata_checksum=verifier_certification.verifier_metadata_checksum,
        trust_policy_config_status=trust_policy_config_validation.status.value,
        trust_policy_config_reason_code=trust_policy_config_validation.reason_code,
        trust_policy_config_validation_checksum=trust_policy_config_validation.checksum,
        source_id=trust_result.source_id,
        source_type=trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        trust_domain=trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
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
        policy_version=policy_record.policy_version,
        policy_schema_version=policy_record.policy_schema_version,
        policy_checksum=policy_record.policy_checksum,
        policy_authority=policy_record.policy_authority,
        policy_result_checksum=policy_record.policy_result_checksum,
        safety_case_id=policy_record.safety_case_id,
        context_authority_checksum=policy_record.context_authority_checksum,
        context_id=policy_record.context_id,
        caller_authority=policy_record.caller_authority,
        deployment_domain=policy_record.deployment_domain,
        context_schema_version=policy_record.context_schema_version,
        context_evaluation_time_ms=policy_record.context_evaluation_time_ms,
        world_snapshot_id=policy_record.world_snapshot_id,
        world_snapshot_checksum=policy_record.world_snapshot_checksum,
        capability_name=policy_record.capability_name,
        capability_version=policy_record.capability_version,
        admission_decision=PolicyAdmissionDecision.ERROR,
        integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
        exception_reason=reason,
        world_snapshot_observed_at_ms=policy_record.world_snapshot_observed_at_ms,
        freshness_result_checksum=policy_record.freshness_result_checksum,
        freshness_status=policy_record.freshness_status,
        world_snapshot_admissibility_status=policy_record.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=(
            policy_record.world_snapshot_admissibility_reason_code
        ),
        world_snapshot_admissibility_result_checksum=(
            policy_record.world_snapshot_admissibility_result_checksum
        ),
        world_snapshot_trust_status=policy_record.world_snapshot_trust_status,
        world_snapshot_trust_reason_code=policy_record.world_snapshot_trust_reason_code,
        world_snapshot_trust_result_checksum=policy_record.world_snapshot_trust_result_checksum,
        evidence_envelope_checksum=policy_record.evidence_envelope_checksum,
        attestation_checksum=policy_record.attestation_checksum,
        trust_policy_checksum=policy_record.trust_policy_checksum,
        verifier_certification_status=policy_record.verifier_certification_status,
        verifier_certification_reason_code=policy_record.verifier_certification_reason_code,
        verifier_certification_checksum=policy_record.verifier_certification_checksum,
        verifier_id=policy_record.verifier_id,
        verifier_metadata_checksum=policy_record.verifier_metadata_checksum,
        trust_policy_config_status=policy_record.trust_policy_config_status,
        trust_policy_config_reason_code=policy_record.trust_policy_config_reason_code,
        trust_policy_config_validation_checksum=(
            policy_record.trust_policy_config_validation_checksum
        ),
        source_id=policy_record.source_id,
        source_type=policy_record.source_type,
        trust_domain=policy_record.trust_domain,
    )


def _trust_record_kwargs(trust_result: WorldSnapshotTrustResult | None) -> _TrustRecordKwargs:
    if trust_result is None:
        return {}
    return {
        "world_snapshot_admissibility_status": trust_result.world_snapshot_admissibility_status,
        "world_snapshot_admissibility_reason_code": (
            trust_result.world_snapshot_admissibility_reason_code
        ),
        "world_snapshot_admissibility_result_checksum": (
            trust_result.world_snapshot_admissibility_result_checksum
        ),
        "world_snapshot_trust_status": trust_result.status.value,
        "world_snapshot_trust_reason_code": trust_result.reason_code,
        "world_snapshot_trust_result_checksum": trust_result.checksum,
        "evidence_envelope_checksum": _none_if_empty(trust_result.evidence_envelope_checksum),
        "attestation_checksum": _none_if_empty(trust_result.attestation_checksum),
        "trust_policy_checksum": _none_if_empty(trust_result.trust_policy_checksum),
        "source_id": _none_if_empty(trust_result.source_id),
        "source_type": trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        "trust_domain": trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
    }


def _record_binding_kwargs(
    trust_result: WorldSnapshotTrustResult | None,
    verifier_certification: VerifierAdapterCertificationResult | None,
    trust_policy_config_validation: TrustPolicyConfigValidationResult | None,
) -> _TrustRecordKwargs:
    kwargs = _trust_record_kwargs(trust_result)
    if verifier_certification is not None:
        kwargs["verifier_certification_status"] = verifier_certification.status.value
        kwargs["verifier_certification_reason_code"] = verifier_certification.reason_code
        kwargs["verifier_certification_checksum"] = verifier_certification.checksum
        kwargs["verifier_id"] = _none_if_empty(verifier_certification.verifier_id)
        kwargs["verifier_metadata_checksum"] = _none_if_empty(
            verifier_certification.verifier_metadata_checksum
        )
    elif trust_result is not None:
        kwargs["verifier_certification_checksum"] = _none_if_empty(
            trust_result.verifier_certification_checksum
        )
        kwargs["verifier_id"] = _none_if_empty(trust_result.verifier_id)
        kwargs["verifier_metadata_checksum"] = _none_if_empty(
            trust_result.verifier_metadata_checksum
        )
    if trust_policy_config_validation is not None:
        kwargs["trust_policy_config_status"] = trust_policy_config_validation.status.value
        kwargs["trust_policy_config_reason_code"] = trust_policy_config_validation.reason_code
        kwargs["trust_policy_config_validation_checksum"] = trust_policy_config_validation.checksum
    elif trust_result is not None:
        kwargs["trust_policy_config_validation_checksum"] = _none_if_empty(
            trust_result.trust_policy_config_validation_checksum
        )
    return kwargs


def _none_if_empty(value: str | None) -> str | None:
    if value == "":
        return None
    return value


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
