"""Policy admission contracts for pipeline enforcement wiring."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import cast

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateDecision, GateDecisionStatus
from aegis.contracts.policy import (
    Capability,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    SafetyCase,
    WorldSnapshotStub,
    policy_evaluation_result_checksum,
)
from aegis.errors import PolicyAdmissionIntegrityError


class PolicyAdmissionMode(StrEnum):
    """Pipeline policy admission modes."""

    DISABLED = "DISABLED"
    ENFORCE = "ENFORCE"


class PolicyAdmissionDecision(StrEnum):
    """Policy admission decision values."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    INVALID = "INVALID"
    ERROR = "ERROR"
    DISABLED = "DISABLED"
    NOT_RUN = "NOT_RUN"


class PolicyAdmissionIntegrityStatus(StrEnum):
    """Policy admission integrity binding status values."""

    DISABLED = "DISABLED"
    NOT_CHECKED = "NOT_CHECKED"
    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class PolicyAdmissionIntegrity:
    """Deterministic proof that a policy admission record binds to an audited plan."""

    status: PolicyAdmissionIntegrityStatus
    audit_id: str
    plan_id: str
    plan_checksum: str
    policy_id: str
    safety_case_id: str
    policy_result_checksum: str


@dataclass(frozen=True, slots=True, init=False)
class PolicyAdmissionInput:
    """Explicit policy admission inputs supplied by the pipeline caller.

    Args:
        mode: Whether policy admission is disabled or enforced.
        policy: Policy-v1 bundle to evaluate in ``ENFORCE`` mode.
        capability: Explicit requested capability to evaluate in ``ENFORCE`` mode.
        world_snapshot: Optional caller-supplied world evidence stub.
        context: Deterministic evaluator context. Values are recursively frozen.
        evidence: Inert SafetyCase evidence. Values are recursively frozen.

    Raises:
        ValueError: If mode is invalid, disabled mode includes policy inputs, or
            context/evidence contain unsupported values.
    """

    mode: PolicyAdmissionMode
    policy: Policy | None
    capability: Capability | None
    world_snapshot: WorldSnapshotStub | None
    context: Mapping[str, FrozenPolicyValue]
    evidence: Mapping[str, FrozenPolicyValue]

    def __init__(
        self,
        mode: str | PolicyAdmissionMode,
        policy: Policy | None = None,
        capability: Capability | None = None,
        world_snapshot: WorldSnapshotStub | None = None,
        context: Mapping[str, object] | None = None,
        evidence: Mapping[str, object] | None = None,
    ) -> None:
        normalized_mode = _normalize_mode(mode)
        frozen_context = _freeze_admission_mapping(context or {})
        frozen_evidence = _freeze_admission_mapping(evidence or {})

        if normalized_mode is PolicyAdmissionMode.DISABLED and (
            policy is not None
            or capability is not None
            or world_snapshot is not None
            or frozen_context
            or frozen_evidence
        ):
            raise ValueError("DISABLED policy admission must not include policy inputs")

        object.__setattr__(self, "mode", normalized_mode)
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "world_snapshot", world_snapshot)
        object.__setattr__(self, "context", frozen_context)
        object.__setattr__(self, "evidence", frozen_evidence)


@dataclass(frozen=True, slots=True, init=False)
class PolicyAdmissionRecord:
    """Observable result of pipeline policy admission.

    Args:
        mode: Admission mode used for the pipeline run.
        policy_result: Policy-v1 evaluator result when evaluation ran.
        safety_case: SafetyCase bound to the audited plan when available.
        enforced: Whether policy enforcement was requested.
        admission_allowed: Whether policy admission permits proceeding to gate.
        reasons: Deterministic admission reason codes.
        audit_id: AuditedPlan audit ID bound by this admission record.
        plan_id: CommandPlan plan ID bound by this admission record.
        plan_checksum: AuditedPlan checksum bound by this admission record.
        policy_id: Policy identity bound by this admission record.
        policy_result_checksum: Deterministic identity of the policy evaluation result.
        safety_case_id: SafetyCase identity bound by this admission record.
        world_snapshot_id: Optional world snapshot identity used during admission.
        world_snapshot_checksum: Optional world snapshot checksum used during admission.
        capability_name: Optional capability name used during admission.
        capability_version: Optional capability version used during admission.
        admission_decision: Explicit admission decision, distinct from disabled mode.
        integrity_status: Integrity status for plan/admission binding.
        exception_reason: Optional exception marker. Any marker prevents approval.

    Raises:
        ValueError: If the field combination contradicts admission semantics.
    """

    mode: PolicyAdmissionMode
    policy_result: PolicyEvaluationResult | None
    safety_case: SafetyCase | None
    enforced: bool
    admission_allowed: bool
    reasons: tuple[str, ...]
    audit_id: str | None
    plan_id: str | None
    plan_checksum: str | None
    policy_id: str | None
    policy_result_checksum: str | None
    safety_case_id: str | None
    world_snapshot_id: str | None
    world_snapshot_checksum: str | None
    capability_name: str | None
    capability_version: str | None
    admission_decision: PolicyAdmissionDecision
    integrity_status: PolicyAdmissionIntegrityStatus
    exception_reason: str | None

    def __init__(
        self,
        mode: str | PolicyAdmissionMode,
        policy_result: PolicyEvaluationResult | None,
        safety_case: SafetyCase | None,
        enforced: object,
        admission_allowed: object,
        reasons: Iterable[str],
        *,
        audit_id: str | None = None,
        plan_id: str | None = None,
        plan_checksum: str | None = None,
        policy_id: str | None = None,
        policy_result_checksum: str | None = None,
        safety_case_id: str | None = None,
        world_snapshot_id: str | None = None,
        world_snapshot_checksum: str | None = None,
        capability_name: str | None = None,
        capability_version: str | None = None,
        admission_decision: str | PolicyAdmissionDecision | None = None,
        integrity_status: str | PolicyAdmissionIntegrityStatus | None = None,
        exception_reason: str | None = None,
    ) -> None:
        normalized_mode = _normalize_mode(mode)
        if not isinstance(enforced, bool):
            raise ValueError("enforced must be a bool")
        if not isinstance(admission_allowed, bool):
            raise ValueError("admission_allowed must be a bool")

        normalized_reasons = _normalize_text_tuple(reasons, "reasons")
        normalized_admission_decision = _normalize_admission_decision(
            admission_decision,
            policy_result,
            normalized_mode,
            admission_allowed,
            normalized_reasons,
        )
        normalized_integrity_status = _normalize_integrity_status(
            integrity_status, normalized_mode, admission_allowed
        )
        normalized_exception_reason = _normalize_optional_text(exception_reason, "exception_reason")
        normalized_audit_id = _normalize_optional_text(audit_id, "audit_id")
        normalized_plan_id = _normalize_optional_text(plan_id, "plan_id")
        normalized_plan_checksum = _normalize_optional_text(plan_checksum, "plan_checksum")
        normalized_policy_id = _normalize_policy_id(policy_id, policy_result)
        normalized_policy_result_checksum = _normalize_policy_result_checksum(
            policy_result_checksum, policy_result
        )
        normalized_safety_case_id = _normalize_safety_case_id(safety_case_id, safety_case)
        normalized_world_snapshot_id = _normalize_optional_text(
            world_snapshot_id, "world_snapshot_id"
        )
        normalized_world_snapshot_checksum = _normalize_optional_text(
            world_snapshot_checksum, "world_snapshot_checksum"
        )
        normalized_capability_name = _normalize_optional_text(capability_name, "capability_name")
        normalized_capability_version = _normalize_optional_text(
            capability_version, "capability_version"
        )

        if normalized_mode is PolicyAdmissionMode.DISABLED:
            _validate_disabled_record(
                policy_result=policy_result,
                safety_case=safety_case,
                enforced=enforced,
                admission_allowed=admission_allowed,
                admission_decision=normalized_admission_decision,
                integrity_status=normalized_integrity_status,
                binding_values=(
                    normalized_audit_id,
                    normalized_plan_id,
                    normalized_plan_checksum,
                    normalized_policy_id,
                    normalized_policy_result_checksum,
                    normalized_safety_case_id,
                    normalized_world_snapshot_id,
                    normalized_world_snapshot_checksum,
                    normalized_capability_name,
                    normalized_capability_version,
                    normalized_exception_reason,
                ),
            )

        if normalized_mode is PolicyAdmissionMode.ENFORCE:
            _validate_enforced_record(
                policy_result=policy_result,
                safety_case=safety_case,
                enforced=enforced,
                admission_allowed=admission_allowed,
                reasons=normalized_reasons,
                admission_decision=normalized_admission_decision,
                integrity_status=normalized_integrity_status,
                audit_id=normalized_audit_id,
                plan_id=normalized_plan_id,
                plan_checksum=normalized_plan_checksum,
                policy_id=normalized_policy_id,
                policy_result_checksum=normalized_policy_result_checksum,
                safety_case_id=normalized_safety_case_id,
                world_snapshot_id=normalized_world_snapshot_id,
                world_snapshot_checksum=normalized_world_snapshot_checksum,
                capability_name=normalized_capability_name,
                capability_version=normalized_capability_version,
                exception_reason=normalized_exception_reason,
            )

        object.__setattr__(self, "mode", normalized_mode)
        object.__setattr__(self, "policy_result", policy_result)
        object.__setattr__(self, "safety_case", safety_case)
        object.__setattr__(self, "enforced", enforced)
        object.__setattr__(self, "admission_allowed", admission_allowed)
        object.__setattr__(self, "reasons", normalized_reasons)
        object.__setattr__(self, "audit_id", normalized_audit_id)
        object.__setattr__(self, "plan_id", normalized_plan_id)
        object.__setattr__(self, "plan_checksum", normalized_plan_checksum)
        object.__setattr__(self, "policy_id", normalized_policy_id)
        object.__setattr__(self, "policy_result_checksum", normalized_policy_result_checksum)
        object.__setattr__(self, "safety_case_id", normalized_safety_case_id)
        object.__setattr__(self, "world_snapshot_id", normalized_world_snapshot_id)
        object.__setattr__(self, "world_snapshot_checksum", normalized_world_snapshot_checksum)
        object.__setattr__(self, "capability_name", normalized_capability_name)
        object.__setattr__(self, "capability_version", normalized_capability_version)
        object.__setattr__(self, "admission_decision", normalized_admission_decision)
        object.__setattr__(self, "integrity_status", normalized_integrity_status)
        object.__setattr__(self, "exception_reason", normalized_exception_reason)


def disabled_policy_admission_record() -> PolicyAdmissionRecord:
    """Return the canonical disabled-mode policy admission record."""
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.DISABLED,
        policy_result=None,
        safety_case=None,
        enforced=False,
        admission_allowed=False,
        reasons=("POLICY_ADMISSION_DISABLED",),
        admission_decision=PolicyAdmissionDecision.DISABLED,
        integrity_status=PolicyAdmissionIntegrityStatus.DISABLED,
    )


def _validate_disabled_record(
    *,
    policy_result: PolicyEvaluationResult | None,
    safety_case: SafetyCase | None,
    enforced: bool,
    admission_allowed: bool,
    admission_decision: PolicyAdmissionDecision,
    integrity_status: PolicyAdmissionIntegrityStatus,
    binding_values: tuple[str | None, ...],
) -> None:
    if enforced:
        raise ValueError("DISABLED admission records must not be enforced")
    if admission_allowed:
        raise ValueError("DISABLED admission records must not allow policy admission")
    if policy_result is not None:
        raise ValueError("DISABLED admission records must not contain policy_result")
    if safety_case is not None:
        raise ValueError("DISABLED admission records must not contain safety_case")
    if admission_decision is not PolicyAdmissionDecision.DISABLED:
        raise ValueError("DISABLED admission records must use DISABLED admission_decision")
    if integrity_status is not PolicyAdmissionIntegrityStatus.DISABLED:
        raise ValueError("DISABLED admission records must use DISABLED integrity_status")
    if any(value is not None for value in binding_values):
        raise ValueError("DISABLED admission records must not contain admission bindings")


def _validate_enforced_record(
    *,
    policy_result: PolicyEvaluationResult | None,
    safety_case: SafetyCase | None,
    enforced: bool,
    admission_allowed: bool,
    reasons: tuple[str, ...],
    admission_decision: PolicyAdmissionDecision,
    integrity_status: PolicyAdmissionIntegrityStatus,
    audit_id: str | None,
    plan_id: str | None,
    plan_checksum: str | None,
    policy_id: str | None,
    policy_result_checksum: str | None,
    safety_case_id: str | None,
    world_snapshot_id: str | None,
    world_snapshot_checksum: str | None,
    capability_name: str | None,
    capability_version: str | None,
    exception_reason: str | None,
) -> None:
    if not enforced:
        raise ValueError("ENFORCE admission records must be enforced")
    if safety_case is not None and policy_result is None:
        raise ValueError("safety_case requires policy_result")
    if safety_case is not None and safety_case.policy_result != policy_result:
        raise ValueError("safety_case must explain policy_result")
    if exception_reason is not None and admission_allowed:
        raise ValueError("admission with exception_reason must not allow")
    if admission_allowed:
        if policy_result is None:
            raise ValueError("allowed ENFORCE admission requires policy_result")
        if policy_result.decision is not PolicyDecision.ALLOW:
            raise ValueError("admission_allowed=True requires policy decision ALLOW")
        if safety_case is None:
            raise ValueError("allowed ENFORCE admission requires safety_case")
        if admission_decision is not PolicyAdmissionDecision.ALLOW:
            raise ValueError("admission_allowed=True requires admission_decision ALLOW")
        if integrity_status is not PolicyAdmissionIntegrityStatus.PASSED:
            raise ValueError("admission_allowed=True requires integrity_status PASSED")
        _require_allowed_binding_values(
            audit_id=audit_id,
            plan_id=plan_id,
            plan_checksum=plan_checksum,
            policy_id=policy_id,
            policy_result_checksum=policy_result_checksum,
            safety_case_id=safety_case_id,
            capability_name=capability_name,
            capability_version=capability_version,
        )
        _validate_safety_case_bindings(
            safety_case=safety_case,
            audit_id=audit_id,
            plan_id=plan_id,
            plan_checksum=plan_checksum,
            policy_result_checksum=policy_result_checksum,
            safety_case_id=safety_case_id,
            world_snapshot_id=world_snapshot_id,
            world_snapshot_checksum=world_snapshot_checksum,
            capability_name=capability_name,
            capability_version=capability_version,
        )
    elif reasons == ():
        raise ValueError("denied ENFORCE admission requires reasons")
    elif admission_decision is PolicyAdmissionDecision.ALLOW:
        raise ValueError("denied ENFORCE admission must not use ALLOW admission_decision")


def assert_policy_admission_integrity(
    audited_plan: AuditedPlan,
    policy_admission: PolicyAdmissionRecord,
) -> PolicyAdmissionIntegrity:
    """Validate that policy admission is bound to the exact audited plan.

    Args:
        audited_plan: The audited plan produced in the current pipeline run.
        policy_admission: The policy admission record to verify.

    Returns:
        A deterministic integrity object for the verified admission.

    Raises:
        PolicyAdmissionIntegrityError: If admission is disabled, missing,
            non-allowing, stale, mismatched, malformed, or exception-marked.
    """
    violations = _policy_admission_integrity_violations(audited_plan, policy_admission)
    if violations:
        raise PolicyAdmissionIntegrityError(
            message="Policy admission integrity check failed",
            layer="policy",
            context={
                "audit_id": audited_plan.audit_id,
                "plan_id": audited_plan.plan.plan_id,
                "reasons": list(violations),
            },
        )

    policy_result = policy_admission.policy_result
    safety_case = policy_admission.safety_case
    assert policy_result is not None
    assert safety_case is not None

    return PolicyAdmissionIntegrity(
        status=PolicyAdmissionIntegrityStatus.PASSED,
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        policy_id=policy_result.policy_id,
        safety_case_id=safety_case.safety_case_id,
        policy_result_checksum=policy_evaluation_result_checksum(policy_result),
    )


def is_policy_backed_approval(
    audited_plan: AuditedPlan,
    policy_admission: PolicyAdmissionRecord | None,
    gate_decision: GateDecision | None,
) -> bool:
    """Return True only for an enforced, integrity-passed policy-backed gate approval."""
    if policy_admission is None or gate_decision is None:
        return False
    if gate_decision.status is not GateDecisionStatus.ALLOWED:
        return False
    if gate_decision.audit_id != audited_plan.audit_id:
        return False
    if gate_decision.plan_id != audited_plan.plan.plan_id:
        return False
    try:
        assert_policy_admission_integrity(audited_plan, policy_admission)
    except PolicyAdmissionIntegrityError:
        return False
    return True


def _policy_admission_integrity_violations(
    audited_plan: AuditedPlan,
    policy_admission: PolicyAdmissionRecord,
) -> tuple[str, ...]:
    violations: list[str] = []
    mode_value: object = policy_admission.mode
    admission_decision: object = policy_admission.admission_decision
    integrity_status: object = policy_admission.integrity_status
    policy_result = policy_admission.policy_result
    safety_case = policy_admission.safety_case

    if mode_value is not PolicyAdmissionMode.ENFORCE:
        violations.append("POLICY_ADMISSION_NOT_ENFORCED")
    if policy_admission.enforced is not True:
        violations.append("POLICY_ADMISSION_ENFORCEMENT_DISABLED")
    if policy_admission.admission_allowed is not True:
        violations.append("POLICY_ADMISSION_NOT_ALLOWED")
    if admission_decision is not PolicyAdmissionDecision.ALLOW:
        violations.append("POLICY_ADMISSION_DECISION_NOT_ALLOW")
    if integrity_status is not PolicyAdmissionIntegrityStatus.PASSED:
        violations.append("POLICY_ADMISSION_INTEGRITY_NOT_PASSED")
    if policy_admission.exception_reason is not None:
        violations.append("POLICY_ADMISSION_EXCEPTION_MARKED")
    if policy_result is None:
        violations.append("POLICY_RESULT_MISSING")
    elif policy_result.decision is not PolicyDecision.ALLOW:
        violations.append("POLICY_EVALUATION_DECISION_NOT_ALLOW")
    if safety_case is None:
        violations.append("SAFETY_CASE_MISSING")

    expected_policy_result_checksum = (
        policy_evaluation_result_checksum(policy_result) if policy_result is not None else None
    )
    expected_policy_id = policy_result.policy_id if policy_result is not None else None
    expected_safety_case_id = safety_case.safety_case_id if safety_case is not None else None

    _append_mismatch(violations, policy_admission.audit_id, audited_plan.audit_id, "AUDIT_ID")
    _append_mismatch(violations, policy_admission.plan_id, audited_plan.plan.plan_id, "PLAN_ID")
    _append_mismatch(
        violations, policy_admission.plan_checksum, audited_plan.checksum, "PLAN_CHECKSUM"
    )
    _append_mismatch(violations, policy_admission.policy_id, expected_policy_id, "POLICY_ID")
    _append_mismatch(
        violations,
        policy_admission.policy_result_checksum,
        expected_policy_result_checksum,
        "POLICY_RESULT_CHECKSUM",
    )
    _append_mismatch(
        violations, policy_admission.safety_case_id, expected_safety_case_id, "SAFETY_CASE_ID"
    )

    if safety_case is not None:
        _append_mismatch(
            violations,
            safety_case.audited_plan_id,
            audited_plan.audit_id,
            "SAFETY_CASE_AUDIT_ID",
        )
        _append_mismatch(
            violations,
            safety_case.plan_id,
            audited_plan.plan.plan_id,
            "SAFETY_CASE_PLAN_ID",
        )
        _append_mismatch(
            violations,
            safety_case.plan_checksum,
            audited_plan.checksum,
            "SAFETY_CASE_PLAN_CHECKSUM",
        )
        _append_mismatch(
            violations,
            safety_case.policy_result_checksum,
            expected_policy_result_checksum,
            "SAFETY_CASE_POLICY_RESULT_CHECKSUM",
        )
        _append_mismatch(
            violations,
            safety_case.world_snapshot_id,
            policy_admission.world_snapshot_id,
            "SAFETY_CASE_WORLD_SNAPSHOT_ID",
        )
        _append_mismatch(
            violations,
            safety_case.world_snapshot_checksum,
            policy_admission.world_snapshot_checksum,
            "SAFETY_CASE_WORLD_SNAPSHOT_CHECKSUM",
        )
        _append_mismatch(
            violations,
            safety_case.capability_name,
            policy_admission.capability_name,
            "SAFETY_CASE_CAPABILITY_NAME",
        )
        _append_mismatch(
            violations,
            safety_case.capability_version,
            policy_admission.capability_version,
            "SAFETY_CASE_CAPABILITY_VERSION",
        )
        if policy_result is not None and safety_case.policy_result != policy_result:
            violations.append("SAFETY_CASE_POLICY_RESULT_MISMATCH")

    return tuple(violations)


def _append_mismatch(
    violations: list[str],
    actual: str | None,
    expected: str | None,
    field_name: str,
) -> None:
    if actual != expected:
        violations.append(f"{field_name}_MISMATCH")


def _require_allowed_binding_values(
    *,
    audit_id: str | None,
    plan_id: str | None,
    plan_checksum: str | None,
    policy_id: str | None,
    policy_result_checksum: str | None,
    safety_case_id: str | None,
    capability_name: str | None,
    capability_version: str | None,
) -> None:
    required_values = {
        "audit_id": audit_id,
        "plan_id": plan_id,
        "plan_checksum": plan_checksum,
        "policy_id": policy_id,
        "policy_result_checksum": policy_result_checksum,
        "safety_case_id": safety_case_id,
        "capability_name": capability_name,
        "capability_version": capability_version,
    }
    missing = tuple(key for key, value in required_values.items() if value is None)
    if missing:
        raise ValueError(f"allowed ENFORCE admission missing bindings: {', '.join(missing)}")


def _validate_safety_case_bindings(
    *,
    safety_case: SafetyCase,
    audit_id: str | None,
    plan_id: str | None,
    plan_checksum: str | None,
    policy_result_checksum: str | None,
    safety_case_id: str | None,
    world_snapshot_id: str | None,
    world_snapshot_checksum: str | None,
    capability_name: str | None,
    capability_version: str | None,
) -> None:
    if safety_case.audited_plan_id != audit_id:
        raise ValueError("safety_case audited plan binding must match admission audit_id")
    if safety_case.plan_id != plan_id:
        raise ValueError("safety_case plan_id must match admission plan_id")
    if safety_case.plan_checksum != plan_checksum:
        raise ValueError("safety_case plan_checksum must match admission plan_checksum")
    if safety_case.world_snapshot_id != world_snapshot_id:
        raise ValueError("safety_case world_snapshot_id must match admission")
    if safety_case.world_snapshot_checksum != world_snapshot_checksum:
        raise ValueError("safety_case world_snapshot_checksum must match admission")
    if safety_case.capability_name != capability_name:
        raise ValueError("safety_case capability_name must match admission")
    if safety_case.capability_version != capability_version:
        raise ValueError("safety_case capability_version must match admission")


def _normalize_mode(value: str | PolicyAdmissionMode) -> PolicyAdmissionMode:
    if isinstance(value, PolicyAdmissionMode):
        return value
    if value != value.strip():
        raise ValueError("mode must not contain leading or trailing whitespace")
    try:
        return PolicyAdmissionMode(value)
    except ValueError:
        raise ValueError("mode must be DISABLED or ENFORCE") from None


def _normalize_admission_decision(
    value: str | PolicyAdmissionDecision | None,
    policy_result: PolicyEvaluationResult | None,
    mode: PolicyAdmissionMode,
    admission_allowed: bool,
    reasons: tuple[str, ...],
) -> PolicyAdmissionDecision:
    if value is not None:
        if isinstance(value, PolicyAdmissionDecision):
            return value
        if value != value.strip():
            raise ValueError("admission_decision must not contain leading or trailing whitespace")
        try:
            return PolicyAdmissionDecision(value)
        except ValueError:
            raise ValueError("admission_decision must be a valid PolicyAdmissionDecision") from None
    if mode is PolicyAdmissionMode.DISABLED:
        return PolicyAdmissionDecision.DISABLED
    if admission_allowed:
        return PolicyAdmissionDecision.ALLOW
    if policy_result is None:
        if any(reason.endswith("FAILED") for reason in reasons):
            return PolicyAdmissionDecision.ERROR
        if "POLICY_ADMISSION_NOT_RUN" in reasons:
            return PolicyAdmissionDecision.NOT_RUN
        return PolicyAdmissionDecision.BLOCK
    if policy_result.decision is PolicyDecision.ALLOW:
        return PolicyAdmissionDecision.BLOCK
    return PolicyAdmissionDecision(policy_result.decision.value)


def _normalize_integrity_status(
    value: str | PolicyAdmissionIntegrityStatus | None,
    mode: PolicyAdmissionMode,
    admission_allowed: bool,
) -> PolicyAdmissionIntegrityStatus:
    if value is not None:
        if isinstance(value, PolicyAdmissionIntegrityStatus):
            return value
        if value != value.strip():
            raise ValueError("integrity_status must not contain leading or trailing whitespace")
        try:
            return PolicyAdmissionIntegrityStatus(value)
        except ValueError:
            raise ValueError(
                "integrity_status must be a valid PolicyAdmissionIntegrityStatus"
            ) from None
    if mode is PolicyAdmissionMode.DISABLED:
        return PolicyAdmissionIntegrityStatus.DISABLED
    if admission_allowed:
        return PolicyAdmissionIntegrityStatus.PASSED
    return PolicyAdmissionIntegrityStatus.NOT_CHECKED


def _normalize_optional_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_policy_id(
    policy_id: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_id, "policy_id")
    if normalized is None and policy_result is not None:
        return policy_result.policy_id
    if (
        normalized is not None
        and policy_result is not None
        and normalized != policy_result.policy_id
    ):
        raise ValueError("policy_id must match policy_result.policy_id")
    return normalized


def _normalize_policy_result_checksum(
    policy_result_checksum: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_result_checksum, "policy_result_checksum")
    if policy_result is None:
        return normalized
    expected = policy_evaluation_result_checksum(policy_result)
    if normalized is None:
        return expected
    if normalized != expected:
        raise ValueError("policy_result_checksum must match policy_result")
    return normalized


def _normalize_safety_case_id(
    safety_case_id: str | None,
    safety_case: SafetyCase | None,
) -> str | None:
    normalized = _normalize_optional_text(safety_case_id, "safety_case_id")
    if normalized is None and safety_case is not None:
        return safety_case.safety_case_id
    if (
        normalized is not None
        and safety_case is not None
        and normalized != safety_case.safety_case_id
    ):
        raise ValueError("safety_case_id must match safety_case")
    return normalized


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must contain non-empty strings")
    return normalized


def _normalize_text_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of strings")

    normalized_values: list[str] = []
    for value in values:
        normalized_values.append(_normalize_required_text(value, field_name))
    return tuple(normalized_values)


def _freeze_admission_mapping(values: Mapping[str, object]) -> Mapping[str, FrozenPolicyValue]:
    return _freeze_admission_items(values.items())


def _freeze_admission_items(
    items: Iterable[tuple[object, object]],
) -> Mapping[str, FrozenPolicyValue]:
    frozen_values: dict[str, FrozenPolicyValue] = {}
    for key, value in items:
        if not isinstance(key, str):
            raise ValueError("policy admission mapping keys must be strings")
        frozen_values[key] = _freeze_admission_value(value)
    return MappingProxyType({key: frozen_values[key] for key in sorted(frozen_values)})


def _freeze_admission_value(value: object) -> FrozenPolicyValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("policy admission numeric values must be finite")
        return value
    if isinstance(value, list):
        items = cast(list[object], value)
        return tuple(_freeze_admission_value(item) for item in items)
    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(_freeze_admission_value(item) for item in items)
    if isinstance(value, set):
        items = cast(set[object], value)
        return frozenset(_freeze_admission_value(item) for item in items)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _freeze_admission_items(mapping.items())
    raise ValueError("policy admission values must be primitive values or nested containers")


__all__ = [
    "PolicyAdmissionDecision",
    "PolicyAdmissionInput",
    "PolicyAdmissionIntegrity",
    "PolicyAdmissionIntegrityStatus",
    "PolicyAdmissionMode",
    "PolicyAdmissionRecord",
    "assert_policy_admission_integrity",
    "disabled_policy_admission_record",
    "is_policy_backed_approval",
]
