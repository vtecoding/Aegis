"""Policy admission contracts for pipeline enforcement wiring."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from re import fullmatch
from types import MappingProxyType
from typing import cast

from aegis.aegis_errors import PolicyAdmissionIntegrityError
from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_gate import GateDecision, GateDecisionStatus
from aegis.contracts.aegis_policy import (
    Capability,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    SafetyCase,
    WorldSnapshotStub,
    policy_evaluation_result_checksum,
)
from aegis.governance.aegis_resource_bounds import validate_resource_bounds


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
        world_snapshot_admissibility_status: Optional admissibility status carried from
            admissibility evaluation.
        world_snapshot_admissibility_result_checksum: Optional admissibility result checksum.
        world_snapshot_trust_status: Optional trust status carried from trust evaluation.
        world_snapshot_trust_result_checksum: Optional trust result checksum.

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
    policy_version: str | None
    policy_schema_version: str | None
    policy_checksum: str | None
    policy_authority: str | None
    policy_result_checksum: str | None
    safety_case_id: str | None
    context_authority_checksum: str | None
    context_id: str | None
    caller_authority: str | None
    deployment_domain: str | None
    context_schema_version: str | None
    context_evaluation_time_ms: int | None
    world_snapshot_id: str | None
    world_snapshot_checksum: str | None
    capability_name: str | None
    capability_version: str | None
    admission_decision: PolicyAdmissionDecision
    integrity_status: PolicyAdmissionIntegrityStatus
    exception_reason: str | None
    world_snapshot_observed_at_ms: int | None
    freshness_result_checksum: str | None
    freshness_status: str | None
    world_snapshot_admissibility_status: str | None
    world_snapshot_admissibility_reason_code: str | None
    world_snapshot_admissibility_result_checksum: str | None
    world_snapshot_trust_status: str | None
    world_snapshot_trust_reason_code: str | None
    world_snapshot_trust_result_checksum: str | None
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
        policy_version: str | None = None,
        policy_schema_version: str | None = None,
        policy_checksum: str | None = None,
        policy_authority: str | None = None,
        policy_result_checksum: str | None = None,
        safety_case_id: str | None = None,
        context_authority_checksum: str | None = None,
        context_id: str | None = None,
        caller_authority: str | None = None,
        deployment_domain: str | None = None,
        context_schema_version: str | None = None,
        context_evaluation_time_ms: int | None = None,
        world_snapshot_id: str | None = None,
        world_snapshot_checksum: str | None = None,
        capability_name: str | None = None,
        capability_version: str | None = None,
        admission_decision: str | PolicyAdmissionDecision | None = None,
        integrity_status: str | PolicyAdmissionIntegrityStatus | None = None,
        exception_reason: str | None = None,
        world_snapshot_observed_at_ms: int | None = None,
        freshness_result_checksum: str | None = None,
        freshness_status: str | None = None,
        world_snapshot_admissibility_status: object = None,
        world_snapshot_admissibility_reason_code: str | None = None,
        world_snapshot_admissibility_result_checksum: str | None = None,
        world_snapshot_trust_status: object = None,
        world_snapshot_trust_reason_code: str | None = None,
        world_snapshot_trust_result_checksum: str | None = None,
        evidence_envelope_checksum: str | None = None,
        attestation_checksum: str | None = None,
        trust_policy_checksum: str | None = None,
        verifier_certification_status: object = None,
        verifier_certification_reason_code: str | None = None,
        verifier_certification_checksum: str | None = None,
        verifier_id: str | None = None,
        verifier_metadata_checksum: str | None = None,
        trust_policy_config_status: object = None,
        trust_policy_config_reason_code: str | None = None,
        trust_policy_config_validation_checksum: str | None = None,
        source_id: str | None = None,
        source_type: object = None,
        trust_domain: object = None,
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
        normalized_policy_version = _normalize_policy_version_binding(policy_version, policy_result)
        normalized_policy_schema_version = _normalize_policy_schema_version_binding(
            policy_schema_version, policy_result
        )
        normalized_policy_checksum = _normalize_policy_checksum_binding(
            policy_checksum, policy_result
        )
        normalized_policy_authority = _normalize_policy_authority_binding(
            policy_authority, policy_result
        )
        normalized_policy_result_checksum = _normalize_policy_result_checksum(
            policy_result_checksum, policy_result
        )
        normalized_safety_case_id = _normalize_safety_case_id(safety_case_id, safety_case)
        normalized_context_authority_checksum = _normalize_context_authority_checksum_binding(
            context_authority_checksum, policy_result
        )
        normalized_context_id = _normalize_optional_text(context_id, "context_id")
        normalized_caller_authority = _normalize_optional_text(caller_authority, "caller_authority")
        normalized_deployment_domain = _normalize_optional_text(
            deployment_domain, "deployment_domain"
        )
        normalized_context_schema_version = _normalize_optional_text(
            context_schema_version, "context_schema_version"
        )
        normalized_context_evaluation_time_ms = _normalize_optional_observed_at_ms(
            context_evaluation_time_ms
        )
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
        normalized_world_snapshot_observed_at_ms = _normalize_optional_observed_at_ms(
            world_snapshot_observed_at_ms
        )
        normalized_freshness_result_checksum = _normalize_optional_text(
            freshness_result_checksum, "freshness_result_checksum"
        )
        normalized_freshness_status = _normalize_optional_freshness_status(freshness_status)
        admissibility_status_value = world_snapshot_admissibility_status
        admissibility_reason_value = world_snapshot_admissibility_reason_code
        admissibility_result_checksum_value = world_snapshot_admissibility_result_checksum
        trust_status_value = world_snapshot_trust_status
        trust_reason_value = world_snapshot_trust_reason_code
        trust_result_checksum_value = world_snapshot_trust_result_checksum
        evidence_envelope_checksum_value = evidence_envelope_checksum
        attestation_checksum_value = attestation_checksum
        trust_policy_checksum_value = trust_policy_checksum
        verifier_certification_checksum_value = verifier_certification_checksum
        trust_policy_config_validation_checksum_value = trust_policy_config_validation_checksum
        verifier_id_value = verifier_id
        verifier_metadata_checksum_value = verifier_metadata_checksum
        source_id_value = source_id
        source_type_value = source_type
        trust_domain_value = trust_domain
        if safety_case is not None:
            admissibility_status_value = (
                admissibility_status_value or safety_case.world_snapshot_admissibility_status
            )
            admissibility_reason_value = (
                admissibility_reason_value or safety_case.world_snapshot_admissibility_reason_code
            )
            admissibility_result_checksum_value = (
                admissibility_result_checksum_value
                or safety_case.world_snapshot_admissibility_result_checksum
            )
            trust_status_value = trust_status_value or safety_case.world_snapshot_trust_status
            trust_reason_value = trust_reason_value or safety_case.world_snapshot_trust_reason_code
            trust_result_checksum_value = (
                trust_result_checksum_value or safety_case.world_snapshot_trust_result_checksum
            )
            evidence_envelope_checksum_value = (
                evidence_envelope_checksum_value or safety_case.evidence_envelope_checksum
            )
            attestation_checksum_value = (
                attestation_checksum_value or safety_case.attestation_checksum
            )
            trust_policy_checksum_value = (
                trust_policy_checksum_value or safety_case.trust_policy_checksum
            )
            verifier_certification_checksum_value = (
                verifier_certification_checksum_value or safety_case.verifier_certification_checksum
            )
            trust_policy_config_validation_checksum_value = (
                trust_policy_config_validation_checksum_value
                or safety_case.trust_policy_config_validation_checksum
            )
            verifier_id_value = verifier_id_value or safety_case.verifier_id
            verifier_metadata_checksum_value = (
                verifier_metadata_checksum_value or safety_case.verifier_metadata_checksum
            )
            source_id_value = source_id_value or safety_case.source_id
            source_type_value = source_type_value or safety_case.source_type
            trust_domain_value = trust_domain_value or safety_case.trust_domain

        normalized_admissibility_status = _normalize_optional_admissibility_status(
            admissibility_status_value
        )
        normalized_admissibility_reason_code = _normalize_optional_reason_code(
            admissibility_reason_value, "world_snapshot_admissibility_reason_code"
        )
        normalized_admissibility_result_checksum = _normalize_optional_text(
            admissibility_result_checksum_value, "world_snapshot_admissibility_result_checksum"
        )
        normalized_trust_status = _normalize_optional_trust_status(trust_status_value)
        normalized_trust_reason_code = _normalize_optional_reason_code(
            trust_reason_value, "world_snapshot_trust_reason_code"
        )
        normalized_trust_result_checksum = _normalize_optional_text(
            trust_result_checksum_value, "world_snapshot_trust_result_checksum"
        )
        normalized_evidence_envelope_checksum = _normalize_optional_text(
            evidence_envelope_checksum_value, "evidence_envelope_checksum"
        )
        normalized_attestation_checksum = _normalize_optional_text(
            attestation_checksum_value, "attestation_checksum"
        )
        normalized_trust_policy_checksum = _normalize_optional_text(
            trust_policy_checksum_value, "trust_policy_checksum"
        )
        normalized_verifier_certification_status = _normalize_optional_certification_status(
            verifier_certification_status
        )
        normalized_verifier_certification_reason_code = _normalize_optional_reason_code(
            verifier_certification_reason_code, "verifier_certification_reason_code"
        )
        normalized_verifier_certification_checksum = _normalize_optional_text(
            verifier_certification_checksum_value, "verifier_certification_checksum"
        )
        normalized_verifier_id = _normalize_optional_text(verifier_id_value, "verifier_id")
        normalized_verifier_metadata_checksum = _normalize_optional_text(
            verifier_metadata_checksum_value, "verifier_metadata_checksum"
        )
        normalized_trust_policy_config_status = _normalize_optional_config_status(
            trust_policy_config_status
        )
        normalized_trust_policy_config_reason_code = _normalize_optional_reason_code(
            trust_policy_config_reason_code, "trust_policy_config_reason_code"
        )
        normalized_trust_policy_config_validation_checksum = _normalize_optional_text(
            trust_policy_config_validation_checksum_value,
            "trust_policy_config_validation_checksum",
        )
        normalized_source_id = _normalize_optional_text(source_id_value, "source_id")
        normalized_source_type = _normalize_optional_source_type(source_type_value)
        normalized_trust_domain = _normalize_optional_trust_domain(trust_domain_value)

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
                    normalized_policy_version,
                    normalized_policy_schema_version,
                    normalized_policy_checksum,
                    normalized_policy_authority,
                    normalized_policy_result_checksum,
                    normalized_safety_case_id,
                    normalized_context_authority_checksum,
                    normalized_context_id,
                    normalized_caller_authority,
                    normalized_deployment_domain,
                    normalized_context_schema_version,
                    normalized_context_evaluation_time_ms,
                    normalized_world_snapshot_id,
                    normalized_world_snapshot_checksum,
                    normalized_capability_name,
                    normalized_capability_version,
                    normalized_exception_reason,
                    normalized_freshness_result_checksum,
                    normalized_freshness_status,
                    normalized_admissibility_status,
                    normalized_admissibility_reason_code,
                    normalized_admissibility_result_checksum,
                    normalized_trust_status,
                    normalized_trust_reason_code,
                    normalized_trust_result_checksum,
                    normalized_evidence_envelope_checksum,
                    normalized_attestation_checksum,
                    normalized_trust_policy_checksum,
                    normalized_verifier_certification_status,
                    normalized_verifier_certification_reason_code,
                    normalized_verifier_certification_checksum,
                    normalized_verifier_id,
                    normalized_verifier_metadata_checksum,
                    normalized_trust_policy_config_status,
                    normalized_trust_policy_config_reason_code,
                    normalized_trust_policy_config_validation_checksum,
                    normalized_source_id,
                    normalized_source_type,
                    normalized_trust_domain,
                ),
                disabled_observed_at_ms=normalized_world_snapshot_observed_at_ms,
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
                policy_version=normalized_policy_version,
                policy_schema_version=normalized_policy_schema_version,
                policy_checksum=normalized_policy_checksum,
                policy_authority=normalized_policy_authority,
                policy_result_checksum=normalized_policy_result_checksum,
                safety_case_id=normalized_safety_case_id,
                context_authority_checksum=normalized_context_authority_checksum,
                context_id=normalized_context_id,
                caller_authority=normalized_caller_authority,
                deployment_domain=normalized_deployment_domain,
                context_schema_version=normalized_context_schema_version,
                context_evaluation_time_ms=normalized_context_evaluation_time_ms,
                world_snapshot_id=normalized_world_snapshot_id,
                world_snapshot_checksum=normalized_world_snapshot_checksum,
                capability_name=normalized_capability_name,
                capability_version=normalized_capability_version,
                exception_reason=normalized_exception_reason,
                world_snapshot_observed_at_ms=normalized_world_snapshot_observed_at_ms,
                freshness_result_checksum=normalized_freshness_result_checksum,
                freshness_status=normalized_freshness_status,
                world_snapshot_admissibility_status=normalized_admissibility_status,
                world_snapshot_admissibility_reason_code=normalized_admissibility_reason_code,
                world_snapshot_admissibility_result_checksum=(
                    normalized_admissibility_result_checksum
                ),
                world_snapshot_trust_status=normalized_trust_status,
                world_snapshot_trust_reason_code=normalized_trust_reason_code,
                world_snapshot_trust_result_checksum=normalized_trust_result_checksum,
                evidence_envelope_checksum=normalized_evidence_envelope_checksum,
                attestation_checksum=normalized_attestation_checksum,
                trust_policy_checksum=normalized_trust_policy_checksum,
                verifier_certification_status=normalized_verifier_certification_status,
                verifier_certification_reason_code=normalized_verifier_certification_reason_code,
                verifier_certification_checksum=normalized_verifier_certification_checksum,
                verifier_id=normalized_verifier_id,
                verifier_metadata_checksum=normalized_verifier_metadata_checksum,
                trust_policy_config_status=normalized_trust_policy_config_status,
                trust_policy_config_reason_code=normalized_trust_policy_config_reason_code,
                trust_policy_config_validation_checksum=(
                    normalized_trust_policy_config_validation_checksum
                ),
                source_id=normalized_source_id,
                source_type=normalized_source_type,
                trust_domain=normalized_trust_domain,
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
        object.__setattr__(self, "policy_version", normalized_policy_version)
        object.__setattr__(self, "policy_schema_version", normalized_policy_schema_version)
        object.__setattr__(self, "policy_checksum", normalized_policy_checksum)
        object.__setattr__(self, "policy_authority", normalized_policy_authority)
        object.__setattr__(self, "policy_result_checksum", normalized_policy_result_checksum)
        object.__setattr__(self, "safety_case_id", normalized_safety_case_id)
        object.__setattr__(
            self, "context_authority_checksum", normalized_context_authority_checksum
        )
        object.__setattr__(self, "context_id", normalized_context_id)
        object.__setattr__(self, "caller_authority", normalized_caller_authority)
        object.__setattr__(self, "deployment_domain", normalized_deployment_domain)
        object.__setattr__(self, "context_schema_version", normalized_context_schema_version)
        object.__setattr__(
            self, "context_evaluation_time_ms", normalized_context_evaluation_time_ms
        )
        object.__setattr__(self, "world_snapshot_id", normalized_world_snapshot_id)
        object.__setattr__(self, "world_snapshot_checksum", normalized_world_snapshot_checksum)
        object.__setattr__(self, "capability_name", normalized_capability_name)
        object.__setattr__(self, "capability_version", normalized_capability_version)
        object.__setattr__(self, "admission_decision", normalized_admission_decision)
        object.__setattr__(self, "integrity_status", normalized_integrity_status)
        object.__setattr__(self, "exception_reason", normalized_exception_reason)
        object.__setattr__(
            self, "world_snapshot_observed_at_ms", normalized_world_snapshot_observed_at_ms
        )
        object.__setattr__(self, "freshness_result_checksum", normalized_freshness_result_checksum)
        object.__setattr__(self, "freshness_status", normalized_freshness_status)
        object.__setattr__(
            self, "world_snapshot_admissibility_status", normalized_admissibility_status
        )
        object.__setattr__(
            self, "world_snapshot_admissibility_reason_code", normalized_admissibility_reason_code
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_result_checksum",
            normalized_admissibility_result_checksum,
        )
        object.__setattr__(self, "world_snapshot_trust_status", normalized_trust_status)
        object.__setattr__(self, "world_snapshot_trust_reason_code", normalized_trust_reason_code)
        object.__setattr__(
            self, "world_snapshot_trust_result_checksum", normalized_trust_result_checksum
        )
        object.__setattr__(
            self, "evidence_envelope_checksum", normalized_evidence_envelope_checksum
        )
        object.__setattr__(self, "attestation_checksum", normalized_attestation_checksum)
        object.__setattr__(self, "trust_policy_checksum", normalized_trust_policy_checksum)
        object.__setattr__(
            self, "verifier_certification_status", normalized_verifier_certification_status
        )
        object.__setattr__(
            self,
            "verifier_certification_reason_code",
            normalized_verifier_certification_reason_code,
        )
        object.__setattr__(
            self, "verifier_certification_checksum", normalized_verifier_certification_checksum
        )
        object.__setattr__(self, "verifier_id", normalized_verifier_id)
        object.__setattr__(
            self, "verifier_metadata_checksum", normalized_verifier_metadata_checksum
        )
        object.__setattr__(
            self, "trust_policy_config_status", normalized_trust_policy_config_status
        )
        object.__setattr__(
            self, "trust_policy_config_reason_code", normalized_trust_policy_config_reason_code
        )
        object.__setattr__(
            self,
            "trust_policy_config_validation_checksum",
            normalized_trust_policy_config_validation_checksum,
        )
        object.__setattr__(self, "source_id", normalized_source_id)
        object.__setattr__(self, "source_type", normalized_source_type)
        object.__setattr__(self, "trust_domain", normalized_trust_domain)


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
    binding_values: tuple[object, ...],
    disabled_observed_at_ms: int | None = None,
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
    if disabled_observed_at_ms is not None:
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
    policy_version: str | None,
    policy_schema_version: str | None,
    policy_checksum: str | None,
    policy_authority: str | None,
    policy_result_checksum: str | None,
    safety_case_id: str | None,
    context_authority_checksum: str | None,
    context_id: str | None,
    caller_authority: str | None,
    deployment_domain: str | None,
    context_schema_version: str | None,
    context_evaluation_time_ms: int | None,
    world_snapshot_id: str | None,
    world_snapshot_checksum: str | None,
    capability_name: str | None,
    capability_version: str | None,
    exception_reason: str | None,
    world_snapshot_observed_at_ms: int | None = None,
    freshness_result_checksum: str | None = None,
    freshness_status: str | None = None,
    world_snapshot_admissibility_status: str | None = None,
    world_snapshot_admissibility_reason_code: str | None = None,
    world_snapshot_admissibility_result_checksum: str | None = None,
    world_snapshot_trust_status: str | None = None,
    world_snapshot_trust_reason_code: str | None = None,
    world_snapshot_trust_result_checksum: str | None = None,
    evidence_envelope_checksum: str | None = None,
    attestation_checksum: str | None = None,
    trust_policy_checksum: str | None = None,
    verifier_certification_status: str | None = None,
    verifier_certification_reason_code: str | None = None,
    verifier_certification_checksum: str | None = None,
    verifier_id: str | None = None,
    verifier_metadata_checksum: str | None = None,
    trust_policy_config_status: str | None = None,
    trust_policy_config_reason_code: str | None = None,
    trust_policy_config_validation_checksum: str | None = None,
    source_id: str | None = None,
    source_type: str | None = None,
    trust_domain: str | None = None,
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
            policy_version=policy_version,
            policy_schema_version=policy_schema_version,
            policy_checksum=policy_checksum,
            policy_authority=policy_authority,
            policy_result_checksum=policy_result_checksum,
            safety_case_id=safety_case_id,
            context_authority_checksum=context_authority_checksum,
            context_id=context_id,
            caller_authority=caller_authority,
            deployment_domain=deployment_domain,
            context_schema_version=context_schema_version,
            context_evaluation_time_ms=context_evaluation_time_ms,
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
            policy_version=policy_version,
            policy_schema_version=policy_schema_version,
            policy_checksum=policy_checksum,
            policy_authority=policy_authority,
            context_authority_checksum=context_authority_checksum,
            world_snapshot_id=world_snapshot_id,
            world_snapshot_checksum=world_snapshot_checksum,
            capability_name=capability_name,
            capability_version=capability_version,
            world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
            freshness_result_checksum=freshness_result_checksum,
            freshness_status=freshness_status,
            world_snapshot_admissibility_status=world_snapshot_admissibility_status,
            world_snapshot_admissibility_reason_code=world_snapshot_admissibility_reason_code,
            world_snapshot_admissibility_result_checksum=(
                world_snapshot_admissibility_result_checksum
            ),
            world_snapshot_trust_status=world_snapshot_trust_status,
            world_snapshot_trust_reason_code=world_snapshot_trust_reason_code,
            world_snapshot_trust_result_checksum=world_snapshot_trust_result_checksum,
            evidence_envelope_checksum=evidence_envelope_checksum,
            attestation_checksum=attestation_checksum,
            trust_policy_checksum=trust_policy_checksum,
            verifier_certification_checksum=verifier_certification_checksum,
            trust_policy_config_validation_checksum=trust_policy_config_validation_checksum,
            verifier_id=verifier_id,
            verifier_metadata_checksum=verifier_metadata_checksum,
            source_id=source_id,
            source_type=source_type,
            trust_domain=trust_domain,
        )
        _validate_policy_result_freshness_bindings(
            policy_result=policy_result,
            world_snapshot_id=world_snapshot_id,
            world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
            freshness_result_checksum=freshness_result_checksum,
            freshness_status=freshness_status,
        )
        _validate_policy_result_identity_bindings(
            policy_result=policy_result,
            policy_version=policy_version,
            policy_schema_version=policy_schema_version,
            policy_checksum=policy_checksum,
            policy_authority=policy_authority,
            context_authority_checksum=context_authority_checksum,
        )
        _require_context_authority_backed_admission(
            context_authority_checksum=context_authority_checksum,
            context_id=context_id,
            caller_authority=caller_authority,
            deployment_domain=deployment_domain,
            context_schema_version=context_schema_version,
            context_evaluation_time_ms=context_evaluation_time_ms,
        )
        _validate_policy_result_trust_bindings(
            policy_result=policy_result,
            world_snapshot_admissibility_status=world_snapshot_admissibility_status,
            world_snapshot_admissibility_reason_code=world_snapshot_admissibility_reason_code,
            world_snapshot_admissibility_result_checksum=(
                world_snapshot_admissibility_result_checksum
            ),
            world_snapshot_trust_status=world_snapshot_trust_status,
            world_snapshot_trust_reason_code=world_snapshot_trust_reason_code,
            world_snapshot_trust_result_checksum=world_snapshot_trust_result_checksum,
            evidence_envelope_checksum=evidence_envelope_checksum,
            attestation_checksum=attestation_checksum,
            trust_policy_checksum=trust_policy_checksum,
            verifier_certification_checksum=verifier_certification_checksum,
            trust_policy_config_validation_checksum=trust_policy_config_validation_checksum,
            verifier_id=verifier_id,
            verifier_metadata_checksum=verifier_metadata_checksum,
            source_id=source_id,
            source_type=source_type,
            trust_domain=trust_domain,
        )
        _require_freshness_backed_admission(
            world_snapshot_id=world_snapshot_id,
            world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
            freshness_result_checksum=freshness_result_checksum,
            freshness_status=freshness_status,
        )
        _require_admissibility_backed_admission(
            world_snapshot_admissibility_status=world_snapshot_admissibility_status,
            world_snapshot_admissibility_reason_code=world_snapshot_admissibility_reason_code,
            world_snapshot_admissibility_result_checksum=(
                world_snapshot_admissibility_result_checksum
            ),
        )
        _require_trust_backed_admission(
            world_snapshot_trust_status=world_snapshot_trust_status,
            world_snapshot_trust_reason_code=world_snapshot_trust_reason_code,
            world_snapshot_trust_result_checksum=world_snapshot_trust_result_checksum,
            evidence_envelope_checksum=evidence_envelope_checksum,
            trust_policy_checksum=trust_policy_checksum,
            source_id=source_id,
            source_type=source_type,
            trust_domain=trust_domain,
        )
        _require_trust_authority_backed_admission(
            verifier_certification_status=verifier_certification_status,
            verifier_certification_reason_code=verifier_certification_reason_code,
            verifier_certification_checksum=verifier_certification_checksum,
            verifier_id=verifier_id,
            verifier_metadata_checksum=verifier_metadata_checksum,
            trust_policy_config_status=trust_policy_config_status,
            trust_policy_config_reason_code=trust_policy_config_reason_code,
            trust_policy_config_validation_checksum=trust_policy_config_validation_checksum,
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

    if policy_result is not None:
        if policy_result.policy_version != policy_admission.policy_version:
            violations.append("POLICY_RESULT_VERSION_MISMATCH")
        if policy_result.policy_schema_version != policy_admission.policy_schema_version:
            violations.append("POLICY_RESULT_SCHEMA_VERSION_MISMATCH")
        if policy_result.policy_checksum != policy_admission.policy_checksum:
            violations.append("POLICY_RESULT_POLICY_CHECKSUM_MISMATCH")
        if policy_result.policy_authority != policy_admission.policy_authority:
            violations.append("POLICY_RESULT_POLICY_AUTHORITY_MISMATCH")
        if policy_result.context_authority_checksum != policy_admission.context_authority_checksum:
            violations.append("POLICY_RESULT_CONTEXT_AUTHORITY_CHECKSUM_MISMATCH")
        _append_mismatch(
            violations,
            policy_result.world_snapshot_id,
            policy_admission.world_snapshot_id,
            "POLICY_RESULT_WORLD_SNAPSHOT_ID",
        )
        if (
            policy_result.world_snapshot_observed_at_ms
            != policy_admission.world_snapshot_observed_at_ms
        ):
            violations.append("POLICY_RESULT_WORLD_SNAPSHOT_OBSERVED_AT_MS_MISMATCH")
        if policy_result.freshness_result_checksum != policy_admission.freshness_result_checksum:
            violations.append("POLICY_RESULT_FRESHNESS_RESULT_CHECKSUM_MISMATCH")
        if policy_result.freshness_status != policy_admission.freshness_status:
            violations.append("POLICY_RESULT_FRESHNESS_STATUS_MISMATCH")
        if (
            policy_result.world_snapshot_admissibility_status
            != policy_admission.world_snapshot_admissibility_status
        ):
            violations.append("POLICY_RESULT_ADMISSIBILITY_STATUS_MISMATCH")
        if (
            policy_result.world_snapshot_admissibility_reason_code
            != policy_admission.world_snapshot_admissibility_reason_code
        ):
            violations.append("POLICY_RESULT_ADMISSIBILITY_REASON_CODE_MISMATCH")
        if (
            policy_result.world_snapshot_admissibility_result_checksum
            != policy_admission.world_snapshot_admissibility_result_checksum
        ):
            violations.append("POLICY_RESULT_ADMISSIBILITY_RESULT_CHECKSUM_MISMATCH")
        if (
            policy_result.world_snapshot_trust_status
            != policy_admission.world_snapshot_trust_status
        ):
            violations.append("POLICY_RESULT_TRUST_STATUS_MISMATCH")
        if (
            policy_result.world_snapshot_trust_reason_code
            != policy_admission.world_snapshot_trust_reason_code
        ):
            violations.append("POLICY_RESULT_TRUST_REASON_CODE_MISMATCH")
        if (
            policy_result.world_snapshot_trust_result_checksum
            != policy_admission.world_snapshot_trust_result_checksum
        ):
            violations.append("POLICY_RESULT_TRUST_RESULT_CHECKSUM_MISMATCH")
        if policy_result.evidence_envelope_checksum != policy_admission.evidence_envelope_checksum:
            violations.append("POLICY_RESULT_EVIDENCE_ENVELOPE_CHECKSUM_MISMATCH")
        if policy_result.attestation_checksum != policy_admission.attestation_checksum:
            violations.append("POLICY_RESULT_ATTESTATION_CHECKSUM_MISMATCH")
        if policy_result.trust_policy_checksum != policy_admission.trust_policy_checksum:
            violations.append("POLICY_RESULT_TRUST_POLICY_CHECKSUM_MISMATCH")
        if (
            policy_result.verifier_certification_checksum
            != policy_admission.verifier_certification_checksum
        ):
            violations.append("POLICY_RESULT_VERIFIER_CERTIFICATION_CHECKSUM_MISMATCH")
        if (
            policy_result.trust_policy_config_validation_checksum
            != policy_admission.trust_policy_config_validation_checksum
        ):
            violations.append("POLICY_RESULT_TRUST_POLICY_CONFIG_CHECKSUM_MISMATCH")
        if policy_result.verifier_id != policy_admission.verifier_id:
            violations.append("POLICY_RESULT_VERIFIER_ID_MISMATCH")
        if policy_result.verifier_metadata_checksum != policy_admission.verifier_metadata_checksum:
            violations.append("POLICY_RESULT_VERIFIER_METADATA_CHECKSUM_MISMATCH")
        if policy_result.source_id != policy_admission.source_id:
            violations.append("POLICY_RESULT_SOURCE_ID_MISMATCH")
        if policy_result.source_type != policy_admission.source_type:
            violations.append("POLICY_RESULT_SOURCE_TYPE_MISMATCH")
        if policy_result.trust_domain != policy_admission.trust_domain:
            violations.append("POLICY_RESULT_TRUST_DOMAIN_MISMATCH")

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
            safety_case.policy_version,
            policy_admission.policy_version,
            "SAFETY_CASE_POLICY_VERSION",
        )
        _append_mismatch(
            violations,
            safety_case.policy_schema_version,
            policy_admission.policy_schema_version,
            "SAFETY_CASE_POLICY_SCHEMA_VERSION",
        )
        _append_mismatch(
            violations,
            safety_case.policy_checksum,
            policy_admission.policy_checksum,
            "SAFETY_CASE_POLICY_CHECKSUM",
        )
        _append_mismatch(
            violations,
            safety_case.policy_authority,
            policy_admission.policy_authority,
            "SAFETY_CASE_POLICY_AUTHORITY",
        )
        _append_mismatch(
            violations,
            safety_case.context_authority_checksum,
            policy_admission.context_authority_checksum,
            "SAFETY_CASE_CONTEXT_AUTHORITY_CHECKSUM",
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
        if (
            safety_case.world_snapshot_observed_at_ms
            != policy_admission.world_snapshot_observed_at_ms
        ):
            violations.append("SAFETY_CASE_WORLD_SNAPSHOT_OBSERVED_AT_MS_MISMATCH")
        if safety_case.freshness_result_checksum != policy_admission.freshness_result_checksum:
            violations.append("SAFETY_CASE_FRESHNESS_RESULT_CHECKSUM_MISMATCH")
        if safety_case.freshness_status != policy_admission.freshness_status:
            violations.append("SAFETY_CASE_FRESHNESS_STATUS_MISMATCH")
        if (
            safety_case.world_snapshot_admissibility_status
            != policy_admission.world_snapshot_admissibility_status
        ):
            violations.append("SAFETY_CASE_ADMISSIBILITY_STATUS_MISMATCH")
        if (
            safety_case.world_snapshot_admissibility_reason_code
            != policy_admission.world_snapshot_admissibility_reason_code
        ):
            violations.append("SAFETY_CASE_ADMISSIBILITY_REASON_CODE_MISMATCH")
        if (
            safety_case.world_snapshot_admissibility_result_checksum
            != policy_admission.world_snapshot_admissibility_result_checksum
        ):
            violations.append("SAFETY_CASE_ADMISSIBILITY_RESULT_CHECKSUM_MISMATCH")
        if safety_case.world_snapshot_trust_status != policy_admission.world_snapshot_trust_status:
            violations.append("SAFETY_CASE_TRUST_STATUS_MISMATCH")
        if (
            safety_case.world_snapshot_trust_reason_code
            != policy_admission.world_snapshot_trust_reason_code
        ):
            violations.append("SAFETY_CASE_TRUST_REASON_CODE_MISMATCH")
        if (
            safety_case.world_snapshot_trust_result_checksum
            != policy_admission.world_snapshot_trust_result_checksum
        ):
            violations.append("SAFETY_CASE_TRUST_RESULT_CHECKSUM_MISMATCH")
        if safety_case.evidence_envelope_checksum != policy_admission.evidence_envelope_checksum:
            violations.append("SAFETY_CASE_EVIDENCE_ENVELOPE_CHECKSUM_MISMATCH")
        if safety_case.attestation_checksum != policy_admission.attestation_checksum:
            violations.append("SAFETY_CASE_ATTESTATION_CHECKSUM_MISMATCH")
        if safety_case.trust_policy_checksum != policy_admission.trust_policy_checksum:
            violations.append("SAFETY_CASE_TRUST_POLICY_CHECKSUM_MISMATCH")
        if (
            safety_case.verifier_certification_checksum
            != policy_admission.verifier_certification_checksum
        ):
            violations.append("SAFETY_CASE_VERIFIER_CERTIFICATION_CHECKSUM_MISMATCH")
        if (
            safety_case.trust_policy_config_validation_checksum
            != policy_admission.trust_policy_config_validation_checksum
        ):
            violations.append("SAFETY_CASE_TRUST_POLICY_CONFIG_CHECKSUM_MISMATCH")
        if safety_case.verifier_id != policy_admission.verifier_id:
            violations.append("SAFETY_CASE_VERIFIER_ID_MISMATCH")
        if safety_case.verifier_metadata_checksum != policy_admission.verifier_metadata_checksum:
            violations.append("SAFETY_CASE_VERIFIER_METADATA_CHECKSUM_MISMATCH")
        if safety_case.source_id != policy_admission.source_id:
            violations.append("SAFETY_CASE_SOURCE_ID_MISMATCH")
        if safety_case.source_type != policy_admission.source_type:
            violations.append("SAFETY_CASE_SOURCE_TYPE_MISMATCH")
        if safety_case.trust_domain != policy_admission.trust_domain:
            violations.append("SAFETY_CASE_TRUST_DOMAIN_MISMATCH")
        if policy_result is not None and safety_case.policy_result != policy_result:
            violations.append("SAFETY_CASE_POLICY_RESULT_MISMATCH")

    if policy_admission.freshness_status != "FRESH":
        violations.append("FRESHNESS_STATUS_NOT_FRESH")
    if policy_admission.freshness_result_checksum is None:
        violations.append("FRESHNESS_RESULT_CHECKSUM_MISSING")
    if policy_admission.world_snapshot_id is None:
        violations.append("FRESHNESS_WORLD_SNAPSHOT_ID_MISSING")
    if policy_admission.policy_version is None:
        violations.append("POLICY_VERSION_MISSING")
    if policy_admission.policy_schema_version is None:
        violations.append("POLICY_SCHEMA_VERSION_MISSING")
    if policy_admission.policy_checksum is None:
        violations.append("POLICY_CHECKSUM_MISSING")
    if policy_admission.policy_authority is None:
        violations.append("POLICY_AUTHORITY_MISSING")
    if policy_admission.context_authority_checksum is None:
        violations.append("CONTEXT_AUTHORITY_CHECKSUM_MISSING")
    if policy_admission.context_id is None:
        violations.append("CONTEXT_ID_MISSING")
    if policy_admission.caller_authority is None:
        violations.append("CALLER_AUTHORITY_MISSING")
    if policy_admission.deployment_domain is None:
        violations.append("DEPLOYMENT_DOMAIN_MISSING")
    if policy_admission.context_schema_version is None:
        violations.append("CONTEXT_SCHEMA_VERSION_MISSING")
    if policy_admission.context_evaluation_time_ms is None:
        violations.append("CONTEXT_EVALUATION_TIME_MISSING")
    if policy_admission.world_snapshot_observed_at_ms is None:
        violations.append("FRESHNESS_WORLD_SNAPSHOT_OBSERVED_AT_MS_MISSING")
    if policy_admission.world_snapshot_admissibility_status != "ADMISSIBLE":
        violations.append("ADMISSIBILITY_STATUS_NOT_ADMISSIBLE")
    if policy_admission.world_snapshot_admissibility_reason_code is None:
        violations.append("ADMISSIBILITY_REASON_MISSING")
    if policy_admission.world_snapshot_admissibility_result_checksum is None:
        violations.append("ADMISSIBILITY_RESULT_CHECKSUM_MISSING")
    if policy_admission.world_snapshot_trust_status != "TRUSTED":
        violations.append("TRUST_STATUS_NOT_TRUSTED")
    if policy_admission.world_snapshot_trust_result_checksum is None:
        violations.append("TRUST_RESULT_CHECKSUM_MISSING")
    if policy_admission.evidence_envelope_checksum is None:
        violations.append("TRUST_EVIDENCE_ENVELOPE_CHECKSUM_MISSING")
    if policy_admission.trust_policy_checksum is None:
        violations.append("TRUST_POLICY_CHECKSUM_MISSING")
    if policy_admission.verifier_certification_status != "CERTIFIED":
        violations.append("VERIFIER_CERTIFICATION_STATUS_NOT_CERTIFIED")
    if policy_admission.verifier_certification_reason_code is None:
        violations.append("VERIFIER_CERTIFICATION_REASON_MISSING")
    if policy_admission.verifier_certification_checksum is None:
        violations.append("VERIFIER_CERTIFICATION_CHECKSUM_MISSING")
    if policy_admission.verifier_id is None:
        violations.append("VERIFIER_ID_MISSING")
    if policy_admission.verifier_metadata_checksum is None:
        violations.append("VERIFIER_METADATA_CHECKSUM_MISSING")
    if policy_admission.trust_policy_config_status != "VALID":
        violations.append("TRUST_POLICY_CONFIG_STATUS_NOT_VALID")
    if policy_admission.trust_policy_config_reason_code is None:
        violations.append("TRUST_POLICY_CONFIG_REASON_MISSING")
    if policy_admission.trust_policy_config_validation_checksum is None:
        violations.append("TRUST_POLICY_CONFIG_VALIDATION_CHECKSUM_MISSING")
    if policy_admission.source_id is None:
        violations.append("TRUST_SOURCE_ID_MISSING")
    if policy_admission.source_type is None:
        violations.append("TRUST_SOURCE_TYPE_MISSING")
    if policy_admission.trust_domain is None:
        violations.append("TRUST_DOMAIN_MISSING")

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
    policy_version: str | None,
    policy_schema_version: str | None,
    policy_checksum: str | None,
    policy_authority: str | None,
    policy_result_checksum: str | None,
    safety_case_id: str | None,
    context_authority_checksum: str | None,
    context_id: str | None,
    caller_authority: str | None,
    deployment_domain: str | None,
    context_schema_version: str | None,
    context_evaluation_time_ms: int | None,
    capability_name: str | None,
    capability_version: str | None,
) -> None:
    required_values = {
        "audit_id": audit_id,
        "plan_id": plan_id,
        "plan_checksum": plan_checksum,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_schema_version": policy_schema_version,
        "policy_checksum": policy_checksum,
        "policy_authority": policy_authority,
        "policy_result_checksum": policy_result_checksum,
        "safety_case_id": safety_case_id,
        "context_authority_checksum": context_authority_checksum,
        "context_id": context_id,
        "caller_authority": caller_authority,
        "deployment_domain": deployment_domain,
        "context_schema_version": context_schema_version,
        "context_evaluation_time_ms": context_evaluation_time_ms,
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
    policy_version: str | None,
    policy_schema_version: str | None,
    policy_checksum: str | None,
    policy_authority: str | None,
    context_authority_checksum: str | None,
    world_snapshot_id: str | None,
    world_snapshot_checksum: str | None,
    capability_name: str | None,
    capability_version: str | None,
    world_snapshot_observed_at_ms: int | None = None,
    freshness_result_checksum: str | None = None,
    freshness_status: str | None = None,
    world_snapshot_admissibility_status: str | None = None,
    world_snapshot_admissibility_reason_code: str | None = None,
    world_snapshot_admissibility_result_checksum: str | None = None,
    world_snapshot_trust_status: str | None = None,
    world_snapshot_trust_reason_code: str | None = None,
    world_snapshot_trust_result_checksum: str | None = None,
    evidence_envelope_checksum: str | None = None,
    attestation_checksum: str | None = None,
    trust_policy_checksum: str | None = None,
    verifier_certification_checksum: str | None = None,
    trust_policy_config_validation_checksum: str | None = None,
    verifier_id: str | None = None,
    verifier_metadata_checksum: str | None = None,
    source_id: str | None = None,
    source_type: str | None = None,
    trust_domain: str | None = None,
) -> None:
    if safety_case.audited_plan_id != audit_id:
        raise ValueError("safety_case audited plan binding must match admission audit_id")
    if safety_case.plan_id != plan_id:
        raise ValueError("safety_case plan_id must match admission plan_id")
    if safety_case.plan_checksum != plan_checksum:
        raise ValueError("safety_case plan_checksum must match admission plan_checksum")
    if safety_case.policy_version != policy_version:
        raise ValueError("safety_case policy_version must match admission")
    if safety_case.policy_schema_version != policy_schema_version:
        raise ValueError("safety_case policy_schema_version must match admission")
    if safety_case.policy_checksum != policy_checksum:
        raise ValueError("safety_case policy_checksum must match admission")
    if safety_case.policy_authority != policy_authority:
        raise ValueError("safety_case policy_authority must match admission")
    if safety_case.context_authority_checksum != context_authority_checksum:
        raise ValueError("safety_case context_authority_checksum must match admission")
    if safety_case.world_snapshot_id != world_snapshot_id:
        raise ValueError("safety_case world_snapshot_id must match admission")
    if safety_case.world_snapshot_checksum != world_snapshot_checksum:
        raise ValueError("safety_case world_snapshot_checksum must match admission")
    if safety_case.capability_name != capability_name:
        raise ValueError("safety_case capability_name must match admission")
    if safety_case.capability_version != capability_version:
        raise ValueError("safety_case capability_version must match admission")
    if safety_case.world_snapshot_observed_at_ms != world_snapshot_observed_at_ms:
        raise ValueError("safety_case world_snapshot_observed_at_ms must match admission")
    if safety_case.freshness_result_checksum != freshness_result_checksum:
        raise ValueError("safety_case freshness_result_checksum must match admission")
    if safety_case.freshness_status != freshness_status:
        raise ValueError("safety_case freshness_status must match admission")
    if safety_case.world_snapshot_admissibility_status != world_snapshot_admissibility_status:
        raise ValueError("safety_case world_snapshot_admissibility_status must match admission")
    if (
        safety_case.world_snapshot_admissibility_reason_code
        != world_snapshot_admissibility_reason_code
    ):
        raise ValueError(
            "safety_case world_snapshot_admissibility_reason_code must match admission"
        )
    if (
        safety_case.world_snapshot_admissibility_result_checksum
        != world_snapshot_admissibility_result_checksum
    ):
        raise ValueError(
            "safety_case world_snapshot_admissibility_result_checksum must match admission"
        )
    if safety_case.world_snapshot_trust_status != world_snapshot_trust_status:
        raise ValueError("safety_case world_snapshot_trust_status must match admission")
    if safety_case.world_snapshot_trust_reason_code != world_snapshot_trust_reason_code:
        raise ValueError("safety_case world_snapshot_trust_reason_code must match admission")
    if safety_case.world_snapshot_trust_result_checksum != world_snapshot_trust_result_checksum:
        raise ValueError("safety_case world_snapshot_trust_result_checksum must match admission")
    if safety_case.evidence_envelope_checksum != evidence_envelope_checksum:
        raise ValueError("safety_case evidence_envelope_checksum must match admission")
    if safety_case.attestation_checksum != attestation_checksum:
        raise ValueError("safety_case attestation_checksum must match admission")
    if safety_case.trust_policy_checksum != trust_policy_checksum:
        raise ValueError("safety_case trust_policy_checksum must match admission")
    if safety_case.verifier_certification_checksum != verifier_certification_checksum:
        raise ValueError("safety_case verifier_certification_checksum must match admission")
    if (
        safety_case.trust_policy_config_validation_checksum
        != trust_policy_config_validation_checksum
    ):
        raise ValueError("safety_case trust_policy_config_validation_checksum must match admission")
    if safety_case.verifier_id != verifier_id:
        raise ValueError("safety_case verifier_id must match admission")
    if safety_case.verifier_metadata_checksum != verifier_metadata_checksum:
        raise ValueError("safety_case verifier_metadata_checksum must match admission")
    if safety_case.source_id != source_id:
        raise ValueError("safety_case source_id must match admission")
    if safety_case.source_type != source_type:
        raise ValueError("safety_case source_type must match admission")
    if safety_case.trust_domain != trust_domain:
        raise ValueError("safety_case trust_domain must match admission")


def _validate_policy_result_freshness_bindings(
    *,
    policy_result: PolicyEvaluationResult,
    world_snapshot_id: str | None,
    world_snapshot_observed_at_ms: int | None,
    freshness_result_checksum: str | None,
    freshness_status: str | None,
) -> None:
    if policy_result.world_snapshot_id != world_snapshot_id:
        raise ValueError("policy_result world_snapshot_id must match admission")
    if policy_result.world_snapshot_observed_at_ms != world_snapshot_observed_at_ms:
        raise ValueError("policy_result world_snapshot_observed_at_ms must match admission")
    if policy_result.freshness_result_checksum != freshness_result_checksum:
        raise ValueError("policy_result freshness_result_checksum must match admission")
    if policy_result.freshness_status != freshness_status:
        raise ValueError("policy_result freshness_status must match admission")


def _validate_policy_result_identity_bindings(
    *,
    policy_result: PolicyEvaluationResult,
    policy_version: str | None,
    policy_schema_version: str | None,
    policy_checksum: str | None,
    policy_authority: str | None,
    context_authority_checksum: str | None,
) -> None:
    if policy_result.policy_version != policy_version:
        raise ValueError("policy_result policy_version must match admission")
    if policy_result.policy_schema_version != policy_schema_version:
        raise ValueError("policy_result policy_schema_version must match admission")
    if policy_result.policy_checksum != policy_checksum:
        raise ValueError("policy_result policy_checksum must match admission")
    if policy_result.policy_authority != policy_authority:
        raise ValueError("policy_result policy_authority must match admission")
    if policy_result.context_authority_checksum != context_authority_checksum:
        raise ValueError("policy_result context_authority_checksum must match admission")


def _validate_policy_result_trust_bindings(
    *,
    policy_result: PolicyEvaluationResult,
    world_snapshot_admissibility_status: str | None,
    world_snapshot_admissibility_reason_code: str | None,
    world_snapshot_admissibility_result_checksum: str | None,
    world_snapshot_trust_status: str | None,
    world_snapshot_trust_reason_code: str | None,
    world_snapshot_trust_result_checksum: str | None,
    evidence_envelope_checksum: str | None,
    attestation_checksum: str | None,
    trust_policy_checksum: str | None,
    verifier_certification_checksum: str | None,
    trust_policy_config_validation_checksum: str | None,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    source_id: str | None,
    source_type: str | None,
    trust_domain: str | None,
) -> None:
    if policy_result.world_snapshot_admissibility_status != world_snapshot_admissibility_status:
        raise ValueError("policy_result world_snapshot_admissibility_status must match admission")
    if (
        policy_result.world_snapshot_admissibility_reason_code
        != world_snapshot_admissibility_reason_code
    ):
        raise ValueError(
            "policy_result world_snapshot_admissibility_reason_code must match admission"
        )
    if (
        policy_result.world_snapshot_admissibility_result_checksum
        != world_snapshot_admissibility_result_checksum
    ):
        raise ValueError(
            "policy_result world_snapshot_admissibility_result_checksum must match admission"
        )
    if policy_result.world_snapshot_trust_status != world_snapshot_trust_status:
        raise ValueError("policy_result world_snapshot_trust_status must match admission")
    if policy_result.world_snapshot_trust_reason_code != world_snapshot_trust_reason_code:
        raise ValueError("policy_result world_snapshot_trust_reason_code must match admission")
    if policy_result.world_snapshot_trust_result_checksum != world_snapshot_trust_result_checksum:
        raise ValueError("policy_result world_snapshot_trust_result_checksum must match admission")
    if policy_result.evidence_envelope_checksum != evidence_envelope_checksum:
        raise ValueError("policy_result evidence_envelope_checksum must match admission")
    if policy_result.attestation_checksum != attestation_checksum:
        raise ValueError("policy_result attestation_checksum must match admission")
    if policy_result.trust_policy_checksum != trust_policy_checksum:
        raise ValueError("policy_result trust_policy_checksum must match admission")
    if policy_result.verifier_certification_checksum != verifier_certification_checksum:
        raise ValueError("policy_result verifier_certification_checksum must match admission")
    if (
        policy_result.trust_policy_config_validation_checksum
        != trust_policy_config_validation_checksum
    ):
        raise ValueError(
            "policy_result trust_policy_config_validation_checksum must match admission"
        )
    if policy_result.verifier_id != verifier_id:
        raise ValueError("policy_result verifier_id must match admission")
    if policy_result.verifier_metadata_checksum != verifier_metadata_checksum:
        raise ValueError("policy_result verifier_metadata_checksum must match admission")
    if policy_result.source_id != source_id:
        raise ValueError("policy_result source_id must match admission")
    if policy_result.source_type != source_type:
        raise ValueError("policy_result source_type must match admission")
    if policy_result.trust_domain != trust_domain:
        raise ValueError("policy_result trust_domain must match admission")


def _require_freshness_backed_admission(
    *,
    world_snapshot_id: str | None,
    world_snapshot_observed_at_ms: int | None,
    freshness_result_checksum: str | None,
    freshness_status: str | None,
) -> None:
    if world_snapshot_id is None:
        raise ValueError("allowed ENFORCE admission requires freshness-backed world_snapshot_id")
    if world_snapshot_observed_at_ms is None:
        raise ValueError(
            "allowed ENFORCE admission requires freshness-backed world_snapshot_observed_at_ms"
        )
    if freshness_result_checksum is None:
        raise ValueError("allowed ENFORCE admission requires freshness_result_checksum")
    if freshness_status != "FRESH":
        raise ValueError("allowed ENFORCE admission requires freshness_status FRESH")


def _require_context_authority_backed_admission(
    *,
    context_authority_checksum: str | None,
    context_id: str | None,
    caller_authority: str | None,
    deployment_domain: str | None,
    context_schema_version: str | None,
    context_evaluation_time_ms: int | None,
) -> None:
    required_values = {
        "context_authority_checksum": context_authority_checksum,
        "context_id": context_id,
        "caller_authority": caller_authority,
        "deployment_domain": deployment_domain,
        "context_schema_version": context_schema_version,
        "context_evaluation_time_ms": context_evaluation_time_ms,
    }
    missing = tuple(key for key, value in required_values.items() if value is None)
    if missing:
        raise ValueError(
            f"allowed ENFORCE admission missing context authority: {', '.join(missing)}"
        )


def _require_admissibility_backed_admission(
    *,
    world_snapshot_admissibility_status: str | None,
    world_snapshot_admissibility_reason_code: str | None,
    world_snapshot_admissibility_result_checksum: str | None,
) -> None:
    if world_snapshot_admissibility_status != "ADMISSIBLE":
        raise ValueError(
            "allowed ENFORCE admission requires world_snapshot_admissibility_status ADMISSIBLE"
        )
    if world_snapshot_admissibility_reason_code is None:
        raise ValueError("allowed ENFORCE admission requires admissibility reason code")
    if world_snapshot_admissibility_result_checksum is None:
        raise ValueError("allowed ENFORCE admission requires admissibility result checksum")


def _require_trust_backed_admission(
    *,
    world_snapshot_trust_status: str | None,
    world_snapshot_trust_reason_code: str | None,
    world_snapshot_trust_result_checksum: str | None,
    evidence_envelope_checksum: str | None,
    trust_policy_checksum: str | None,
    source_id: str | None,
    source_type: str | None,
    trust_domain: str | None,
) -> None:
    if world_snapshot_trust_status != "TRUSTED":
        raise ValueError("allowed ENFORCE admission requires world_snapshot_trust_status TRUSTED")
    if world_snapshot_trust_reason_code is None:
        raise ValueError("allowed ENFORCE admission requires trust reason code")
    if world_snapshot_trust_result_checksum is None:
        raise ValueError("allowed ENFORCE admission requires trust result checksum")
    if evidence_envelope_checksum is None:
        raise ValueError("allowed ENFORCE admission requires evidence envelope checksum")
    if trust_policy_checksum is None:
        raise ValueError("allowed ENFORCE admission requires trust policy checksum")
    if source_id is None:
        raise ValueError("allowed ENFORCE admission requires source_id")
    if source_type is None:
        raise ValueError("allowed ENFORCE admission requires source_type")
    if trust_domain is None:
        raise ValueError("allowed ENFORCE admission requires trust_domain")


def _require_trust_authority_backed_admission(
    *,
    verifier_certification_status: str | None,
    verifier_certification_reason_code: str | None,
    verifier_certification_checksum: str | None,
    verifier_id: str | None,
    verifier_metadata_checksum: str | None,
    trust_policy_config_status: str | None,
    trust_policy_config_reason_code: str | None,
    trust_policy_config_validation_checksum: str | None,
) -> None:
    if verifier_certification_status != "CERTIFIED":
        raise ValueError("allowed ENFORCE admission requires certified verifier")
    if verifier_certification_reason_code is None:
        raise ValueError("allowed ENFORCE admission requires verifier certification reason")
    if verifier_certification_checksum is None:
        raise ValueError("allowed ENFORCE admission requires verifier certification checksum")
    if verifier_id is None:
        raise ValueError("allowed ENFORCE admission requires verifier_id")
    if verifier_metadata_checksum is None:
        raise ValueError("allowed ENFORCE admission requires verifier metadata checksum")
    if trust_policy_config_status != "VALID":
        raise ValueError("allowed ENFORCE admission requires valid trust policy config")
    if trust_policy_config_reason_code is None:
        raise ValueError("allowed ENFORCE admission requires trust policy config reason")
    if trust_policy_config_validation_checksum is None:
        raise ValueError(
            "allowed ENFORCE admission requires trust policy config validation checksum"
        )


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


def _normalize_optional_observed_at_ms(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("world_snapshot_observed_at_ms must be an integer or None")
    if value < 0:
        raise ValueError("world_snapshot_observed_at_ms must be >= 0")
    return value


_VALID_FRESHNESS_STATUS_VALUES = frozenset(
    {
        "FRESH",
        "STALE",
        "MISSING_SNAPSHOT",
        "MISSING_TIMESTAMP",
        "MISSING_EVALUATION_TIME",
        "FUTURE_DATED",
        "INVALID_MAX_AGE",
        "INVALID_TIMESTAMP",
        "SNAPSHOT_ID_MISSING",
        "CONTRADICTORY_METADATA",
        "NOT_CHECKED",
        "ERROR",
    }
)

_VALID_ADMISSIBILITY_STATUS_VALUES = frozenset(
    {
        "ADMISSIBLE",
        "SNAPSHOT_MISSING",
        "SNAPSHOT_CHECKSUM_MISSING",
        "SNAPSHOT_CHECKSUM_EMPTY",
        "CAPABILITY_SCOPE_MISSING",
        "CAPABILITY_SCOPE_EMPTY",
        "CAPABILITY_SCOPE_MISMATCH",
        "FACTS_MALFORMED",
        "DECLARED_FACT_KEY_MISSING",
        "REQUIRED_FACT_KEY_MISSING",
        "REQUIRED_FACT_KEY_UNDECLARED",
        "CONTRADICTORY_SNAPSHOT_EVIDENCE",
    }
)

_VALID_TRUST_STATUS_VALUES = frozenset(
    {
        "TRUSTED",
        "UNTRUSTED",
        "MISSING_EVIDENCE",
        "MISSING_TRUST_POLICY",
        "MISSING_VERIFIER",
        "SNAPSHOT_CHECKSUM_MISMATCH",
        "SOURCE_NOT_ALLOWED",
        "SOURCE_TYPE_NOT_ALLOWED",
        "TRUST_DOMAIN_NOT_ALLOWED",
        "CAPABILITY_NOT_ALLOWED",
        "ATTESTATION_MISSING",
        "ATTESTATION_INVALID",
        "ATTESTATION_EXPIRED",
        "ATTESTATION_NOT_YET_VALID",
        "ATTESTATION_REPLAY_DETECTED",
        "UNSUPPORTED_ATTESTATION_ALGORITHM",
        "MALFORMED_EVIDENCE",
        "CONTRADICTORY_EVIDENCE",
    }
)

_VALID_VERIFIER_CERTIFICATION_STATUS_VALUES = frozenset(
    {
        "CERTIFIED",
        "MISSING_VERIFIER",
        "UNSUPPORTED_ADAPTER_TYPE",
        "MISSING_VERIFIER_ID",
        "MISSING_DECLARED_ALGORITHMS",
        "MISSING_DECLARED_KEY_IDS",
        "POSITIVE_VECTOR_FAILED",
        "NEGATIVE_VECTOR_ACCEPTED",
        "WRONG_SNAPSHOT_ACCEPTED",
        "WRONG_ENVELOPE_ACCEPTED",
        "WRONG_KEY_ACCEPTED",
        "UNSUPPORTED_ALGORITHM_ACCEPTED",
        "NON_DETERMINISTIC_RESULT",
        "MALFORMED_RESULT",
        "CHECKSUM_BINDING_MISSING",
        "UNSAFE_FOR_ENFORCE",
    }
)

_VALID_TRUST_POLICY_CONFIG_STATUS_VALUES = frozenset(
    {
        "VALID",
        "MISSING_POLICY",
        "EMPTY_ALLOWED_SOURCES",
        "EMPTY_ALLOWED_SOURCE_TYPES",
        "EMPTY_ALLOWED_DOMAINS",
        "EMPTY_ALLOWED_CAPABILITIES",
        "EMPTY_ALLOWED_ALGORITHMS",
        "EMPTY_ALLOWED_KEY_IDS",
        "WILDCARD_SOURCE_NOT_ALLOWED",
        "WILDCARD_DOMAIN_NOT_ALLOWED",
        "WILDCARD_CAPABILITY_NOT_ALLOWED",
        "TEST_SOURCE_FOR_PHYSICAL_RUNTIME",
        "SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME",
        "ATTESTATION_REQUIRED_FALSE_IN_ENFORCE",
        "POLICY_VERIFIER_ALGORITHM_MISMATCH",
        "POLICY_VERIFIER_KEY_MISMATCH",
        "POLICY_CAPABILITY_CONTEXT_MISMATCH",
        "CONFLICTING_POLICY_FIELDS",
        "MALFORMED_POLICY",
    }
)

_VALID_SOURCE_TYPE_VALUES = frozenset(
    {
        "TEST_FIXTURE",
        "SIMULATOR",
        "SENSOR_BRIDGE",
        "HUMAN_OPERATOR",
        "STATIC_SCENE",
        "UNKNOWN",
    }
)

_VALID_TRUST_DOMAIN_VALUES = frozenset(
    {"TEST", "SIMULATION", "DEVELOPMENT", "STAGING", "PHYSICAL_RUNTIME"}
)


def _normalize_optional_freshness_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("freshness_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("freshness_status must not contain surrounding whitespace")
    if value not in _VALID_FRESHNESS_STATUS_VALUES:
        raise ValueError(f"freshness_status not recognised: {value!r}")
    return value


def _normalize_optional_admissibility_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("world_snapshot_admissibility_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError(
            "world_snapshot_admissibility_status must not contain surrounding whitespace"
        )
    if value not in _VALID_ADMISSIBILITY_STATUS_VALUES:
        raise ValueError(f"world_snapshot_admissibility_status not recognised: {value!r}")
    return value


def _normalize_optional_trust_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("world_snapshot_trust_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("world_snapshot_trust_status must not contain surrounding whitespace")
    if value not in _VALID_TRUST_STATUS_VALUES:
        raise ValueError(f"world_snapshot_trust_status not recognised: {value!r}")
    return value


def _normalize_optional_certification_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("verifier_certification_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("verifier_certification_status must not contain surrounding whitespace")
    if value not in _VALID_VERIFIER_CERTIFICATION_STATUS_VALUES:
        raise ValueError(f"verifier_certification_status not recognised: {value!r}")
    return value


def _normalize_optional_config_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("trust_policy_config_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("trust_policy_config_status must not contain surrounding whitespace")
    if value not in _VALID_TRUST_POLICY_CONFIG_STATUS_VALUES:
        raise ValueError(f"trust_policy_config_status not recognised: {value!r}")
    return value


def _normalize_optional_source_type(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("source_type must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("source_type must not contain surrounding whitespace")
    if value not in _VALID_SOURCE_TYPE_VALUES:
        raise ValueError(f"source_type not recognised: {value!r}")
    return value


def _normalize_optional_trust_domain(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("trust_domain must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("trust_domain must not contain surrounding whitespace")
    if value not in _VALID_TRUST_DOMAIN_VALUES:
        raise ValueError(f"trust_domain not recognised: {value!r}")
    return value


def _normalize_optional_reason_code(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a machine-readable uppercase reason code")
    return normalized


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


def _normalize_policy_version_binding(
    policy_version: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_version, "policy_version")
    expected = policy_result.policy_version if policy_result is not None else None
    if normalized is None:
        return expected
    if expected is not None and normalized != expected:
        raise ValueError("policy_version must match policy_result.policy_version")
    return normalized


def _normalize_policy_schema_version_binding(
    policy_schema_version: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_schema_version, "policy_schema_version")
    expected = policy_result.policy_schema_version if policy_result is not None else None
    if normalized is None:
        return expected
    if expected is not None and normalized != expected:
        raise ValueError("policy_schema_version must match policy_result.policy_schema_version")
    return normalized


def _normalize_policy_checksum_binding(
    policy_checksum: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_checksum, "policy_checksum")
    expected = policy_result.policy_checksum if policy_result is not None else None
    if normalized is None:
        return expected
    if expected is not None and normalized != expected:
        raise ValueError("policy_checksum must match policy_result.policy_checksum")
    return normalized


def _normalize_policy_authority_binding(
    policy_authority: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(policy_authority, "policy_authority")
    expected = policy_result.policy_authority if policy_result is not None else None
    if normalized is None:
        return expected
    if expected is not None and normalized != expected:
        raise ValueError("policy_authority must match policy_result.policy_authority")
    return normalized


def _normalize_context_authority_checksum_binding(
    context_authority_checksum: str | None,
    policy_result: PolicyEvaluationResult | None,
) -> str | None:
    normalized = _normalize_optional_text(context_authority_checksum, "context_authority_checksum")
    expected = policy_result.context_authority_checksum if policy_result is not None else None
    if normalized is None:
        return expected
    if expected is not None and normalized != expected:
        raise ValueError(
            "context_authority_checksum must match policy_result.context_authority_checksum"
        )
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
    validate_resource_bounds(values, label="policy admission mapping")
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
