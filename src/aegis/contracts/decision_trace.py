"""Decision trace contracts for deterministic approval-boundary receipts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import cast

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.gate import GateDecision
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import FrozenJsonValue, JsonValue, freeze_json_mapping
from aegis.contracts.planning import CommandPlan, CommandStep
from aegis.contracts.policy import (
    PolicyEvaluationResult,
    SafetyCase,
    policy_evaluation_result_checksum,
)
from aegis.contracts.policy_admission import PolicyAdmissionRecord
from aegis.contracts.validation import ValidationResult, Violation

type CanonicalTraceValue = (
    str | int | float | bool | None | list[CanonicalTraceValue] | dict[str, CanonicalTraceValue]
)

DECISION_TRACE_STAGE_ORDER = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "verifier_certification",
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "policy_admission",
    "gate_decision",
)
"""Canonical stage order for approval-boundary decision traces."""

ALLOW_REQUIRED_STAGE_CHAIN = DECISION_TRACE_STAGE_ORDER
"""All stages required before a final ALLOWED pipeline result can be trusted."""

_ALLOWED_STAGE_NAMES = frozenset(DECISION_TRACE_STAGE_ORDER)


@dataclass(frozen=True, slots=True, init=False)
class DecisionTraceStep:
    """One immutable stage in the deterministic decision trace.

    Args:
        stage_name: Canonical stage identifier from ``DECISION_TRACE_STAGE_ORDER``.
        stage_status: Deterministic status emitted by the stage.
        stage_reason: Optional stable reason code for the status.
        input_checksum: Canonical identity consumed by the stage.
        output_checksum: Canonical identity produced by the stage.
        predecessor_checksum: Previous step checksum, or ``None`` for the first step.
        metadata: JSON-compatible inert metadata for external audit consumers.
        stage_checksum: Optional supplied checksum; must match recomputation.

    Raises:
        ValueError: If identifiers are malformed, metadata is not JSON-compatible,
            the stage name is unknown, or the checksum does not match.
    """

    stage_name: str
    stage_status: str
    stage_reason: str | None
    input_checksum: str
    output_checksum: str
    predecessor_checksum: str | None
    metadata: Mapping[str, FrozenJsonValue]
    stage_checksum: str

    def __init__(
        self,
        *,
        stage_name: str,
        stage_status: str,
        stage_reason: str | None,
        input_checksum: str,
        output_checksum: str,
        predecessor_checksum: str | None,
        metadata: Mapping[str, JsonValue] | None = None,
        stage_checksum: str | None = None,
    ) -> None:
        normalized_stage_name = _normalize_stage_name(stage_name)
        normalized_stage_status = _normalize_required_text(stage_status, "stage_status")
        normalized_stage_reason = _normalize_optional_text(stage_reason, "stage_reason")
        normalized_input_checksum = _normalize_required_text(input_checksum, "input_checksum")
        normalized_output_checksum = _normalize_required_text(output_checksum, "output_checksum")
        normalized_predecessor_checksum = _normalize_optional_text(
            predecessor_checksum, "predecessor_checksum"
        )
        frozen_metadata = freeze_json_mapping(metadata or {})
        computed_checksum = decision_trace_step_checksum(
            stage_name=normalized_stage_name,
            stage_status=normalized_stage_status,
            stage_reason=normalized_stage_reason,
            input_checksum=normalized_input_checksum,
            output_checksum=normalized_output_checksum,
            predecessor_checksum=normalized_predecessor_checksum,
            metadata=frozen_metadata,
        )
        normalized_stage_checksum = _normalize_supplied_checksum(
            stage_checksum, computed_checksum, "stage_checksum"
        )

        object.__setattr__(self, "stage_name", normalized_stage_name)
        object.__setattr__(self, "stage_status", normalized_stage_status)
        object.__setattr__(self, "stage_reason", normalized_stage_reason)
        object.__setattr__(self, "input_checksum", normalized_input_checksum)
        object.__setattr__(self, "output_checksum", normalized_output_checksum)
        object.__setattr__(self, "predecessor_checksum", normalized_predecessor_checksum)
        object.__setattr__(self, "metadata", frozen_metadata)
        object.__setattr__(self, "stage_checksum", normalized_stage_checksum)


@dataclass(frozen=True, slots=True, init=False)
class DecisionTrace:
    """Immutable, hash-linked trace of one pipeline decision."""

    steps: tuple[DecisionTraceStep, ...]
    trace_checksum: str

    def __init__(
        self,
        steps: Iterable[DecisionTraceStep],
        *,
        trace_checksum: str | None = None,
    ) -> None:
        steps_tuple = tuple(steps)
        if not steps_tuple:
            raise ValueError("decision trace must contain at least one step")
        errors = decision_trace_integrity_errors_for_steps(steps_tuple)
        if errors:
            raise ValueError(errors[0])
        computed_checksum = decision_trace_checksum(steps_tuple)
        normalized_trace_checksum = _normalize_supplied_checksum(
            trace_checksum, computed_checksum, "trace_checksum"
        )

        object.__setattr__(self, "steps", steps_tuple)
        object.__setattr__(self, "trace_checksum", normalized_trace_checksum)


def decision_trace_step_checksum(
    *,
    stage_name: str,
    stage_status: str,
    stage_reason: str | None,
    input_checksum: str,
    output_checksum: str,
    predecessor_checksum: str | None,
    metadata: Mapping[str, FrozenJsonValue],
) -> str:
    """Return the deterministic checksum for a decision trace step."""
    return _sha256(
        {
            "stage_name": stage_name,
            "stage_status": stage_status,
            "stage_reason": stage_reason,
            "input_checksum": input_checksum,
            "output_checksum": output_checksum,
            "predecessor_checksum": predecessor_checksum,
            "metadata": _canonical_mapping(metadata),
        }
    )


def decision_trace_checksum(steps: Iterable[DecisionTraceStep]) -> str:
    """Return the deterministic checksum for an ordered decision trace."""
    return _sha256({"stage_checksums": [step.stage_checksum for step in steps]})


def decision_trace_integrity_errors(trace: DecisionTrace) -> tuple[str, ...]:
    """Return deterministic integrity errors for a possibly mutated trace."""
    errors = list(decision_trace_integrity_errors_for_steps(trace.steps))
    recomputed_trace_checksum = decision_trace_checksum(trace.steps)
    if trace.trace_checksum != recomputed_trace_checksum:
        errors.append("DECISION_TRACE_CHECKSUM_MISMATCH")
    return tuple(errors)


def decision_trace_integrity_errors_for_steps(
    steps: tuple[DecisionTraceStep, ...],
) -> tuple[str, ...]:
    """Return integrity errors for ordered trace steps."""
    errors: list[str] = []
    seen_names: set[str] = set()
    stage_indexes: list[int] = []
    previous_stage_checksum: str | None = None
    previous_output_checksum: str | None = None
    for index, step in enumerate(steps):
        if step.stage_name not in _ALLOWED_STAGE_NAMES:
            errors.append("DECISION_TRACE_UNKNOWN_STAGE")
        elif step.stage_name in seen_names:
            errors.append("DECISION_TRACE_DUPLICATE_STAGE")
        else:
            seen_names.add(step.stage_name)
            stage_indexes.append(DECISION_TRACE_STAGE_ORDER.index(step.stage_name))
        expected_predecessor = None if index == 0 else previous_stage_checksum
        if step.predecessor_checksum != expected_predecessor:
            errors.append("DECISION_TRACE_PREDECESSOR_BROKEN")
        if previous_output_checksum is not None and step.input_checksum != previous_output_checksum:
            errors.append("DECISION_TRACE_INPUT_CHAIN_BROKEN")
        if _stage_checksum_mismatch(step):
            errors.append("DECISION_TRACE_STAGE_CHECKSUM_MISMATCH")
        previous_stage_checksum = step.stage_checksum
        previous_output_checksum = step.output_checksum
    if stage_indexes != sorted(stage_indexes):
        errors.append("DECISION_TRACE_STAGE_ORDER_INVALID")
    return tuple(dict.fromkeys(errors))


def execution_context_identity_checksum(context: ExecutionContext) -> str:
    """Return a deterministic identity checksum for an execution context."""
    return _sha256(
        {
            "request_id": context.request_id,
            "submitted_at": _iso_utc(context.submitted_at),
            "policy_version": context.policy_version,
            "run_id": context.run_id,
        }
    )


def raw_intent_identity_checksum(intent: RawIntent) -> str:
    """Return a deterministic identity checksum for a raw intent."""
    return _sha256(
        {
            "command": intent.command,
            "parameters": _canonical_mapping(intent.parameters),
            "source_id": intent.source_id,
            "priority": intent.priority,
            "context_checksum": execution_context_identity_checksum(intent.context),
        }
    )


def validation_result_identity_checksum(validation_result: ValidationResult) -> str:
    """Return a deterministic identity checksum for a validation result."""
    return _sha256(
        {
            "is_valid": validation_result.is_valid,
            "intent_checksum": raw_intent_identity_checksum(validation_result.intent),
            "violations": [
                _canonical_violation(violation) for violation in validation_result.violations
            ],
        }
    )


def command_plan_identity_checksum(plan: CommandPlan) -> str:
    """Return a deterministic identity checksum for a command plan."""
    return _sha256(
        {
            "plan_id": plan.plan_id,
            "intent_checksum": raw_intent_identity_checksum(plan.intent),
            "steps": [_canonical_step(step) for step in plan.steps],
        }
    )


def gate_decision_identity_checksum(gate_decision: GateDecision) -> str:
    """Return a deterministic identity checksum for a gate decision."""
    return _sha256(
        {
            "status": gate_decision.status.value,
            "audit_id": gate_decision.audit_id,
            "plan_id": gate_decision.plan_id,
            "reasons": [reason.value for reason in gate_decision.reasons],
            "checksum_verified": gate_decision.checksum_verified,
            "audit_id_verified": gate_decision.audit_id_verified,
        }
    )


def policy_admission_record_identity_checksum(policy_admission: PolicyAdmissionRecord) -> str:
    """Return a deterministic identity checksum for a policy admission record."""
    return _sha256(
        {
            "mode": policy_admission.mode.value,
            "enforced": policy_admission.enforced,
            "admission_allowed": policy_admission.admission_allowed,
            "reasons": list(policy_admission.reasons),
            "audit_id": policy_admission.audit_id,
            "plan_id": policy_admission.plan_id,
            "plan_checksum": policy_admission.plan_checksum,
            "policy_id": policy_admission.policy_id,
            "policy_result_checksum": policy_admission.policy_result_checksum,
            "safety_case_id": policy_admission.safety_case_id,
            "world_snapshot_id": policy_admission.world_snapshot_id,
            "world_snapshot_checksum": policy_admission.world_snapshot_checksum,
            "capability_name": policy_admission.capability_name,
            "capability_version": policy_admission.capability_version,
            "admission_decision": policy_admission.admission_decision.value,
            "integrity_status": policy_admission.integrity_status.value,
            "exception_reason": policy_admission.exception_reason,
            "world_snapshot_observed_at_ms": policy_admission.world_snapshot_observed_at_ms,
            "freshness_result_checksum": policy_admission.freshness_result_checksum,
            "freshness_status": policy_admission.freshness_status,
            "world_snapshot_admissibility_status": (
                policy_admission.world_snapshot_admissibility_status
            ),
            "world_snapshot_admissibility_reason_code": (
                policy_admission.world_snapshot_admissibility_reason_code
            ),
            "world_snapshot_admissibility_result_checksum": (
                policy_admission.world_snapshot_admissibility_result_checksum
            ),
            "world_snapshot_trust_status": policy_admission.world_snapshot_trust_status,
            "world_snapshot_trust_reason_code": policy_admission.world_snapshot_trust_reason_code,
            "world_snapshot_trust_result_checksum": (
                policy_admission.world_snapshot_trust_result_checksum
            ),
            "evidence_envelope_checksum": policy_admission.evidence_envelope_checksum,
            "attestation_checksum": policy_admission.attestation_checksum,
            "trust_policy_checksum": policy_admission.trust_policy_checksum,
            "verifier_certification_status": policy_admission.verifier_certification_status,
            "verifier_certification_reason_code": (
                policy_admission.verifier_certification_reason_code
            ),
            "verifier_certification_checksum": policy_admission.verifier_certification_checksum,
            "verifier_id": policy_admission.verifier_id,
            "verifier_metadata_checksum": policy_admission.verifier_metadata_checksum,
            "trust_policy_config_status": policy_admission.trust_policy_config_status,
            "trust_policy_config_reason_code": policy_admission.trust_policy_config_reason_code,
            "trust_policy_config_validation_checksum": (
                policy_admission.trust_policy_config_validation_checksum
            ),
            "source_id": policy_admission.source_id,
            "source_type": policy_admission.source_type,
            "trust_domain": policy_admission.trust_domain,
        }
    )


def policy_result_identity_checksum(policy_result: PolicyEvaluationResult | None) -> str | None:
    """Return the policy result checksum when a policy result exists."""
    if policy_result is None:
        return None
    return policy_evaluation_result_checksum(policy_result)


def safety_case_identity_checksum(safety_case: SafetyCase | None) -> str | None:
    """Return the deterministic SafetyCase identity when available."""
    if safety_case is None:
        return None
    return safety_case.safety_case_id


def audited_plan_checksum(audited_plan: AuditedPlan | None) -> str | None:
    """Return the audited plan executable checksum when available."""
    if audited_plan is None:
        return None
    return audited_plan.checksum


def synthetic_stage_output_checksum(
    *,
    stage_name: str,
    stage_status: str,
    stage_reason: str | None,
    input_checksum: str,
) -> str:
    """Return a deterministic output identity for a failed or skipped stage."""
    return _sha256(
        {
            "stage_name": stage_name,
            "stage_status": stage_status,
            "stage_reason": stage_reason,
            "input_checksum": input_checksum,
        }
    )


def _stage_checksum_mismatch(step: DecisionTraceStep) -> bool:
    computed_checksum = decision_trace_step_checksum(
        stage_name=step.stage_name,
        stage_status=step.stage_status,
        stage_reason=step.stage_reason,
        input_checksum=step.input_checksum,
        output_checksum=step.output_checksum,
        predecessor_checksum=step.predecessor_checksum,
        metadata=step.metadata,
    )
    return step.stage_checksum != computed_checksum


def _canonical_violation(violation: Violation) -> dict[str, CanonicalTraceValue]:
    return {
        "code": violation.code,
        "field": violation.field,
        "reason": violation.reason,
        "layer": violation.layer,
    }


def _canonical_step(step: CommandStep) -> dict[str, CanonicalTraceValue]:
    return {
        "step_type": step.step_type.value,
        "parameters": _canonical_mapping(step.parameters),
        "sequence": step.sequence,
    }


def _canonical_mapping(values: Mapping[str, FrozenJsonValue]) -> dict[str, CanonicalTraceValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: FrozenJsonValue) -> CanonicalTraceValue:
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
            raise ValueError("trace values must be finite")
        return value
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, FrozenJsonValue], value)
        return _canonical_mapping(mapping)
    tuple_value = cast(tuple[FrozenJsonValue, ...], value)
    return [_canonical_value(item) for item in tuple_value]


def _sha256(payload: Mapping[str, CanonicalTraceValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_stage_name(value: str) -> str:
    normalized = _normalize_required_text(value, "stage_name")
    if normalized not in _ALLOWED_STAGE_NAMES:
        raise ValueError("stage_name must be a canonical decision trace stage")
    return normalized


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


def _iso_utc(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")


__all__ = [
    "ALLOW_REQUIRED_STAGE_CHAIN",
    "DECISION_TRACE_STAGE_ORDER",
    "DecisionTrace",
    "DecisionTraceStep",
    "audited_plan_checksum",
    "command_plan_identity_checksum",
    "decision_trace_checksum",
    "decision_trace_integrity_errors",
    "decision_trace_integrity_errors_for_steps",
    "decision_trace_step_checksum",
    "execution_context_identity_checksum",
    "gate_decision_identity_checksum",
    "policy_admission_record_identity_checksum",
    "policy_result_identity_checksum",
    "raw_intent_identity_checksum",
    "safety_case_identity_checksum",
    "synthetic_stage_output_checksum",
    "validation_result_identity_checksum",
]
