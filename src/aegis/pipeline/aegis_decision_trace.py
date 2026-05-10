"""Build deterministic decision traces for pipeline results."""

from __future__ import annotations

from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_decision_trace import (
    DecisionTrace,
    DecisionTraceStep,
    command_plan_identity_checksum,
    execution_context_identity_checksum,
    gate_decision_identity_checksum,
    policy_admission_record_identity_checksum,
    raw_intent_identity_checksum,
    safety_case_identity_checksum,
    synthetic_stage_output_checksum,
    validation_result_identity_checksum,
)
from aegis.contracts.aegis_gate import GateDecision
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import JsonValue, is_json_value
from aegis.contracts.aegis_planning import CommandPlan
from aegis.contracts.aegis_policy_admission import PolicyAdmissionMode, PolicyAdmissionRecord
from aegis.contracts.aegis_validation import ValidationResult


def build_decision_trace(
    *,
    raw_intent: RawIntent,
    context: ExecutionContext,
    validation_result: ValidationResult | None,
    plan: CommandPlan | None,
    audited_plan: AuditedPlan | None,
    gate_decision: GateDecision | None,
    policy_admission: PolicyAdmissionRecord,
) -> DecisionTrace:
    """Build a deterministic trace for the pipeline artifacts produced so far."""
    builder = _DecisionTraceBuilder()
    context_checksum = execution_context_identity_checksum(context)
    raw_checksum = raw_intent_identity_checksum(raw_intent)
    builder.append(
        stage_name="raw_intent",
        stage_status="ACCEPTED",
        stage_reason="RAW_INTENT_ACCEPTED",
        input_checksum=context_checksum,
        output_checksum=raw_checksum,
        metadata={
            "command": raw_intent.command,
            "source_id": raw_intent.source_id,
            "priority": raw_intent.priority,
            "request_id": context.request_id,
        },
    )

    if validation_result is None:
        validation_output = synthetic_stage_output_checksum(
            stage_name="validation",
            stage_status="ERROR",
            stage_reason="VALIDATION_FAILED",
            input_checksum=raw_checksum,
        )
        builder.append(
            stage_name="validation",
            stage_status="ERROR",
            stage_reason="VALIDATION_FAILED",
            input_checksum=raw_checksum,
            output_checksum=validation_output,
            metadata={"is_valid": False},
        )
        return builder.build()

    validation_checksum = validation_result_identity_checksum(validation_result)
    builder.append(
        stage_name="validation",
        stage_status="VALID" if validation_result.is_valid else "INVALID",
        stage_reason="VALIDATION_PASSED" if validation_result.is_valid else "VALIDATION_FAILED",
        input_checksum=raw_checksum,
        output_checksum=validation_checksum,
        metadata={
            "is_valid": validation_result.is_valid,
            "violation_count": len(validation_result.violations),
        },
    )
    if not validation_result.is_valid:
        return builder.build()

    if plan is None:
        builder.append_synthetic(
            stage_name="planning",
            stage_status="ERROR",
            stage_reason="PLANNING_FAILED",
        )
        return builder.build()

    plan_checksum = command_plan_identity_checksum(plan)
    builder.append(
        stage_name="planning",
        stage_status="PLANNED",
        stage_reason="PLAN_BUILT",
        input_checksum=validation_checksum,
        output_checksum=plan_checksum,
        metadata={"plan_id": plan.plan_id, "step_count": len(plan.steps)},
    )
    if audited_plan is None:
        builder.append_synthetic(
            stage_name="audit",
            stage_status="ERROR",
            stage_reason="AUDIT_FAILED",
        )
        return builder.build()

    builder.append(
        stage_name="audit",
        stage_status="AUDITED",
        stage_reason="AUDIT_BUILT",
        input_checksum=plan_checksum,
        output_checksum=audited_plan.checksum,
        metadata={"audit_id": audited_plan.audit_id, "plan_id": audited_plan.plan.plan_id},
    )

    _append_policy_stages(builder, policy_admission)
    if gate_decision is not None:
        builder.append(
            stage_name="gate_decision",
            stage_status=gate_decision.status.value,
            stage_reason=_gate_reason(gate_decision),
            input_checksum=builder.previous_output_checksum,
            output_checksum=gate_decision_identity_checksum(gate_decision),
            metadata={
                "audit_id": gate_decision.audit_id,
                "plan_id": gate_decision.plan_id,
                "checksum_verified": gate_decision.checksum_verified,
                "audit_id_verified": gate_decision.audit_id_verified,
                "reasons": [reason.value for reason in gate_decision.reasons],
            },
        )
    return builder.build()


class _DecisionTraceBuilder:
    def __init__(self) -> None:
        self._steps: list[DecisionTraceStep] = []

    @property
    def previous_output_checksum(self) -> str:
        if not self._steps:
            raise ValueError("trace builder has no previous step")
        return self._steps[-1].output_checksum

    def append(
        self,
        *,
        stage_name: str,
        stage_status: str,
        stage_reason: str | None,
        input_checksum: str,
        output_checksum: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        predecessor_checksum = self._steps[-1].stage_checksum if self._steps else None
        self._steps.append(
            DecisionTraceStep(
                stage_name=stage_name,
                stage_status=stage_status,
                stage_reason=stage_reason,
                input_checksum=input_checksum,
                output_checksum=output_checksum,
                predecessor_checksum=predecessor_checksum,
                metadata=_json_metadata(metadata or {}),
            )
        )

    def append_synthetic(
        self,
        *,
        stage_name: str,
        stage_status: str,
        stage_reason: str,
    ) -> None:
        input_checksum = self.previous_output_checksum
        self.append(
            stage_name=stage_name,
            stage_status=stage_status,
            stage_reason=stage_reason,
            input_checksum=input_checksum,
            output_checksum=synthetic_stage_output_checksum(
                stage_name=stage_name,
                stage_status=stage_status,
                stage_reason=stage_reason,
                input_checksum=input_checksum,
            ),
        )

    def build(self) -> DecisionTrace:
        return DecisionTrace(self._steps)


def _append_policy_stages(
    builder: _DecisionTraceBuilder,
    policy_admission: PolicyAdmissionRecord,
) -> None:
    if policy_admission.mode is PolicyAdmissionMode.DISABLED:
        _append_policy_admission_stage(builder, policy_admission)
        return
    _append_optional_stage(
        builder,
        stage_name="world_snapshot_admissibility",
        stage_status=policy_admission.world_snapshot_admissibility_status,
        stage_reason=policy_admission.world_snapshot_admissibility_reason_code,
        output_checksum=policy_admission.world_snapshot_admissibility_result_checksum,
        metadata={"world_snapshot_checksum": policy_admission.world_snapshot_checksum},
    )
    _append_optional_stage(
        builder,
        stage_name="world_snapshot_freshness",
        stage_status=policy_admission.freshness_status,
        stage_reason=_first_reason(policy_admission),
        output_checksum=policy_admission.freshness_result_checksum,
        metadata={"observed_at_ms": policy_admission.world_snapshot_observed_at_ms},
    )
    _append_optional_stage(
        builder,
        stage_name="verifier_certification",
        stage_status=policy_admission.verifier_certification_status,
        stage_reason=policy_admission.verifier_certification_reason_code,
        output_checksum=policy_admission.verifier_certification_checksum,
        metadata={
            "verifier_id": policy_admission.verifier_id,
            "verifier_metadata_checksum": policy_admission.verifier_metadata_checksum,
        },
    )
    _append_optional_stage(
        builder,
        stage_name="trust_policy_config",
        stage_status=policy_admission.trust_policy_config_status,
        stage_reason=policy_admission.trust_policy_config_reason_code,
        output_checksum=policy_admission.trust_policy_config_validation_checksum,
        metadata={"trust_policy_checksum": policy_admission.trust_policy_checksum},
    )
    _append_optional_stage(
        builder,
        stage_name="world_snapshot_trust",
        stage_status=policy_admission.world_snapshot_trust_status,
        stage_reason=policy_admission.world_snapshot_trust_reason_code,
        output_checksum=policy_admission.world_snapshot_trust_result_checksum,
        metadata={
            "source_id": policy_admission.source_id,
            "source_type": policy_admission.source_type,
            "trust_domain": policy_admission.trust_domain,
        },
    )
    if policy_admission.policy_result_checksum is not None:
        builder.append(
            stage_name="policy_evaluation",
            stage_status=(
                policy_admission.policy_result.decision.value
                if policy_admission.policy_result is not None
                else "ERROR"
            ),
            stage_reason=_first_reason(policy_admission),
            input_checksum=builder.previous_output_checksum,
            output_checksum=policy_admission.policy_result_checksum,
            metadata={"policy_id": policy_admission.policy_id},
        )
    if policy_admission.safety_case_id is not None:
        builder.append(
            stage_name="safety_case",
            stage_status="BUILT",
            stage_reason="SAFETY_CASE_BUILT",
            input_checksum=builder.previous_output_checksum,
            output_checksum=safety_case_identity_checksum(policy_admission.safety_case)
            or policy_admission.safety_case_id,
            metadata={
                "safety_case_id": policy_admission.safety_case_id,
                "audit_id": policy_admission.audit_id,
            },
        )
    _append_policy_admission_stage(builder, policy_admission)


def _append_optional_stage(
    builder: _DecisionTraceBuilder,
    *,
    stage_name: str,
    stage_status: str | None,
    stage_reason: str | None,
    output_checksum: str | None,
    metadata: dict[str, object],
) -> None:
    if output_checksum is None:
        return
    builder.append(
        stage_name=stage_name,
        stage_status=stage_status or "UNKNOWN",
        stage_reason=stage_reason,
        input_checksum=builder.previous_output_checksum,
        output_checksum=output_checksum,
        metadata=metadata,
    )


def _append_policy_admission_stage(
    builder: _DecisionTraceBuilder,
    policy_admission: PolicyAdmissionRecord,
) -> None:
    builder.append(
        stage_name="policy_admission",
        stage_status=policy_admission.admission_decision.value,
        stage_reason=_first_reason(policy_admission),
        input_checksum=builder.previous_output_checksum,
        output_checksum=policy_admission_record_identity_checksum(policy_admission),
        metadata={
            "mode": policy_admission.mode.value,
            "admission_allowed": policy_admission.admission_allowed,
            "integrity_status": policy_admission.integrity_status.value,
            "reasons": list(policy_admission.reasons),
        },
    )


def _first_reason(policy_admission: PolicyAdmissionRecord) -> str | None:
    return policy_admission.reasons[0] if policy_admission.reasons else None


def _gate_reason(gate_decision: GateDecision) -> str:
    if gate_decision.status.value == "allowed":
        return "GATE_ALLOWED"
    return gate_decision.reasons[0].value if gate_decision.reasons else "GATE_BLOCKED"


def _json_metadata(values: dict[str, object]) -> dict[str, JsonValue]:
    metadata: dict[str, JsonValue] = {}
    for key, value in values.items():
        if value is None:
            continue
        if not is_json_value(value):
            raise ValueError("decision trace metadata must be JSON-compatible")
        metadata[key] = value
    return metadata


__all__ = ["build_decision_trace"]
