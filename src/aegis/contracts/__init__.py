"""Shared typed contracts between Aegis pipeline layers."""

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import (
    FrozenJsonValue,
    JsonScalar,
    JsonValue,
    freeze_json_mapping,
    freeze_json_value,
    is_json_value,
)
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.contracts.planning import CommandPlan, CommandStep, CommandStepType
from aegis.contracts.policy import (
    Capability,
    Constraint,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyDefaultDecision,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyScalar,
    SafetyCase,
    WorldSnapshotStub,
    policy_evaluation_result_checksum,
)
from aegis.contracts.policy_admission import (
    PolicyAdmissionDecision,
    PolicyAdmissionInput,
    PolicyAdmissionIntegrity,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    disabled_policy_admission_record,
    is_policy_backed_approval,
)
from aegis.contracts.validation import ValidationResult, Violation

__all__ = [
    "AuditedPlan",
    "Capability",
    "CommandPlan",
    "CommandStep",
    "CommandStepType",
    "Constraint",
    "ExecutionContext",
    "FrozenJsonValue",
    "FrozenPolicyValue",
    "GateBlockReason",
    "GateDecision",
    "GateDecisionStatus",
    "JsonScalar",
    "JsonValue",
    "Policy",
    "PolicyAdmissionDecision",
    "PolicyAdmissionInput",
    "PolicyAdmissionIntegrity",
    "PolicyAdmissionIntegrityStatus",
    "PolicyAdmissionMode",
    "PolicyAdmissionRecord",
    "PolicyDecision",
    "PolicyDefaultDecision",
    "PolicyEvaluationResult",
    "PolicyRule",
    "PolicyScalar",
    "PipelineOutcome",
    "PipelineResult",
    "RawIntent",
    "SafetyCase",
    "ValidationResult",
    "Violation",
    "WorldSnapshotStub",
    "assert_policy_admission_integrity",
    "disabled_policy_admission_record",
    "freeze_json_mapping",
    "freeze_json_value",
    "is_json_value",
    "is_policy_backed_approval",
    "policy_evaluation_result_checksum",
]
