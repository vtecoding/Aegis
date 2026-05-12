"""Scenario runner contracts for deterministic pipeline evidence validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from aegis.contracts.aegis_decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import FrozenJsonValue, JsonValue, freeze_json_mapping
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Policy, WorldSnapshotStub
from aegis.contracts.aegis_world_snapshot_freshness import FreshnessPolicy
from aegis.contracts.aegis_world_snapshot_trust import (
    AttestationVerifier,
    TrustDomain,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotTrustPolicy,
)
from aegis.governance.aegis_context_authority import ContextAuthority

type DecisionTraceStageName = str
type TrustPolicyConfig = WorldSnapshotTrustPolicy
type ScenarioChecksumValue = (
    str | int | float | bool | None | list[ScenarioChecksumValue] | dict[str, ScenarioChecksumValue]
)

_SCENARIO_ONLY_STAGES = frozenset({"receipt_validation", "direct_gate"})
_ALLOWED_EXPECTATION_STAGES = frozenset(DECISION_TRACE_STAGE_ORDER).union(_SCENARIO_ONLY_STAGES)


class ScenarioCategory(StrEnum):
    """Required ADR-0013 and ADR-0015 scenario categories."""

    POSITIVE_ALLOWED = "POSITIVE_ALLOWED"
    MISSING_WORLD_SNAPSHOT = "MISSING_WORLD_SNAPSHOT"
    INADMISSIBLE_WORLD_SNAPSHOT = "INADMISSIBLE_WORLD_SNAPSHOT"
    STALE_WORLD_SNAPSHOT = "STALE_WORLD_SNAPSHOT"
    FUTURE_DATED_WORLD_SNAPSHOT = "FUTURE_DATED_WORLD_SNAPSHOT"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    INVALID_ATTESTATION = "INVALID_ATTESTATION"
    UNCERTIFIED_VERIFIER = "UNCERTIFIED_VERIFIER"
    INVALID_TRUST_CONFIG = "INVALID_TRUST_CONFIG"
    WRONG_CAPABILITY_SCOPE = "WRONG_CAPABILITY_SCOPE"
    POLICY_DENIED = "POLICY_DENIED"
    SAFETY_CASE_FORGED = "SAFETY_CASE_FORGED"
    ADMISSION_MISMATCH = "ADMISSION_MISMATCH"
    RECEIPT_FORGED = "RECEIPT_FORGED"
    DIRECT_GATE_BYPASS = "DIRECT_GATE_BYPASS"
    REPLAYED_RECEIPT = "REPLAYED_RECEIPT"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    CONFUSABLE_STAGE_NAME = "CONFUSABLE_STAGE_NAME"
    PARTIAL_RECEIPT_OVERCLAIM = "PARTIAL_RECEIPT_OVERCLAIM"
    ADAPTER_VALID_ROS2_MOVE_MAPPING = "ADAPTER_VALID_ROS2_MOVE_MAPPING"
    ADAPTER_VALID_ROS2_STOP_MAPPING = "ADAPTER_VALID_ROS2_STOP_MAPPING"
    ADAPTER_BLOCKED_PIPELINE_RESULT = "ADAPTER_BLOCKED_PIPELINE_RESULT"
    ADAPTER_INVALID_RECEIPT = "ADAPTER_INVALID_RECEIPT"
    ADAPTER_CAPABILITY_MISMATCH = "ADAPTER_CAPABILITY_MISMATCH"
    ADAPTER_COMMAND_MISMATCH = "ADAPTER_COMMAND_MISMATCH"
    ADAPTER_NAMESPACE_MISMATCH = "ADAPTER_NAMESPACE_MISMATCH"
    ADAPTER_QOS_INVALID = "ADAPTER_QOS_INVALID"
    ADAPTER_REQUIRED_FIELD_MISSING = "ADAPTER_REQUIRED_FIELD_MISSING"
    ADAPTER_FORBIDDEN_FIELD = "ADAPTER_FORBIDDEN_FIELD"
    ADAPTER_CHECKSUM_FORGED = "ADAPTER_CHECKSUM_FORGED"
    ADAPTER_DIRECT_BYPASS = "ADAPTER_DIRECT_BYPASS"
    ADAPTER_CONFUSABLE_RUNTIME_NAME = "ADAPTER_CONFUSABLE_RUNTIME_NAME"
    ADAPTER_PAYLOAD_RESOURCE_EXCEEDED = "ADAPTER_PAYLOAD_RESOURCE_EXCEEDED"
    ADAPTER_REPLAY_POSITIVE = "ADAPTER_REPLAY_POSITIVE"
    ADAPTER_REPLAY_RECEIPT_DRIFT = "ADAPTER_REPLAY_RECEIPT_DRIFT"
    ADAPTER_REPLAY_MAPPING_DRIFT = "ADAPTER_REPLAY_MAPPING_DRIFT"
    ADAPTER_REPLAY_RUNTIME_TARGET_DRIFT = "ADAPTER_REPLAY_RUNTIME_TARGET_DRIFT"
    ADAPTER_REPLAY_CROSS_PIPELINE_SWAP = "ADAPTER_REPLAY_CROSS_PIPELINE_SWAP"
    ADAPTER_REPLAY_AUTHORITY_MISMATCH = "ADAPTER_REPLAY_AUTHORITY_MISMATCH"
    ADAPTER_REPLAY_QOS_NAMESPACE_MUTATION = "ADAPTER_REPLAY_QOS_NAMESPACE_MUTATION"
    ADAPTER_REPLAY_RESOURCE_BOUNDS = "ADAPTER_REPLAY_RESOURCE_BOUNDS"
    RUNTIME_DISPATCH_DRY_RUN_POSITIVE = "RUNTIME_DISPATCH_DRY_RUN_POSITIVE"
    RUNTIME_DISPATCH_REPLAY_PROOF_REQUIRED = "RUNTIME_DISPATCH_REPLAY_PROOF_REQUIRED"
    RUNTIME_DISPATCH_CROSS_ENVELOPE_SWAP = "RUNTIME_DISPATCH_CROSS_ENVELOPE_SWAP"
    RUNTIME_DISPATCH_MAPPING_DRIFT = "RUNTIME_DISPATCH_MAPPING_DRIFT"
    RUNTIME_DISPATCH_PAYLOAD_BOUNDS = "RUNTIME_DISPATCH_PAYLOAD_BOUNDS"
    RUNTIME_DISPATCH_SEQUENCE_INTEGRITY = "RUNTIME_DISPATCH_SEQUENCE_INTEGRITY"
    RUNTIME_DISPATCH_MODE_FIREWALL = "RUNTIME_DISPATCH_MODE_FIREWALL"
    RUNTIME_DISPATCH_RUNTIME_OBJECT_INJECTION = "RUNTIME_DISPATCH_RUNTIME_OBJECT_INJECTION"
    BACKEND_NULL_POSITIVE = "BACKEND_NULL_POSITIVE"
    BACKEND_REQUIRES_FIREWALL_ALLOWED_PLAN = "BACKEND_REQUIRES_FIREWALL_ALLOWED_PLAN"
    BACKEND_REJECTS_NON_NULL_KIND = "BACKEND_REJECTS_NON_NULL_KIND"
    BACKEND_REJECTS_EXECUTION_CAPABILITY = "BACKEND_REJECTS_EXECUTION_CAPABILITY"
    BACKEND_REJECTS_IO_CAPABILITY = "BACKEND_REJECTS_IO_CAPABILITY"
    BACKEND_REJECTS_ASYNC_CAPABILITY = "BACKEND_REJECTS_ASYNC_CAPABILITY"
    BACKEND_REJECTS_RUNTIME_OBJECT_INJECTION = "BACKEND_REJECTS_RUNTIME_OBJECT_INJECTION"
    BACKEND_REJECTS_SCOPE_DRIFT = "BACKEND_REJECTS_SCOPE_DRIFT"
    BACKEND_RECEIPT_ZERO_EXECUTION = "BACKEND_RECEIPT_ZERO_EXECUTION"
    BACKEND_CERTIFICATION_CHECKSUM_DRIFT = "BACKEND_CERTIFICATION_CHECKSUM_DRIFT"
    BACKEND_REPLAY_POSITIVE = "BACKEND_REPLAY_POSITIVE"
    BACKEND_REPLAY_REQUIRES_CERTIFIED_NULL = "BACKEND_REPLAY_REQUIRES_CERTIFIED_NULL"
    BACKEND_REPLAY_DISPATCH_DRIFT = "BACKEND_REPLAY_DISPATCH_DRIFT"
    BACKEND_REPLAY_FIREWALL_DRIFT = "BACKEND_REPLAY_FIREWALL_DRIFT"
    BACKEND_REPLAY_DESCRIPTOR_DRIFT = "BACKEND_REPLAY_DESCRIPTOR_DRIFT"
    BACKEND_REPLAY_SCOPE_DRIFT = "BACKEND_REPLAY_SCOPE_DRIFT"
    BACKEND_REPLAY_RECEIPT_EXECUTION_DRIFT = "BACKEND_REPLAY_RECEIPT_EXECUTION_DRIFT"
    BACKEND_REPLAY_CROSS_PLAN_SWAP = "BACKEND_REPLAY_CROSS_PLAN_SWAP"
    BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION = "BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION"
    BACKEND_REPLAY_CHECKSUM_DRIFT = "BACKEND_REPLAY_CHECKSUM_DRIFT"
    BACKEND_ADMISSION_NULL_POSITIVE = "BACKEND_ADMISSION_NULL_POSITIVE"
    BACKEND_ADMISSION_UNKNOWN_KIND = "BACKEND_ADMISSION_UNKNOWN_KIND"
    BACKEND_ADMISSION_NON_NULL_KIND = "BACKEND_ADMISSION_NON_NULL_KIND"
    BACKEND_ADMISSION_MANIFEST_DRIFT = "BACKEND_ADMISSION_MANIFEST_DRIFT"
    BACKEND_ADMISSION_REGISTRY_DRIFT = "BACKEND_ADMISSION_REGISTRY_DRIFT"
    BACKEND_ADMISSION_MISSING_CERTIFICATION = "BACKEND_ADMISSION_MISSING_CERTIFICATION"
    BACKEND_ADMISSION_MISSING_REPLAY = "BACKEND_ADMISSION_MISSING_REPLAY"
    BACKEND_ADMISSION_SCOPE_OVERCLAIM = "BACKEND_ADMISSION_SCOPE_OVERCLAIM"
    BACKEND_ADMISSION_WILDCARD_AUTHORITY = "BACKEND_ADMISSION_WILDCARD_AUTHORITY"
    BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION = "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION"
    CAPABILITY_LEASE_NULL_POSITIVE = "CAPABILITY_LEASE_NULL_POSITIVE"
    CAPABILITY_LEASE_REQUIRES_ADMISSION = "CAPABILITY_LEASE_REQUIRES_ADMISSION"
    CAPABILITY_LEASE_SCOPE_SUBSET = "CAPABILITY_LEASE_SCOPE_SUBSET"
    CAPABILITY_LEASE_REGISTRY_DRIFT = "CAPABILITY_LEASE_REGISTRY_DRIFT"
    CAPABILITY_LEASE_MANIFEST_DRIFT = "CAPABILITY_LEASE_MANIFEST_DRIFT"
    CAPABILITY_LEASE_CERTIFICATION_DRIFT = "CAPABILITY_LEASE_CERTIFICATION_DRIFT"
    CAPABILITY_LEASE_REPLAY_DRIFT = "CAPABILITY_LEASE_REPLAY_DRIFT"
    CAPABILITY_LEASE_CONTEXT_AUTHORITY_DRIFT = "CAPABILITY_LEASE_CONTEXT_AUTHORITY_DRIFT"
    CAPABILITY_LEASE_WILDCARD_SCOPE = "CAPABILITY_LEASE_WILDCARD_SCOPE"
    CAPABILITY_LEASE_REVOCATION = "CAPABILITY_LEASE_REVOCATION"
    COMMAND_QUARANTINE_POSITIVE = "COMMAND_QUARANTINE_POSITIVE"
    COMMAND_QUARANTINE_REQUIRES_VALID_LEASE = "COMMAND_QUARANTINE_REQUIRES_VALID_LEASE"
    COMMAND_QUARANTINE_MISSING_APPROVAL = "COMMAND_QUARANTINE_MISSING_APPROVAL"
    COMMAND_QUARANTINE_REJECTED_APPROVAL = "COMMAND_QUARANTINE_REJECTED_APPROVAL"
    COMMAND_QUARANTINE_SCOPE_OVERCLAIM = "COMMAND_QUARANTINE_SCOPE_OVERCLAIM"
    COMMAND_QUARANTINE_EVIDENCE_DRIFT = "COMMAND_QUARANTINE_EVIDENCE_DRIFT"
    COMMAND_QUARANTINE_STALE_APPROVAL = "COMMAND_QUARANTINE_STALE_APPROVAL"
    COMMAND_QUARANTINE_PARTIAL_OMISSION = "COMMAND_QUARANTINE_PARTIAL_OMISSION"
    COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION = "COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION"
    COMMAND_QUARANTINE_RELEASE_DRY_RUN_ONLY = "COMMAND_QUARANTINE_RELEASE_DRY_RUN_ONLY"
    OPERATOR_AUTHORITY_POSITIVE = "OPERATOR_AUTHORITY_POSITIVE"
    OPERATOR_AUTHORITY_UNKNOWN_ROLE = "OPERATOR_AUTHORITY_UNKNOWN_ROLE"
    OPERATOR_AUTHORITY_SCOPE_OVERCLAIM = "OPERATOR_AUTHORITY_SCOPE_OVERCLAIM"
    OPERATOR_AUTHORITY_MANIFEST_DRIFT = "OPERATOR_AUTHORITY_MANIFEST_DRIFT"
    OPERATOR_AUTHORITY_CONTEXT_DRIFT = "OPERATOR_AUTHORITY_CONTEXT_DRIFT"
    OPERATOR_AUTHORITY_NONCE_REPLAY = "OPERATOR_AUTHORITY_NONCE_REPLAY"
    OPERATOR_AUTHORITY_CROSS_QUARANTINE_REPLAY = "OPERATOR_AUTHORITY_CROSS_QUARANTINE_REPLAY"
    OPERATOR_AUTHORITY_CROSS_OPERATOR_REPLAY = "OPERATOR_AUTHORITY_CROSS_OPERATOR_REPLAY"
    OPERATOR_AUTHORITY_EPOCH_REPLAY = "OPERATOR_AUTHORITY_EPOCH_REPLAY"
    OPERATOR_AUTHORITY_OBJECT_INJECTION = "OPERATOR_AUTHORITY_OBJECT_INJECTION"
    APPROVAL_LEDGER_POSITIVE = "APPROVAL_LEDGER_POSITIVE"
    APPROVAL_LEDGER_CHAIN_TAMPER = "APPROVAL_LEDGER_CHAIN_TAMPER"
    APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION = "APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION"
    APPROVAL_LEDGER_HEAD_POSITIVE = "APPROVAL_LEDGER_HEAD_POSITIVE"
    APPROVAL_LEDGER_HEAD_STALE_EPOCH = "APPROVAL_LEDGER_HEAD_STALE_EPOCH"
    APPROVAL_LEDGER_HEAD_CONTEXT_DRIFT = "APPROVAL_LEDGER_HEAD_CONTEXT_DRIFT"
    APPROVAL_LEDGER_HEAD_TIP_MISMATCH = "APPROVAL_LEDGER_HEAD_TIP_MISMATCH"
    APPROVAL_LEDGER_HEAD_ENFORCED_MODE_BYPASS = "APPROVAL_LEDGER_HEAD_ENFORCED_MODE_BYPASS"
    APPROVAL_LEDGER_STATE_VALID = "APPROVAL_LEDGER_STATE_VALID"
    APPROVAL_LEDGER_STATE_STALE_HEAD = "APPROVAL_LEDGER_STATE_STALE_HEAD"
    APPROVAL_LEDGER_STATE_FORKED_HEAD = "APPROVAL_LEDGER_STATE_FORKED_HEAD"
    APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK = "APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK"
    APPROVAL_LEDGER_STATE_SEQUENCE_SKIP = "APPROVAL_LEDGER_STATE_SEQUENCE_SKIP"
    APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT = "APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT"
    APPROVAL_LEDGER_STATE_SOURCE_DRIFT = "APPROVAL_LEDGER_STATE_SOURCE_DRIFT"
    APPROVAL_LEDGER_REPOSITORY_POSITIVE = "APPROVAL_LEDGER_REPOSITORY_POSITIVE"
    APPROVAL_LEDGER_REPOSITORY_STALE_READ = "APPROVAL_LEDGER_REPOSITORY_STALE_READ"
    APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE = "APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE"
    APPROVAL_LEDGER_REPOSITORY_FORK_ATTEMPT = "APPROVAL_LEDGER_REPOSITORY_FORK_ATTEMPT"
    APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ATTEMPT = "APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ATTEMPT"
    APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT = "APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT"
    APPROVAL_LEDGER_REPOSITORY_FORGED_TRANSITION = "APPROVAL_LEDGER_REPOSITORY_FORGED_TRANSITION"
    APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE = "APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE"
    APPROVAL_LEDGER_PERSISTENCE_POSITIVE = "APPROVAL_LEDGER_PERSISTENCE_POSITIVE"
    APPROVAL_LEDGER_PERSISTENCE_CORRUPT = "APPROVAL_LEDGER_PERSISTENCE_CORRUPT"
    APPROVAL_LEDGER_PERSISTENCE_ROLLBACK = "APPROVAL_LEDGER_PERSISTENCE_ROLLBACK"
    APPROVAL_LEDGER_PERSISTENCE_FORKED = "APPROVAL_LEDGER_PERSISTENCE_FORKED"
    APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY = (
        "APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY"
    )
    APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY = (
        "APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY"
    )
    APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE = "APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE"
    APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE = "APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE"


class EvilTwinMutation(StrEnum):
    """Closed set of deterministic evidence mutations used by evil-twin scenarios."""

    NONE = "NONE"
    SAFETY_CASE_FORGED = "SAFETY_CASE_FORGED"
    ADMISSION_MISMATCH = "ADMISSION_MISMATCH"
    RECEIPT_FIELD_FORGED = "RECEIPT_FIELD_FORGED"
    DIRECT_GATE_ONLY = "DIRECT_GATE_ONLY"
    REPLAYED_RECEIPT = "REPLAYED_RECEIPT"
    TRACE_CHECKSUM_MISMATCH = "TRACE_CHECKSUM_MISMATCH"
    CONFUSABLE_STAGE_NAME = "CONFUSABLE_STAGE_NAME"
    PARTIAL_RECEIPT_OVERCLAIM = "PARTIAL_RECEIPT_OVERCLAIM"


REQUIRED_SCENARIO_CATEGORIES: tuple[ScenarioCategory, ...] = tuple(ScenarioCategory)
"""Minimum ADR-0013/ADR-0015 category matrix required by the coverage gate."""


@dataclass(frozen=True, slots=True)
class ScenarioExpectation:
    """Expected pipeline result and receipt-proven decision path for a scenario."""

    expected_outcome: PipelineOutcome
    expected_reason: str
    expected_terminal_stage: DecisionTraceStageName
    required_stages: tuple[DecisionTraceStageName, ...]
    forbidden_stages: tuple[DecisionTraceStageName, ...]
    receipt_must_be_valid: bool
    approval_receipt_required: bool
    allow_late_stage_artifacts: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_outcome", _normalize_outcome(self.expected_outcome))
        object.__setattr__(
            self,
            "expected_reason",
            _normalize_required_text(self.expected_reason, "expected_reason"),
        )
        object.__setattr__(
            self,
            "expected_terminal_stage",
            _normalize_stage(self.expected_terminal_stage, "expected_terminal_stage"),
        )
        required = _normalize_stage_tuple(self.required_stages, "required_stages")
        forbidden = _normalize_stage_tuple(self.forbidden_stages, "forbidden_stages")
        overlap = frozenset(required).intersection(forbidden)
        if overlap:
            raise ValueError("required_stages and forbidden_stages must not overlap")
        object.__setattr__(self, "required_stages", required)
        object.__setattr__(self, "forbidden_stages", forbidden)
        if self.expected_outcome is PipelineOutcome.ALLOWED:
            if not self.receipt_must_be_valid:
                raise ValueError("ALLOWED scenarios require a valid receipt")
            if not self.approval_receipt_required:
                raise ValueError("ALLOWED scenarios require an approval receipt")
            if self.forbidden_stages:
                raise ValueError("ALLOWED scenarios must not forbid stages")
            if tuple(self.required_stages) != DECISION_TRACE_STAGE_ORDER:
                raise ValueError("ALLOWED scenarios require the full decision trace chain")
        _validate_bool(self.receipt_must_be_valid, "receipt_must_be_valid")
        _validate_bool(self.approval_receipt_required, "approval_receipt_required")
        _validate_bool(self.allow_late_stage_artifacts, "allow_late_stage_artifacts")


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    """Immutable description of one deterministic scenario."""

    scenario_id: str
    name: str
    category: ScenarioCategory
    intent: RawIntent
    policy: Policy | None
    world_snapshot: WorldSnapshotStub | None
    evaluation_time_ms: int | None
    trust_policy_config: TrustPolicyConfig | None
    verifier: AttestationVerifier | None
    expected: ScenarioExpectation
    metadata: Mapping[str, FrozenJsonValue]
    capability: Capability | None = None
    context_authority: ContextAuthority | None = None
    world_snapshot_evidence: WorldSnapshotEvidenceEnvelope | None = None
    freshness_policy: FreshnessPolicy | None = None
    runtime_trust_domain: TrustDomain = TrustDomain.SIMULATION
    evil_twin_mutation: EvilTwinMutation = EvilTwinMutation.NONE

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "scenario_id", _normalize_identifier(self.scenario_id, "scenario_id")
        )
        object.__setattr__(self, "name", _normalize_required_text(self.name, "name"))
        object.__setattr__(self, "category", _normalize_category(self.category))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))
        object.__setattr__(
            self, "runtime_trust_domain", _normalize_trust_domain(self.runtime_trust_domain)
        )
        object.__setattr__(
            self, "evil_twin_mutation", _normalize_evil_twin_mutation(self.evil_twin_mutation)
        )
        if self.evaluation_time_ms is not None:
            object.__setattr__(
                self,
                "evaluation_time_ms",
                _normalize_non_negative_int(self.evaluation_time_ms, "evaluation_time_ms"),
            )


@dataclass(frozen=True, slots=True)
class ScenarioViolation:
    """One deterministic scenario validation violation."""

    code: str
    message: str
    field: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_required_text(self.code, "code"))
        object.__setattr__(self, "message", _normalize_required_text(self.message, "message"))
        object.__setattr__(self, "field", _normalize_optional_text(self.field, "field"))


@dataclass(frozen=True, slots=True)
class ScenarioRunResult:
    """Result of executing and validating one scenario."""

    scenario_id: str
    passed: bool
    actual_outcome: PipelineOutcome
    actual_reason: str
    expected_outcome: PipelineOutcome
    expected_reason: str
    terminal_stage: str | None
    receipt_valid: bool
    trace_valid: bool
    stage_path: tuple[str, ...]
    violations: tuple[ScenarioViolation, ...]
    pipeline_result_checksum: str
    scenario_result_checksum: str
    category: ScenarioCategory | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "scenario_id", _normalize_identifier(self.scenario_id, "scenario_id")
        )
        _validate_bool(self.passed, "passed")
        object.__setattr__(self, "actual_outcome", _normalize_outcome(self.actual_outcome))
        object.__setattr__(self, "expected_outcome", _normalize_outcome(self.expected_outcome))
        object.__setattr__(
            self, "actual_reason", _normalize_required_text(self.actual_reason, "actual_reason")
        )
        object.__setattr__(
            self,
            "expected_reason",
            _normalize_required_text(self.expected_reason, "expected_reason"),
        )
        object.__setattr__(
            self, "terminal_stage", _normalize_optional_text(self.terminal_stage, "terminal_stage")
        )
        _validate_bool(self.receipt_valid, "receipt_valid")
        _validate_bool(self.trace_valid, "trace_valid")
        object.__setattr__(self, "stage_path", _normalize_observed_stage_path(self.stage_path))
        object.__setattr__(self, "violations", tuple(self.violations))
        object.__setattr__(
            self,
            "pipeline_result_checksum",
            _normalize_checksum(self.pipeline_result_checksum, "pipeline_result_checksum"),
        )
        object.__setattr__(
            self,
            "scenario_result_checksum",
            _normalize_checksum(self.scenario_result_checksum, "scenario_result_checksum"),
        )


@dataclass(frozen=True, slots=True)
class CoverageGateResult:
    """Machine-checkable proof of required scenario category coverage."""

    passed: bool
    required_categories: tuple[ScenarioCategory, ...]
    covered_categories: tuple[ScenarioCategory, ...]
    missing_categories: tuple[ScenarioCategory, ...]
    category_counts: Mapping[ScenarioCategory, int]
    coverage_checksum: str

    def __post_init__(self) -> None:
        _validate_bool(self.passed, "passed")
        object.__setattr__(
            self,
            "required_categories",
            _normalize_category_tuple(self.required_categories, "required_categories"),
        )
        object.__setattr__(
            self,
            "covered_categories",
            _normalize_category_tuple(self.covered_categories, "covered_categories"),
        )
        object.__setattr__(
            self,
            "missing_categories",
            _normalize_category_tuple(self.missing_categories, "missing_categories"),
        )
        object.__setattr__(self, "category_counts", _freeze_category_counts(self.category_counts))
        object.__setattr__(
            self,
            "coverage_checksum",
            _normalize_checksum(self.coverage_checksum, "coverage_checksum"),
        )


@dataclass(frozen=True, slots=True)
class ScenarioSuiteResult:
    """Aggregate result for a deterministic scenario suite run."""

    suite_id: str
    passed: bool
    total: int
    passed_count: int
    failed_count: int
    results: tuple[ScenarioRunResult, ...]
    coverage: CoverageGateResult
    suite_checksum: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "suite_id", _normalize_identifier(self.suite_id, "suite_id"))
        _validate_bool(self.passed, "passed")
        _validate_non_negative_counter(self.total, "total")
        _validate_non_negative_counter(self.passed_count, "passed_count")
        _validate_non_negative_counter(self.failed_count, "failed_count")
        if self.total != len(self.results):
            raise ValueError("total must equal len(results)")
        if self.passed_count + self.failed_count != self.total:
            raise ValueError("passed_count + failed_count must equal total")
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(
            self, "suite_checksum", _normalize_checksum(self.suite_checksum, "suite_checksum")
        )


def scenario_run_result_checksum(
    *,
    scenario_id: str,
    passed: bool,
    actual_outcome: PipelineOutcome,
    actual_reason: str,
    expected_outcome: PipelineOutcome,
    expected_reason: str,
    terminal_stage: str | None,
    receipt_valid: bool,
    trace_valid: bool,
    stage_path: Iterable[str],
    violations: Iterable[ScenarioViolation],
    pipeline_result_checksum: str,
) -> str:
    """Return the deterministic checksum for a ScenarioRunResult."""
    return _sha256(
        {
            "scenario_id": scenario_id,
            "passed": passed,
            "actual_outcome": actual_outcome.value,
            "actual_reason": actual_reason,
            "expected_outcome": expected_outcome.value,
            "expected_reason": expected_reason,
            "terminal_stage": terminal_stage,
            "receipt_valid": receipt_valid,
            "trace_valid": trace_valid,
            "stage_path": list(stage_path),
            "violations": [
                {"code": violation.code, "message": violation.message, "field": violation.field}
                for violation in violations
            ],
            "pipeline_result_checksum": pipeline_result_checksum,
        }
    )


def coverage_gate_checksum(
    *,
    passed: bool,
    required_categories: Iterable[ScenarioCategory],
    covered_categories: Iterable[ScenarioCategory],
    missing_categories: Iterable[ScenarioCategory],
    category_counts: Mapping[ScenarioCategory, int],
) -> str:
    """Return the deterministic checksum for a CoverageGateResult."""
    return _sha256(
        {
            "passed": passed,
            "required_categories": [category.value for category in required_categories],
            "covered_categories": [category.value for category in covered_categories],
            "missing_categories": [category.value for category in missing_categories],
            "category_counts": {
                category.value: count
                for category, count in sorted(
                    category_counts.items(), key=lambda item: item[0].value
                )
            },
        }
    )


def scenario_suite_checksum(
    *,
    suite_id: str,
    passed: bool,
    results: Iterable[ScenarioRunResult],
    coverage: CoverageGateResult,
) -> str:
    """Return the deterministic checksum for a ScenarioSuiteResult."""
    return _sha256(
        {
            "suite_id": suite_id,
            "passed": passed,
            "results": [result.scenario_result_checksum for result in results],
            "coverage_checksum": coverage.coverage_checksum,
        }
    )


def _normalize_identifier(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must be ASCII") from exc
    if not all(char.isalnum() or char in "._:-" for char in normalized):
        raise ValueError(
            f"{field_name} must contain only ASCII letters, digits, '.', '_', ':', '-'"
        )
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_checksum(value: object, field_name: str) -> str:
    checksum = _normalize_required_text(value, field_name)
    if len(checksum) != 64 or not all(char in "0123456789abcdef" for char in checksum):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return checksum


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _validate_non_negative_counter(value: object, field_name: str) -> None:
    _normalize_non_negative_int(value, field_name)


def _normalize_outcome(value: object) -> PipelineOutcome:
    if isinstance(value, PipelineOutcome):
        return value
    if isinstance(value, str):
        try:
            return PipelineOutcome(value)
        except ValueError as exc:
            raise ValueError("expected_outcome must be a PipelineOutcome") from exc
    raise ValueError("expected_outcome must be a PipelineOutcome")


def _normalize_category(value: object) -> ScenarioCategory:
    if isinstance(value, ScenarioCategory):
        return value
    if isinstance(value, str):
        try:
            return ScenarioCategory(value)
        except ValueError as exc:
            raise ValueError("category must be a known ScenarioCategory") from exc
    raise ValueError("category must be a ScenarioCategory")


def _normalize_evil_twin_mutation(value: object) -> EvilTwinMutation:
    if isinstance(value, EvilTwinMutation):
        return value
    if isinstance(value, str):
        try:
            return EvilTwinMutation(value)
        except ValueError as exc:
            raise ValueError("evil_twin_mutation must be known") from exc
    raise ValueError("evil_twin_mutation must be an EvilTwinMutation")


def _normalize_trust_domain(value: object) -> TrustDomain:
    if isinstance(value, TrustDomain):
        return value
    if isinstance(value, str):
        try:
            return TrustDomain(value)
        except ValueError as exc:
            raise ValueError("runtime_trust_domain must be a TrustDomain") from exc
    raise ValueError("runtime_trust_domain must be a TrustDomain")


def _normalize_stage(value: object, field_name: str) -> DecisionTraceStageName:
    stage = _normalize_required_text(value, field_name)
    if stage not in _ALLOWED_EXPECTATION_STAGES:
        raise ValueError(f"{field_name} contains an unknown stage")
    return stage


def _normalize_stage_tuple(
    values: Iterable[object], field_name: str
) -> tuple[DecisionTraceStageName, ...]:
    normalized = tuple(_normalize_stage(value, field_name) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicate stages")
    return normalized


def _normalize_observed_stage_path(values: Iterable[object]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("stage_path values must be strings")
        if value == "":
            raise ValueError("stage_path values must be non-empty")
        normalized.append(value)
    return tuple(normalized)


def _validate_bool(value: object, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool")


def _normalize_category_tuple(
    values: Iterable[object], field_name: str
) -> tuple[ScenarioCategory, ...]:
    normalized = tuple(_normalize_category(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicate categories")
    return normalized


def _freeze_metadata(values: Mapping[str, FrozenJsonValue]) -> Mapping[str, FrozenJsonValue]:
    metadata = cast(Mapping[str, JsonValue], values)
    return freeze_json_mapping(metadata)


def _freeze_category_counts(
    values: Mapping[ScenarioCategory, int],
) -> Mapping[ScenarioCategory, int]:
    frozen: dict[ScenarioCategory, int] = {}
    for category, count in values.items():
        normalized_category = _normalize_category(category)
        normalized_count = _normalize_non_negative_int(count, "category_counts")
        frozen[normalized_category] = normalized_count
    return MappingProxyType(
        {category: frozen[category] for category in sorted(frozen, key=lambda item: item.value)}
    )


def _sha256(payload: Mapping[str, ScenarioChecksumValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "CoverageGateResult",
    "DecisionTraceStageName",
    "EvilTwinMutation",
    "REQUIRED_SCENARIO_CATEGORIES",
    "ScenarioCategory",
    "ScenarioDefinition",
    "ScenarioExpectation",
    "ScenarioRunResult",
    "ScenarioSuiteResult",
    "ScenarioViolation",
    "TrustPolicyConfig",
    "coverage_gate_checksum",
    "scenario_run_result_checksum",
    "scenario_suite_checksum",
]
