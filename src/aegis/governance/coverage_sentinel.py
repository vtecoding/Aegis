"""Coverage sentinels for closed stage, category, and checksum registries."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.approval_receipt import ApprovalReceipt
from aegis.contracts.decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.governance.authority_fields import AUTHORITY_FIELD_MANIFESTS
from aegis.governance.policy_identity import POLICY_CHECKSUM_FIELDS, POLICY_IDENTITY_FIELDS
from aegis.scenarios.contracts import REQUIRED_SCENARIO_CATEGORIES, ScenarioCategory

REQUIRED_STAGE_COVERAGE = DECISION_TRACE_STAGE_ORDER
"""Decision trace stages that must be scenario-covered for ALLOWED results."""

REQUIRED_CATEGORY_COVERAGE = tuple(ScenarioCategory)
"""Scenario categories that must remain covered by the canonical matrix."""

POLICY_ADMISSION_CHECKSUM_FIELDS = (
    "mode",
    "policy_result",
    "safety_case",
    "enforced",
    "admission_allowed",
    "reasons",
    "audit_id",
    "plan_id",
    "plan_checksum",
    "policy_id",
    "policy_version",
    "policy_schema_version",
    "policy_checksum",
    "policy_authority",
    "policy_result_checksum",
    "safety_case_id",
    "context_authority_checksum",
    "context_id",
    "caller_authority",
    "deployment_domain",
    "context_schema_version",
    "context_evaluation_time_ms",
    "world_snapshot_id",
    "world_snapshot_checksum",
    "capability_name",
    "capability_version",
    "admission_decision",
    "integrity_status",
    "exception_reason",
    "world_snapshot_observed_at_ms",
    "freshness_result_checksum",
    "freshness_status",
    "world_snapshot_admissibility_status",
    "world_snapshot_admissibility_reason_code",
    "world_snapshot_admissibility_result_checksum",
    "world_snapshot_trust_status",
    "world_snapshot_trust_reason_code",
    "world_snapshot_trust_result_checksum",
    "evidence_envelope_checksum",
    "attestation_checksum",
    "trust_policy_checksum",
    "verifier_certification_status",
    "verifier_certification_reason_code",
    "verifier_certification_checksum",
    "verifier_id",
    "verifier_metadata_checksum",
    "trust_policy_config_status",
    "trust_policy_config_reason_code",
    "trust_policy_config_validation_checksum",
    "source_id",
    "source_type",
    "trust_domain",
)
"""Fields consumed by policy_admission_record_identity_checksum."""

RECEIPT_BOUND_FIELDS = tuple(field for field in ApprovalReceipt.__dataclass_fields__)
"""Fields stored by ApprovalReceipt and therefore bound by its checksum."""


@dataclass(frozen=True, slots=True)
class CoverageSentinelResult:
    """Machine-checkable coverage sentinel result."""

    passed: bool
    errors: tuple[str, ...]


def evaluate_coverage_sentinel(
    *,
    stage_registry: tuple[str, ...] = DECISION_TRACE_STAGE_ORDER,
    expected_stage_coverage: tuple[str, ...] = REQUIRED_STAGE_COVERAGE,
    category_registry: tuple[ScenarioCategory, ...] = tuple(ScenarioCategory),
    required_categories: tuple[ScenarioCategory, ...] = REQUIRED_SCENARIO_CATEGORIES,
) -> CoverageSentinelResult:
    """Compare closed registries against their release coverage matrices."""
    errors: list[str] = []
    if stage_registry != expected_stage_coverage:
        errors.append("DECISION_TRACE_STAGE_COVERAGE_DRIFT")
    if category_registry != required_categories:
        errors.append("SCENARIO_CATEGORY_COVERAGE_DRIFT")
    manifest_names = {manifest.contract_name for manifest in AUTHORITY_FIELD_MANIFESTS}
    if len(manifest_names) != len(AUTHORITY_FIELD_MANIFESTS):
        errors.append("AUTHORITY_FIELD_MANIFEST_DUPLICATE")
    if (
        set(POLICY_IDENTITY_FIELDS)
        .difference(POLICY_CHECKSUM_FIELDS)
        .difference({"policy_checksum"})
    ):
        errors.append("POLICY_IDENTITY_FIELDS_MISSING_FROM_POLICY_CHECKSUM")
    admission_manifest = next(
        manifest
        for manifest in AUTHORITY_FIELD_MANIFESTS
        if manifest.contract_name == "PolicyAdmissionRecord"
    )
    missing_admission_fields = set(admission_manifest.authoritative_fields).difference(
        POLICY_ADMISSION_CHECKSUM_FIELDS
    )
    if missing_admission_fields:
        errors.append(
            "POLICY_ADMISSION_CHECKSUM_FIELD_DRIFT:" + ",".join(sorted(missing_admission_fields))
        )
    receipt_manifest = next(
        manifest
        for manifest in AUTHORITY_FIELD_MANIFESTS
        if manifest.contract_name == "ApprovalReceipt"
    )
    missing_receipt_fields = set(receipt_manifest.authoritative_fields).difference(
        RECEIPT_BOUND_FIELDS
    )
    if missing_receipt_fields:
        errors.append("RECEIPT_BOUND_FIELD_DRIFT:" + ",".join(sorted(missing_receipt_fields)))
    return CoverageSentinelResult(passed=not errors, errors=tuple(errors))


def assert_coverage_sentinel() -> None:
    """Raise ValueError when any closed registry expands without coverage."""
    result = evaluate_coverage_sentinel()
    if not result.passed:
        raise ValueError("; ".join(result.errors))


__all__ = [
    "CoverageSentinelResult",
    "POLICY_ADMISSION_CHECKSUM_FIELDS",
    "POLICY_CHECKSUM_FIELDS",
    "RECEIPT_BOUND_FIELDS",
    "REQUIRED_CATEGORY_COVERAGE",
    "REQUIRED_STAGE_COVERAGE",
    "assert_coverage_sentinel",
    "evaluate_coverage_sentinel",
]
