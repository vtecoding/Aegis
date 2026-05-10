"""Governance coverage tests for ADR-0023 operator authority."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_replay import (
    ApprovalReplayValidationResult,
    AuthorityBoundApprovalReceipt,
)
from aegis.execution.aegis_operator_authority import OperatorAuthorityManifest
from aegis.execution.aegis_operator_authority_fields import (
    APPROVAL_REPLAY_VALIDATION_CHECKSUM_FIELDS,
    AUTHORITY_BOUND_APPROVAL_CHECKSUM_FIELDS,
    OPERATOR_APPROVAL_NONCE_CHECKSUM_FIELDS,
    OPERATOR_AUTHORITY_MANIFEST_CHECKSUM_FIELDS,
    OPERATOR_AUTHORITY_SCENARIO_CATEGORY_NAMES,
    OPERATOR_IDENTITY_CLAIM_CHECKSUM_FIELDS,
    STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES,
)
from aegis.execution.aegis_operator_identity import OperatorApprovalNonce, OperatorIdentityClaim
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_operator_authority_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(OPERATOR_AUTHORITY_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(OPERATOR_AUTHORITY_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_operator_authority_checksum_field_sentinels_match_contracts() -> None:
    manifest_fields = tuple(
        field.name
        for field in fields(OperatorAuthorityManifest)
        if field.name != "manifest_checksum"
    )
    identity_fields = tuple(
        field.name for field in fields(OperatorIdentityClaim) if field.name != "identity_checksum"
    )
    nonce_fields = tuple(
        field.name for field in fields(OperatorApprovalNonce) if field.name != "nonce_checksum"
    )
    approval_fields = tuple(
        field.name
        for field in fields(AuthorityBoundApprovalReceipt)
        if field.name != "authority_bound_checksum"
    )
    replay_fields = tuple(
        field.name
        for field in fields(ApprovalReplayValidationResult)
        if field.name != "replay_validation_checksum"
    )

    assert manifest_fields == OPERATOR_AUTHORITY_MANIFEST_CHECKSUM_FIELDS
    assert identity_fields == OPERATOR_IDENTITY_CLAIM_CHECKSUM_FIELDS
    assert nonce_fields == OPERATOR_APPROVAL_NONCE_CHECKSUM_FIELDS
    assert approval_fields == AUTHORITY_BOUND_APPROVAL_CHECKSUM_FIELDS
    assert replay_fields == APPROVAL_REPLAY_VALIDATION_CHECKSUM_FIELDS


def test_operator_authority_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "registered_operator_role_required" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "authority_manifest_required" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "identity_bound_to_manifest" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "approval_nonce_bound_to_quarantine" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "approval_bound_to_dispatch_plan" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "approval_bound_to_capability_lease" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "approval_bound_to_backend_admission" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "approval_bound_to_context_authority" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "no_auth_provider_claim" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "no_signatures_or_pki" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "no_network_calls" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES


def test_operator_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "OperatorAuthorityManifest" in names
    assert "OperatorIdentityClaim" in names
    assert "OperatorApprovalNonce" in names
    assert "AuthorityBoundApprovalReceipt" in names
    assert "ApprovalReplayValidationResult" in names
