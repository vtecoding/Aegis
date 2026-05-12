"""Governance coverage tests for ADR-0027 approval-ledger repository boundary."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_ledger_repository import (
    ApprovalLedgerRepositoryAuthorityEvidence,
    RepositoryCommitResult,
)
from aegis.execution.aegis_approval_ledger_repository_fields import (
    APPROVAL_LEDGER_REPOSITORY_AUTHORITY_EVIDENCE_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_REPOSITORY_SCENARIO_CATEGORY_NAMES,
    REPOSITORY_COMMIT_RESULT_CHECKSUM_FIELDS,
    STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES,
)
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_approval_ledger_repository_categories_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)
    assert set(APPROVAL_LEDGER_REPOSITORY_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(APPROVAL_LEDGER_REPOSITORY_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_approval_ledger_repository_checksum_field_sentinels_match_contracts() -> None:
    authority_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerRepositoryAuthorityEvidence)
        if field.name != "authority_evidence_checksum"
    )
    commit_fields = tuple(
        field.name
        for field in fields(RepositoryCommitResult)
        if field.name != "commit_result_checksum"
    )
    assert authority_fields == (
        "prior_entries",
        "ledger_head",
        "ledger_epoch_manifest",
        "state_source_id",
    )
    assert APPROVAL_LEDGER_REPOSITORY_AUTHORITY_EVIDENCE_CHECKSUM_FIELDS == (
        "ledger_head_checksum",
        "ledger_epoch_manifest_checksum",
        "state_source_id",
        "prior_entries_checksum",
    )
    assert commit_fields == REPOSITORY_COMMIT_RESULT_CHECKSUM_FIELDS


def test_approval_ledger_repository_profile_keeps_core_boundaries() -> None:
    assert (
        "commit_requires_compare_and_swap_proof" in STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES
    )
    assert "no_database_clients" in STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES
    assert "no_filesystem_persistence" in STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES


def test_approval_ledger_repository_manifests_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}
    assert "ApprovalLedgerRepositoryAuthorityEvidence" in names
    assert "RepositoryCommitResult" in names
