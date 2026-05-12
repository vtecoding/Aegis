"""Governance coverage tests for ADR-0024 approval ledger."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerChainValidationResult,
    ApprovalLedgerEntry,
)
from aegis.execution.aegis_approval_ledger_fields import (
    APPROVAL_LEDGER_CHAIN_VALIDATION_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_ENTRY_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_SCENARIO_CATEGORY_NAMES,
    STRICT_APPROVAL_LEDGER_V1_PROPERTIES,
)
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_approval_ledger_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(APPROVAL_LEDGER_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(APPROVAL_LEDGER_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_approval_ledger_checksum_field_sentinels_match_contracts() -> None:
    entry_fields = tuple(
        field.name for field in fields(ApprovalLedgerEntry) if field.name != "entry_checksum"
    )
    validation_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerChainValidationResult)
        if field.name != "ledger_validation_checksum"
    )

    assert entry_fields == APPROVAL_LEDGER_ENTRY_CHECKSUM_FIELDS
    assert validation_fields == APPROVAL_LEDGER_CHAIN_VALIDATION_CHECKSUM_FIELDS


def test_approval_ledger_profile_keeps_core_boundaries() -> None:
    assert "hash_linked_sequence" in STRICT_APPROVAL_LEDGER_V1_PROPERTIES
    assert "no_signatures_or_pki" in STRICT_APPROVAL_LEDGER_V1_PROPERTIES
    assert "no_filesystem_persistence" in STRICT_APPROVAL_LEDGER_V1_PROPERTIES


def test_approval_ledger_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "ApprovalLedgerEntry" in names
    assert "ApprovalLedgerChainValidationResult" in names
