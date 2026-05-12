"""Governance coverage tests for ADR-0025 approval ledger head."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerAppendResult,
    ApprovalLedgerHead,
    LedgerEpochManifest,
)
from aegis.execution.aegis_approval_ledger_head_fields import (
    APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_HEAD_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_HEAD_SCENARIO_CATEGORY_NAMES,
    LEDGER_EPOCH_MANIFEST_CHECKSUM_FIELDS,
    STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES,
)
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_approval_ledger_head_categories_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(APPROVAL_LEDGER_HEAD_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(APPROVAL_LEDGER_HEAD_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_approval_ledger_head_checksum_field_sentinels_match_contract() -> None:
    head_fields = tuple(
        field.name for field in fields(ApprovalLedgerHead) if field.name != "head_checksum"
    )
    assert head_fields == APPROVAL_LEDGER_HEAD_CHECKSUM_FIELDS


def test_ledger_epoch_manifest_checksum_field_sentinels_match_contract() -> None:
    manifest_fields = tuple(
        field.name for field in fields(LedgerEpochManifest) if field.name != "manifest_checksum"
    )
    assert manifest_fields == LEDGER_EPOCH_MANIFEST_CHECKSUM_FIELDS


def test_approval_ledger_head_profile_keeps_core_boundaries() -> None:
    assert "head_checksum_recomputable" in STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES
    assert "no_signatures_or_pki" in STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES
    assert "no_filesystem_persistence" in STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES
    assert "direct_head_construction_blocked" in STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES


def test_approval_ledger_head_manifests_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}
    assert "ApprovalLedgerHead" in names
    assert "LedgerEpochManifest" in names
    assert "ApprovalLedgerAppendResult" in names


def test_append_result_checksum_fields_are_logical_coverage() -> None:
    assert "new_entry_checksum" in APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS
    assert "new_head_checksum" in APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS
    assert "chain_validation_checksum" in APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS
    _ = ApprovalLedgerAppendResult
