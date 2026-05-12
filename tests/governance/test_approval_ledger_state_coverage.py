"""Governance coverage tests for ADR-0026 approval ledger state."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_ledger_state import (
    ApprovalLedgerStateSnapshot,
    ApprovalLedgerStateTransition,
    LedgerStateValidationResult,
)
from aegis.execution.aegis_approval_ledger_state_fields import (
    APPROVAL_LEDGER_STATE_SCENARIO_CATEGORY_NAMES,
    APPROVAL_LEDGER_STATE_SNAPSHOT_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_STATE_TRANSITION_CHECKSUM_FIELDS,
    LEDGER_STATE_VALIDATION_RESULT_CHECKSUM_FIELDS,
    STRICT_APPROVAL_LEDGER_STATE_SNAPSHOT_V1_PROPERTIES,
    STRICT_APPROVAL_LEDGER_STATE_TRANSITION_V1_PROPERTIES,
    STRICT_LEDGER_STATE_VALIDATION_RESULT_V1_PROPERTIES,
)
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_approval_ledger_state_categories_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)
    assert set(APPROVAL_LEDGER_STATE_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(APPROVAL_LEDGER_STATE_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_approval_ledger_state_checksum_field_sentinels_match_contracts() -> None:
    snapshot_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerStateSnapshot)
        if field.name != "state_snapshot_checksum"
    )
    transition_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerStateTransition)
        if field.name != "state_transition_checksum"
    )
    validation_fields = tuple(
        field.name
        for field in fields(LedgerStateValidationResult)
        if field.name != "validation_checksum"
    )
    assert snapshot_fields == APPROVAL_LEDGER_STATE_SNAPSHOT_CHECKSUM_FIELDS
    assert transition_fields == APPROVAL_LEDGER_STATE_TRANSITION_CHECKSUM_FIELDS
    assert validation_fields == LEDGER_STATE_VALIDATION_RESULT_CHECKSUM_FIELDS


def test_approval_ledger_state_profile_keeps_core_boundaries() -> None:
    assert "canonical_current_state_boundary" in STRICT_APPROVAL_LEDGER_STATE_SNAPSHOT_V1_PROPERTIES
    assert "sequence_increment_exactly_one" in STRICT_APPROVAL_LEDGER_STATE_TRANSITION_V1_PROPERTIES
    assert "valid_result_token_gated" in STRICT_LEDGER_STATE_VALIDATION_RESULT_V1_PROPERTIES
    assert "no_signatures_or_pki" in STRICT_APPROVAL_LEDGER_STATE_SNAPSHOT_V1_PROPERTIES
    assert "no_filesystem_persistence" in STRICT_APPROVAL_LEDGER_STATE_TRANSITION_V1_PROPERTIES


def test_approval_ledger_state_manifests_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}
    assert "ApprovalLedgerStateSnapshot" in names
    assert "ApprovalLedgerStateTransition" in names
    assert "LedgerStateValidationResult" in names
