"""Governance coverage tests for ADR-0028 approval-ledger persistence boundary."""

from __future__ import annotations

from dataclasses import fields

from aegis.execution.aegis_approval_ledger_persistence import (
    ApprovalLedgerPersistenceLoadResult,
    ApprovalLedgerPersistenceReceipt,
    ApprovalLedgerPersistenceRecord,
    ApprovalLedgerPersistenceValidationResult,
    ApprovalLedgerRecoveryResult,
)
from aegis.execution.aegis_approval_ledger_persistence_fields import (
    APPROVAL_LEDGER_PERSISTENCE_LOAD_RESULT_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_PERSISTENCE_RECEIPT_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_PERSISTENCE_RECORD_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_PERSISTENCE_SCENARIO_CATEGORY_NAMES,
    APPROVAL_LEDGER_PERSISTENCE_VALIDATION_RESULT_CHECKSUM_FIELDS,
    APPROVAL_LEDGER_RECOVERY_RESULT_CHECKSUM_FIELDS,
    STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES,
)
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_approval_ledger_persistence_categories_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)
    assert set(APPROVAL_LEDGER_PERSISTENCE_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(APPROVAL_LEDGER_PERSISTENCE_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_approval_ledger_persistence_checksum_field_sentinels_match_contracts() -> None:
    record_fields = tuple(
        field.name for field in fields(ApprovalLedgerPersistenceRecord) if field.name != "checksum"
    )
    receipt_fields = tuple(
        field.name for field in fields(ApprovalLedgerPersistenceReceipt) if field.name != "checksum"
    )
    load_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerPersistenceLoadResult)
        if field.name != "checksum"
    )
    validation_fields = tuple(
        field.name
        for field in fields(ApprovalLedgerPersistenceValidationResult)
        if field.name != "checksum"
    )
    recovery_fields = tuple(
        field.name for field in fields(ApprovalLedgerRecoveryResult) if field.name != "checksum"
    )
    assert record_fields == APPROVAL_LEDGER_PERSISTENCE_RECORD_CHECKSUM_FIELDS
    assert receipt_fields == APPROVAL_LEDGER_PERSISTENCE_RECEIPT_CHECKSUM_FIELDS
    assert load_fields == APPROVAL_LEDGER_PERSISTENCE_LOAD_RESULT_CHECKSUM_FIELDS
    assert validation_fields == APPROVAL_LEDGER_PERSISTENCE_VALIDATION_RESULT_CHECKSUM_FIELDS
    assert recovery_fields == APPROVAL_LEDGER_RECOVERY_RESULT_CHECKSUM_FIELDS


def test_approval_ledger_persistence_profile_keeps_core_boundaries() -> None:
    assert (
        "deterministic_serialization_boundary" in STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES
    )
    assert (
        "failed_write_does_not_mutate_repository_authority"
        in STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES
    )
    assert "no_database_clients" in STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES


def test_approval_ledger_persistence_manifests_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}
    assert "ApprovalLedgerPersistenceRecord" in names
    assert "ApprovalLedgerPersistenceReceipt" in names
    assert "ApprovalLedgerPersistenceLoadResult" in names
    assert "ApprovalLedgerPersistenceValidationResult" in names
    assert "ApprovalLedgerRecoveryResult" in names
    assert "ApprovalLedgerPersistenceAdapterDescriptor" in names
