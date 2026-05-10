"""Governance coverage tests for ADR-0018 null backend certification."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.contracts.runtime_backend import (
    BackendCertificationResult,
    BackendDryRunReceipt,
    RuntimeBackendDescriptor,
)
from aegis.execution.backend_fields import (
    BACKEND_CERTIFICATION_CHECKSUM_FIELDS,
    BACKEND_CERTIFICATION_SCENARIO_CATEGORY_NAMES,
    BACKEND_DRY_RUN_RECEIPT_CHECKSUM_FIELDS,
    RUNTIME_BACKEND_DESCRIPTOR_CHECKSUM_FIELDS,
    STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES,
)
from aegis.governance.adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions


def test_backend_certification_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(BACKEND_CERTIFICATION_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(BACKEND_CERTIFICATION_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_backend_certification_checksum_field_sentinels_match_contracts() -> None:
    descriptor_fields = tuple(
        field.name
        for field in fields(RuntimeBackendDescriptor)
        if field.name != "descriptor_checksum"
    )
    certification_fields = tuple(
        field.name
        for field in fields(BackendCertificationResult)
        if field.name != "certification_checksum"
    )
    receipt_fields = tuple(
        field.name for field in fields(BackendDryRunReceipt) if field.name != "receipt_checksum"
    )

    assert descriptor_fields == RUNTIME_BACKEND_DESCRIPTOR_CHECKSUM_FIELDS
    assert certification_fields == BACKEND_CERTIFICATION_CHECKSUM_FIELDS
    assert receipt_fields == BACKEND_DRY_RUN_RECEIPT_CHECKSUM_FIELDS


def test_backend_certification_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "firewall_allowed_plan_required" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "dry_run_only" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "null_backend_only" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "descriptor_only_interface" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_execution_capability" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_io_capability" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_async_capability" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_callable_handles" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_runtime_objects" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_network_calls" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES
    assert "zero_executed_receipts" in STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES


def test_backend_certification_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "RuntimeBackendDescriptor" in names
    assert "BackendCertificationResult" in names
    assert "BackendDryRunReceipt" in names


def test_only_null_runtime_backend_is_implemented() -> None:
    execution_root = Path(__file__).parents[2] / "src" / "aegis" / "execution"
    backend_classes: set[str] = set()
    for source_file in execution_root.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("RuntimeBackend"):
                backend_classes.add(node.name)

    assert backend_classes == {"NullRuntimeBackend"}
