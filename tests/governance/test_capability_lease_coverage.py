"""Governance coverage tests for ADR-0021 runtime capability leases."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease
from aegis.execution.aegis_lease_fields import (
    CAPABILITY_LEASE_CHECKSUM_FIELDS,
    CAPABILITY_LEASE_SCENARIO_CATEGORY_NAMES,
    LEASE_REVOCATION_CHECKSUM_FIELDS,
    LEASE_VALIDATION_CHECKSUM_FIELDS,
    STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES,
)
from aegis.execution.aegis_lease_revocation import LeaseRevocationDecision
from aegis.execution.aegis_lease_validation import LeaseValidationResult
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_capability_lease_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(CAPABILITY_LEASE_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(CAPABILITY_LEASE_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_capability_lease_checksum_field_sentinels_match_contracts() -> None:
    lease_fields = tuple(
        field.name for field in fields(RuntimeCapabilityLease) if field.name != "lease_checksum"
    )
    validation_fields = tuple(
        field.name for field in fields(LeaseValidationResult) if field.name != "validation_checksum"
    )
    revocation_fields = tuple(
        field.name
        for field in fields(LeaseRevocationDecision)
        if field.name != "revocation_checksum"
    )

    assert lease_fields == CAPABILITY_LEASE_CHECKSUM_FIELDS
    assert validation_fields == LEASE_VALIDATION_CHECKSUM_FIELDS
    assert revocation_fields == LEASE_REVOCATION_CHECKSUM_FIELDS


def test_capability_lease_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "admitted_null_backend_required" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "checksum_bound_admission_decision" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "checksum_bound_context_authority" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "explicit_epoch_required" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_wall_clock_fallback" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "scope_subset_bound" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_wildcard_capabilities" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_wildcard_runtime_kinds" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_runtime_objects" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_network_calls" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES


def test_capability_lease_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "RuntimeCapabilityLease" in names
    assert "LeaseValidationResult" in names
    assert "LeaseRevocationDecision" in names


def test_capability_lease_forbidden_runtime_import_scan_is_clean() -> None:
    forbidden_import_roots = {"rclpy", "rclcpp", "ros", "moveit", "gazebo", "isaac", "viam"}
    src_root = Path(__file__).parents[2] / "src" / "aegis"
    violations: list[str] = []
    for source_file in src_root.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", maxsplit=1)[0]
                    if root in forbidden_import_roots or any(
                        root.startswith(f"{forbidden}_") for forbidden in forbidden_import_roots
                    ):
                        violations.append(f"{source_file}:{alias.name}")
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                root = node.module.split(".", maxsplit=1)[0]
                if root in forbidden_import_roots or any(
                    root.startswith(f"{forbidden}_") for forbidden in forbidden_import_roots
                ):
                    violations.append(f"{source_file}:{node.module}")

    assert violations == []
