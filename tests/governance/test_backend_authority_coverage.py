"""Governance coverage tests for ADR-0020 backend authority admission."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.execution.backend_admission import BackendAdmissionDecision, BackendAdmissionRequest
from aegis.execution.backend_authority import BackendAuthorityManifest
from aegis.execution.backend_authority_fields import (
    BACKEND_ADMISSION_DECISION_CHECKSUM_FIELDS,
    BACKEND_ADMISSION_REQUEST_FIELDS,
    BACKEND_AUTHORITY_MANIFEST_CHECKSUM_FIELDS,
    BACKEND_AUTHORITY_REGISTRY_CHECKSUM_FIELDS,
    BACKEND_AUTHORITY_SCENARIO_CATEGORY_NAMES,
    STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES,
)
from aegis.execution.backend_registry import BackendAuthorityRegistry
from aegis.governance.adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions


def test_backend_authority_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(BACKEND_AUTHORITY_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(BACKEND_AUTHORITY_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_backend_authority_checksum_field_sentinels_match_contracts() -> None:
    manifest_fields = tuple(
        field.name
        for field in fields(BackendAuthorityManifest)
        if field.name != "manifest_checksum"
    )
    registry_fields = tuple(
        field.name
        for field in fields(BackendAuthorityRegistry)
        if field.name != "registry_checksum"
    )
    request_fields = tuple(field.name for field in fields(BackendAdmissionRequest))
    decision_fields = tuple(
        field.name
        for field in fields(BackendAdmissionDecision)
        if field.name != "decision_checksum"
    )

    assert manifest_fields == BACKEND_AUTHORITY_MANIFEST_CHECKSUM_FIELDS
    assert registry_fields == BACKEND_AUTHORITY_REGISTRY_CHECKSUM_FIELDS
    assert request_fields == BACKEND_ADMISSION_REQUEST_FIELDS
    assert decision_fields == BACKEND_ADMISSION_DECISION_CHECKSUM_FIELDS


def test_backend_authority_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "closed_backend_kind_registry" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "null_backend_only" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "adr_0018_certification_required" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "adr_0019_replay_required" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "checksum_bound_manifest" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "checksum_bound_registry" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_execution_capability" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_io_capability" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_async_capability" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_wildcard_capabilities" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_wildcard_runtime_kinds" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_runtime_objects" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_network_calls" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES


def test_backend_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "BackendAuthorityManifest" in names
    assert "BackendAuthorityRegistry" in names
    assert "BackendAdmissionRequest" in names
    assert "BackendAdmissionDecision" in names


def test_backend_authority_forbidden_runtime_import_scan_is_clean() -> None:
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
