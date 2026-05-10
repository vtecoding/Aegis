"""Governance coverage tests for ADR-0022 command quarantine."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.execution.aegis_command_quarantine import CommandQuarantineEnvelope
from aegis.execution.aegis_operator_approval import OperatorApprovalReceipt
from aegis.execution.aegis_quarantine_fields import (
    COMMAND_QUARANTINE_CHECKSUM_FIELDS,
    COMMAND_QUARANTINE_SCENARIO_CATEGORY_NAMES,
    OPERATOR_APPROVAL_CHECKSUM_FIELDS,
    QUARANTINE_RELEASE_CHECKSUM_FIELDS,
    STRICT_COMMAND_QUARANTINE_V1_PROPERTIES,
)
from aegis.execution.aegis_quarantine_release import QuarantineReleaseDecision
from aegis.governance.aegis_adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.aegis_contracts import ScenarioCategory
from aegis.scenarios.aegis_coverage import evaluate_scenario_coverage
from aegis.scenarios.aegis_fixtures import canonical_scenario_definitions


def test_command_quarantine_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(COMMAND_QUARANTINE_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(COMMAND_QUARANTINE_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_command_quarantine_checksum_field_sentinels_match_contracts() -> None:
    quarantine_fields = tuple(
        field.name
        for field in fields(CommandQuarantineEnvelope)
        if field.name != "quarantine_checksum"
    )
    approval_fields = tuple(
        field.name for field in fields(OperatorApprovalReceipt) if field.name != "approval_checksum"
    )
    release_fields = tuple(
        field.name
        for field in fields(QuarantineReleaseDecision)
        if field.name != "decision_checksum"
    )

    assert quarantine_fields == COMMAND_QUARANTINE_CHECKSUM_FIELDS
    assert approval_fields == OPERATOR_APPROVAL_CHECKSUM_FIELDS
    assert release_fields == QUARANTINE_RELEASE_CHECKSUM_FIELDS


def test_command_quarantine_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "lease_valid_dispatch_enters_quarantine" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "all_dispatch_items_quarantined" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "approval_required_for_release" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "approval_scope_explicit" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_backend_admission" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_backend_descriptor" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_registry" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_certification" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_backend_replay_proof" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "release_bound_to_context_authority" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_backend_calls" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_queueing" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_network_calls" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_COMMAND_QUARANTINE_V1_PROPERTIES


def test_command_quarantine_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "CommandQuarantineEnvelope" in names
    assert "OperatorApprovalReceipt" in names
    assert "QuarantineReleaseDecision" in names


def test_command_quarantine_forbidden_runtime_import_scan_is_clean() -> None:
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
