"""Governance coverage tests for ADR-0017 runtime dispatch dry-run firewall."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.contracts.runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchPlan,
    RuntimeDispatchReceipt,
)
from aegis.execution.dispatch_fields import (
    DISPATCH_FIREWALL_DECISION_CHECKSUM_FIELDS,
    RUNTIME_DISPATCH_PLAN_CHECKSUM_FIELDS,
    RUNTIME_DISPATCH_RECEIPT_CHECKSUM_FIELDS,
    RUNTIME_DISPATCH_SCENARIO_CATEGORY_NAMES,
    STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES,
)
from aegis.governance.adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions


def test_runtime_dispatch_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(RUNTIME_DISPATCH_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(RUNTIME_DISPATCH_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_runtime_dispatch_checksum_field_sentinels_match_contracts() -> None:
    plan_fields = tuple(
        field.name for field in fields(RuntimeDispatchPlan) if field.name != "plan_checksum"
    )
    decision_fields = tuple(
        field.name
        for field in fields(DispatchFirewallDecision)
        if field.name != "decision_checksum"
    )
    receipt_fields = tuple(
        field.name
        for field in fields(RuntimeDispatchReceipt)
        if field.name != "dry_run_receipt_checksum"
    )

    assert plan_fields == RUNTIME_DISPATCH_PLAN_CHECKSUM_FIELDS
    assert decision_fields == DISPATCH_FIREWALL_DECISION_CHECKSUM_FIELDS
    assert receipt_fields == RUNTIME_DISPATCH_RECEIPT_CHECKSUM_FIELDS


def test_runtime_dispatch_dry_run_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "replay_proof_required" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "exact_envelope_binding" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "dry_run_only" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "inert_data_only" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_runtime_backend" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_runtime_io" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_network_calls" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES
    assert "no_async" in STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES


def test_runtime_dispatch_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "RuntimeDispatchItem" in names
    assert "RuntimeDispatchPlan" in names
    assert "DispatchFirewallDecision" in names
    assert "RuntimeDispatchReceipt" in names


def test_runtime_dispatch_forbidden_runtime_import_scan_is_clean() -> None:
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
