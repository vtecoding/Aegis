"""Governance coverage tests for ADR-0019 backend replay proofs."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from aegis.contracts.backend_replay import BackendReplayProofResult, BackendReplayRequest
from aegis.execution.backend_replay_fields import (
    BACKEND_REPLAY_PROOF_CHECKSUM_FIELDS,
    BACKEND_REPLAY_REQUEST_FIELDS,
    BACKEND_REPLAY_SCENARIO_CATEGORY_NAMES,
    STRICT_BACKEND_REPLAY_V1_PROPERTIES,
)
from aegis.governance.adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions


def test_backend_replay_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(BACKEND_REPLAY_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(BACKEND_REPLAY_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_backend_replay_checksum_field_sentinels_match_contracts() -> None:
    request_fields = tuple(field.name for field in fields(BackendReplayRequest))
    proof_fields = tuple(
        field.name for field in fields(BackendReplayProofResult) if field.name != "proof_checksum"
    )

    assert request_fields == BACKEND_REPLAY_REQUEST_FIELDS
    assert proof_fields == BACKEND_REPLAY_PROOF_CHECKSUM_FIELDS


def test_strict_backend_replay_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "deterministic_canonical_serialization" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_io" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_clocks" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_randomness" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_async" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_network_calls" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_runtime_imports" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_simulator_hooks" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_hardware_hooks" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "no_global_mutable_state" in STRICT_BACKEND_REPLAY_V1_PROPERTIES
    assert "zero_execution_required" in STRICT_BACKEND_REPLAY_V1_PROPERTIES


def test_backend_replay_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "BackendReplayRequest" in names
    assert "BackendReplayProofResult" in names


def test_backend_replay_forbidden_runtime_import_scan_is_clean() -> None:
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
