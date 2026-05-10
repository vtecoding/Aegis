"""Governance coverage tests for ADR-0016 adapter replay."""

from __future__ import annotations

from dataclasses import fields

from aegis.contracts.adapter_replay import AdapterReplayProofResult
from aegis.execution.adapter_replay_fields import (
    ADAPTER_REPLAY_PROOF_CHECKSUM_FIELDS,
    ADAPTER_REPLAY_SCENARIO_CATEGORY_NAMES,
    STRICT_ADAPTER_REPLAY_V1_PROPERTIES,
)
from aegis.governance.adapter_fields import ADAPTER_AUTHORITY_FIELD_MANIFESTS
from aegis.scenarios.contracts import ScenarioCategory
from aegis.scenarios.coverage import evaluate_scenario_coverage
from aegis.scenarios.fixtures import canonical_scenario_definitions


def test_adapter_replay_categories_are_registered_and_covered() -> None:
    category_names = {category.value for category in ScenarioCategory}
    scenarios = canonical_scenario_definitions()
    covered_names = {scenario.category.value for scenario in scenarios}
    coverage = evaluate_scenario_coverage(scenarios)

    assert set(ADAPTER_REPLAY_SCENARIO_CATEGORY_NAMES).issubset(category_names)
    assert set(ADAPTER_REPLAY_SCENARIO_CATEGORY_NAMES).issubset(covered_names)
    assert coverage.passed is True


def test_adapter_replay_proof_checksum_field_sentinel_matches_contract() -> None:
    proof_fields = tuple(
        field.name for field in fields(AdapterReplayProofResult) if field.name != "proof_checksum"
    )

    assert proof_fields == ADAPTER_REPLAY_PROOF_CHECKSUM_FIELDS


def test_strict_adapter_replay_profile_keeps_runtime_boundaries_forbidden() -> None:
    assert "no_runtime_io" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_clocks" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_random_ids" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_environment_reads" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_filesystem_reads" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_network_calls" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_ros_imports" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES
    assert "no_async" in STRICT_ADAPTER_REPLAY_V1_PROPERTIES


def test_adapter_replay_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "AdapterReplayRequest" in names
    assert "AdapterReplayProofResult" in names
