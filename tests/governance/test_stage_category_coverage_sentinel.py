"""Tests for ADR-0014 stage and scenario coverage sentinels."""

from __future__ import annotations

from dataclasses import replace

import pytest

import aegis.governance.aegis_coverage_sentinel as coverage_sentinel
from aegis.contracts.aegis_decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.governance.aegis_authority_fields import AUTHORITY_FIELD_MANIFESTS
from aegis.governance.aegis_coverage_sentinel import (
    assert_coverage_sentinel,
    evaluate_coverage_sentinel,
)
from aegis.scenarios.aegis_contracts import ScenarioCategory


def test_coverage_sentinel_passes_for_registered_stage_and_category_sets() -> None:
    result = evaluate_coverage_sentinel()

    assert result.passed
    assert result.errors == ()
    assert_coverage_sentinel()


def test_coverage_sentinel_rejects_stage_registry_drift() -> None:
    drifted_stages = DECISION_TRACE_STAGE_ORDER + ("uncovered_authority_stage",)

    result = evaluate_coverage_sentinel(stage_registry=drifted_stages)

    assert not result.passed
    assert "DECISION_TRACE_STAGE_COVERAGE_DRIFT" in result.errors


def test_coverage_sentinel_rejects_category_registry_drift() -> None:
    drifted_categories = tuple(ScenarioCategory)[1:]
    result = evaluate_coverage_sentinel(category_registry=drifted_categories)  # type: ignore[arg-type]
    assert not result.passed
    assert "SCENARIO_CATEGORY_COVERAGE_DRIFT" in result.errors


def test_coverage_sentinel_rejects_manifest_and_checksum_field_drift(
    monkeypatch,
) -> None:
    policy_manifest = next(
        manifest
        for manifest in AUTHORITY_FIELD_MANIFESTS
        if manifest.contract_name == "PolicyAdmissionRecord"
    )
    receipt_manifest = next(
        manifest
        for manifest in AUTHORITY_FIELD_MANIFESTS
        if manifest.contract_name == "ApprovalReceipt"
    )
    drifted_policy_manifest = replace(
        policy_manifest,
        authoritative_fields=policy_manifest.authoritative_fields + ("detached_read_isolation",),
    )
    drifted_receipt_manifest = replace(
        receipt_manifest,
        authoritative_fields=receipt_manifest.authoritative_fields + ("detached_read_isolation",),
    )
    monkeypatch.setattr(
        coverage_sentinel,
        "AUTHORITY_FIELD_MANIFESTS",
        (drifted_policy_manifest, drifted_receipt_manifest, drifted_policy_manifest),
    )
    monkeypatch.setattr(
        coverage_sentinel,
        "POLICY_CHECKSUM_FIELDS",
        tuple(
            field
            for field in coverage_sentinel.POLICY_CHECKSUM_FIELDS
            if field != "policy_authority"
        ),
    )
    monkeypatch.setattr(coverage_sentinel, "POLICY_IDENTITY_FIELDS", ("policy_authority",))

    result = evaluate_coverage_sentinel()

    assert not result.passed
    assert "AUTHORITY_FIELD_MANIFEST_DUPLICATE" in result.errors
    assert "POLICY_IDENTITY_FIELDS_MISSING_FROM_POLICY_CHECKSUM" in result.errors
    assert any(
        error.startswith("POLICY_ADMISSION_CHECKSUM_FIELD_DRIFT:") for error in result.errors
    )
    assert any(error.startswith("RECEIPT_BOUND_FIELD_DRIFT:") for error in result.errors)


def test_assert_coverage_sentinel_raises_on_drift(monkeypatch) -> None:
    monkeypatch.setattr(
        coverage_sentinel,
        "evaluate_coverage_sentinel",
        lambda: coverage_sentinel.CoverageSentinelResult(
            passed=False,
            errors=("DECISION_TRACE_STAGE_COVERAGE_DRIFT",),
        ),
    )
    with pytest.raises(ValueError, match="DECISION_TRACE_STAGE_COVERAGE_DRIFT"):
        assert_coverage_sentinel()
