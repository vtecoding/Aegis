"""Tests for ADR-0014 authority field drift detection."""

from __future__ import annotations

from aegis.governance.aegis_authority_fields import manifest_for
from aegis.governance.aegis_context_authority import ContextAuthority
from aegis.governance.aegis_contract_drift import assert_no_contract_drift, evaluate_contract_drift


def test_contract_drift_sentinel_passes_for_registered_manifests() -> None:
    result = evaluate_contract_drift()

    assert result.passed
    assert result.errors == ()
    assert_no_contract_drift()


def test_contract_drift_sentinel_rejects_unclassified_authority_field() -> None:
    incomplete_contract = manifest_for(
        contract_type=ContextAuthority,
        authoritative_fields=(
            "context_id",
            "request_id",
            "evaluation_time_ms",
            "caller_authority",
            "deployment_domain",
            "context_checksum",
        ),
        non_authoritative_fields=(),
        checksum_function="context_authority_checksum",
        reason="intentional incomplete manifest for drift detection",
    )

    result = evaluate_contract_drift((incomplete_contract,))

    assert not result.passed
    assert any("context_schema_version" in error for error in result.errors)


def test_contract_drift_sentinel_rejects_manifest_shape_and_duplicate_contracts() -> None:
    duplicate_one = manifest_for(
        contract_type=ContextAuthority,
        authoritative_fields=("context_id",),
        non_authoritative_fields=("context_id", "not_real_field"),
        checksum_function="",
        reason="",
    )
    duplicate_two = manifest_for(
        contract_type=ContextAuthority,
        authoritative_fields=("request_id",),
        non_authoritative_fields=(),
        checksum_function="context_authority_checksum",
        reason="duplicate entry",
    )
    object.__setattr__(duplicate_one.manifest, "contract_name", "WrongName")

    result = evaluate_contract_drift((duplicate_one, duplicate_two))

    assert not result.passed
    assert any("manifest contract_name mismatch" in error for error in result.errors)
    assert any("duplicate authority manifest" in error for error in result.errors)
    assert any("fields classified twice" in error for error in result.errors)
    assert any("manifest names unknown fields" in error for error in result.errors)
    assert any("checksum_function missing" in error for error in result.errors)
    assert any("manifest reason missing" in error for error in result.errors)
