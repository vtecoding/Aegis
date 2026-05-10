"""Governance tests for ADR-0015 adapter authority manifests."""

from __future__ import annotations

from aegis.contracts.aegis_ros2_mapping import RuntimeTarget
from aegis.governance.aegis_adapter_authority import (
    assert_no_adapter_authority_drift,
    evaluate_adapter_authority_drift,
)
from aegis.governance.aegis_adapter_fields import (
    ADAPTER_AUTHORITY_FIELD_MANIFESTS,
    AdapterAuthorityContract,
    AdapterAuthorityFieldManifest,
)


def test_adapter_authority_manifest_drift_check_passes() -> None:
    result = evaluate_adapter_authority_drift()

    assert result.passed
    assert result.errors == ()
    assert_no_adapter_authority_drift()


def test_adapter_authority_manifests_are_registered() -> None:
    names = {manifest.contract_name for manifest in ADAPTER_AUTHORITY_FIELD_MANIFESTS}

    assert "RuntimeTarget" in names
    assert "Ros2MessageMapping" in names
    assert "ExecutionAdapterEnvelope" in names
    assert "AdapterReceipt" in names


def test_adapter_authority_drift_reports_missing_and_unknown_fields() -> None:
    manifest = AdapterAuthorityFieldManifest(
        contract_name="RuntimeTarget",
        authoritative_fields=("runtime_kind", "unknown_field"),
        checksum_function="runtime_target_checksum_value",
        reason="test manifest drift",
    )
    result = evaluate_adapter_authority_drift(
        (AdapterAuthorityContract(contract_type=RuntimeTarget, manifest=manifest),)
    )

    assert not result.passed
    assert any("missing adapter manifest fields" in error for error in result.errors)
    assert any("unknown adapter manifest fields" in error for error in result.errors)


def test_adapter_authority_drift_reports_duplicate_contracts() -> None:
    manifest = AdapterAuthorityFieldManifest(
        contract_name="RuntimeTarget",
        authoritative_fields=(
            "runtime_kind",
            "runtime_id",
            "runtime_version",
            "deployment_domain",
            "target_namespace",
            "target_robot_id",
            "runtime_authority",
            "runtime_target_checksum",
        ),
        checksum_function="runtime_target_checksum_value",
        reason="test manifest drift",
    )
    contract = AdapterAuthorityContract(contract_type=RuntimeTarget, manifest=manifest)
    result = evaluate_adapter_authority_drift((contract, contract))

    assert not result.passed
    assert result.errors == ("RuntimeTarget: duplicate adapter authority manifest",)
