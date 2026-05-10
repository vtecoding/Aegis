"""Contract tests for ADR-0021 lease validation results."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.execution.aegis_capability_lease import CapabilityLeaseReason
from aegis.execution.aegis_lease_validation import (
    LeaseValidationResult,
    lease_validation_result_checksum,
    recompute_lease_validation_result_checksum,
    validate_runtime_capability_lease,
)


def _validate_positive(request_id: str = "lease-validation-positive") -> LeaseValidationResult:
    lease = runtime_capability_lease(request_id=request_id)
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id=request_id)
    return validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )


def test_lease_validation_result_valid_requires_scope_and_evidence_match() -> None:
    result = _validate_positive()

    assert result.status == "VALID"
    assert result.reason_code == CapabilityLeaseReason.CAPABILITY_LEASE_VALID.value
    assert result.scope_match is True
    assert result.evidence_chain_match is True
    assert result.validation_checksum == recompute_lease_validation_result_checksum(result)

    with pytest.raises(ValueError, match="VALID"):
        LeaseValidationResult(
            status="VALID",
            reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_VALID.value,
            lease_checksum=result.lease_checksum,
            current_registry_checksum=result.current_registry_checksum,
            current_manifest_checksum=result.current_manifest_checksum,
            current_context_authority_checksum=result.current_context_authority_checksum,
            scope_match=False,
            evidence_chain_match=True,
        )


def test_lease_validation_result_checksum_binds_all_fields() -> None:
    result = _validate_positive(request_id="lease-validation-checksum")
    changed_checksum = lease_validation_result_checksum(
        status="INVALID",
        reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_CHECKSUM_DRIFT.value,
        lease_checksum=result.lease_checksum,
        current_registry_checksum=result.current_registry_checksum,
        current_manifest_checksum=result.current_manifest_checksum,
        current_context_authority_checksum=result.current_context_authority_checksum,
        scope_match=result.scope_match,
        evidence_chain_match=False,
    )

    assert result.validation_checksum != changed_checksum


def test_lease_validation_rejects_unknown_lease_shape_as_invalid() -> None:
    lease = runtime_capability_lease(request_id="lease-validation-unknown-field")
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id="lease-validation-unknown-field")
    forged = SimpleNamespace(lease_checksum=lease.lease_checksum, unexpected="field")

    result = validate_runtime_capability_lease(
        lease=forged,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert result.status == "INVALID"
    assert (
        result.reason_code == CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value
    )


def test_lease_validation_context_drift_revokes() -> None:
    lease = runtime_capability_lease(request_id="lease-validation-context-drift")
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        _,
    ) = capability_lease_parts(request_id="lease-validation-context-drift")

    result = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum="1" * 64,
        current_lease_epoch=1,
    )

    assert result.status == "REVOKED"
    assert (
        result.reason_code
        == CapabilityLeaseReason.CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT.value
    )
    assert result.evidence_chain_match is False
