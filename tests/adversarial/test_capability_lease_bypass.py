"""Adversarial bypass tests for ADR-0021 capability leases."""

from __future__ import annotations

import pytest
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.execution.aegis_capability_lease import (
    CapabilityLeaseReason,
    issue_runtime_capability_lease,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease


def test_capability_overclaim_blocks_lease_issue() -> None:
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
    ) = capability_lease_parts(request_id="lease-bypass-capability")

    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_CAPABILITY_OVERCLAIM.value
    ):
        issue_runtime_capability_lease(
            admission_decision=admission_decision,
            backend_descriptor=descriptor,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            dispatch_plan=plan,
            firewall_decision=decision,
            context_authority_checksum=context_authority.context_checksum,
            leased_capabilities=("unsafe.execute",),
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )


def test_runtime_kind_overclaim_blocks_lease_issue() -> None:
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
    ) = capability_lease_parts(request_id="lease-bypass-runtime-kind")

    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM.value
    ):
        issue_runtime_capability_lease(
            admission_decision=admission_decision,
            backend_descriptor=descriptor,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            dispatch_plan=plan,
            firewall_decision=decision,
            context_authority_checksum=context_authority.context_checksum,
            leased_capabilities=manifest.allowed_capabilities,
            leased_runtime_kinds=("service", "action"),
            lease_epoch=1,
        )


def test_registry_manifest_certification_and_replay_drift_invalidate_lease() -> None:
    lease = runtime_capability_lease(request_id="lease-bypass-drift")
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
    ) = capability_lease_parts(request_id="lease-bypass-drift")

    object.__setattr__(manifest, "manifest_checksum", "1" * 64)
    manifest_result = validate_runtime_capability_lease(
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
    object.__setattr__(manifest, "manifest_checksum", lease.authority_manifest_checksum)
    object.__setattr__(certification, "certification_checksum", "1" * 64)
    certification_result = validate_runtime_capability_lease(
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
    object.__setattr__(certification, "certification_checksum", lease.certification_checksum)
    object.__setattr__(replay_proof, "proof_checksum", "1" * 64)
    replay_result = validate_runtime_capability_lease(
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
    registry_result = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum="1" * 64,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert manifest_result.status == "REVOKED"
    assert certification_result.status == "REVOKED"
    assert replay_result.status == "REVOKED"
    assert registry_result.status == "REVOKED"


def test_stale_lease_epoch_does_not_validate() -> None:
    lease = runtime_capability_lease(request_id="lease-bypass-stale", lease_epoch=1)
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
    ) = capability_lease_parts(request_id="lease-bypass-stale")

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
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=2,
    )

    assert result.status == "REVOKED"
    assert result.reason_code == CapabilityLeaseReason.CAPABILITY_LEASE_STALE_EPOCH.value
