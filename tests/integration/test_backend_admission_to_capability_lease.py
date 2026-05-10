"""Integration tests from backend admission to ADR-0021 capability leases."""

from __future__ import annotations

import pytest
from tests.capability_lease_fixtures import capability_lease_parts

from aegis.execution.aegis_backend_admission import BackendAdmissionDecision
from aegis.execution.aegis_capability_lease import (
    CapabilityLeaseReason,
    issue_runtime_capability_lease,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease


def test_admitted_null_backend_receives_valid_capability_lease() -> None:
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
    ) = capability_lease_parts(request_id="lease-integration-positive")

    lease = issue_runtime_capability_lease(
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
        leased_runtime_kinds=manifest.allowed_runtime_kinds,
        lease_epoch=1,
    )
    validation = validate_runtime_capability_lease(
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

    assert lease.lease_status.value == "ACTIVE_NULL_ONLY"
    assert validation.status == "VALID"
    assert validation.scope_match is True
    assert validation.evidence_chain_match is True


def test_non_admitted_backend_blocks_capability_lease() -> None:
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
    ) = capability_lease_parts(request_id="lease-integration-non-admitted")
    blocked = BackendAdmissionDecision(
        status="BLOCKED",
        reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
        backend_kind=admission_decision.backend_kind,
        backend_descriptor_checksum=admission_decision.backend_descriptor_checksum,
        certification_checksum=admission_decision.certification_checksum,
        replay_proof_checksum=admission_decision.replay_proof_checksum,
        authority_manifest_checksum=admission_decision.authority_manifest_checksum,
        registry_checksum=admission_decision.registry_checksum,
    )

    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_BACKEND_NOT_ADMITTED.value
    ):
        issue_runtime_capability_lease(
            admission_decision=blocked,
            backend_descriptor=descriptor,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            dispatch_plan=plan,
            firewall_decision=decision,
            context_authority_checksum=context_authority.context_checksum,
            leased_capabilities=manifest.allowed_capabilities,
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )


def test_scope_subset_can_be_narrower_than_backend_authority() -> None:
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
    ) = capability_lease_parts(request_id="lease-integration-scope-subset")
    one_capability = (next(iter(manifest.allowed_capabilities)),)
    one_runtime_kind = (next(iter(manifest.allowed_runtime_kinds)),)

    lease = issue_runtime_capability_lease(
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        leased_capabilities=one_capability,
        leased_runtime_kinds=one_runtime_kind,
        lease_epoch=1,
    )

    assert lease.leased_capabilities == frozenset(one_capability)
    assert lease.leased_runtime_kinds == frozenset(one_runtime_kind)
