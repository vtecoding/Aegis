"""Object injection tests for ADR-0021 capability leases."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.execution.aegis_capability_lease import (
    CapabilityLeaseReason,
    issue_runtime_capability_lease,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease


def test_runtime_object_injection_blocks_lease_issue() -> None:
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
    ) = capability_lease_parts(request_id="lease-object-injection")

    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value
    ):
        issue_runtime_capability_lease(
            admission_decision=admission_decision,
            backend_descriptor={"mutable": descriptor},
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


def test_callable_scope_injection_blocks_lease_issue() -> None:
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
    ) = capability_lease_parts(request_id="lease-callable-scope")

    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value
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
            leased_capabilities=(lambda: "locomotion.translation",),
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )


def test_runtime_object_injection_invalidates_validation() -> None:
    lease = runtime_capability_lease(request_id="lease-validation-object-injection")
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
    ) = capability_lease_parts(request_id="lease-validation-object-injection")
    injected = SimpleNamespace(
        lease_checksum=lease.lease_checksum,
        backend_client=object(),
        leased_capabilities=["locomotion.translation"],
    )

    result = validate_runtime_capability_lease(
        lease=injected,
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


def test_mutable_scope_cannot_escape_from_valid_lease() -> None:
    lease = runtime_capability_lease(request_id="lease-no-mutable-scope")

    assert isinstance(lease.leased_capabilities, frozenset)
    assert isinstance(lease.leased_runtime_kinds, frozenset)
