"""Contract tests for ADR-0021 runtime capability leases."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.contracts.aegis_runtime_backend import RuntimeBackendKind
from aegis.contracts.aegis_runtime_dispatch import RuntimeDispatchKind
from aegis.execution.aegis_capability_lease import (
    CapabilityLeaseReason,
    RuntimeCapabilityLease,
    RuntimeCapabilityLeaseStatus,
    capability_lease_issue_block_reason,
    checksum_or_fallback,
    issue_runtime_capability_lease,
    normalize_lease_capabilities,
    normalize_lease_epoch,
    normalize_lease_runtime_kinds,
    recompute_runtime_capability_lease_checksum,
)


def test_runtime_capability_lease_binds_admitted_null_backend_evidence() -> None:
    lease = runtime_capability_lease(request_id="lease-contract-bindings")
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
    ) = capability_lease_parts(request_id="lease-contract-bindings")

    assert lease.backend_kind == RuntimeBackendKind.NULL_BACKEND_V1.value
    assert lease.backend_descriptor_checksum == descriptor.descriptor_checksum
    assert lease.admission_decision_checksum == admission_decision.decision_checksum
    assert lease.authority_manifest_checksum == manifest.manifest_checksum
    assert lease.registry_checksum == registry.registry_checksum
    assert lease.certification_checksum == certification.certification_checksum
    assert lease.replay_proof_checksum == replay_proof.proof_checksum
    assert lease.dispatch_plan_checksum == plan.plan_checksum
    assert lease.firewall_decision_checksum == decision.decision_checksum
    assert lease.context_authority_checksum == context_authority.context_checksum
    assert lease.leased_capabilities == manifest.allowed_capabilities
    assert lease.leased_runtime_kinds == manifest.allowed_runtime_kinds
    assert lease.lease_status is RuntimeCapabilityLeaseStatus.ACTIVE_NULL_ONLY
    assert lease.lease_checksum == recompute_runtime_capability_lease_checksum(lease)


def test_runtime_capability_lease_is_immutable_and_direct_construction_is_blocked() -> None:
    lease = runtime_capability_lease(request_id="lease-contract-immutable")

    with pytest.raises(FrozenInstanceError):
        lease.lease_epoch = 2
    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.DIRECT_CAPABILITY_LEASE_CONSTRUCTION.value
    ):
        RuntimeCapabilityLease(
            lease_id=lease.lease_id,
            backend_kind=lease.backend_kind,
            backend_descriptor_checksum=lease.backend_descriptor_checksum,
            admission_decision_checksum=lease.admission_decision_checksum,
            authority_manifest_checksum=lease.authority_manifest_checksum,
            registry_checksum=lease.registry_checksum,
            certification_checksum=lease.certification_checksum,
            replay_proof_checksum=lease.replay_proof_checksum,
            dispatch_plan_checksum=lease.dispatch_plan_checksum,
            firewall_decision_checksum=lease.firewall_decision_checksum,
            context_authority_checksum=lease.context_authority_checksum,
            leased_capabilities=lease.leased_capabilities,
            leased_runtime_kinds=lease.leased_runtime_kinds,
            lease_epoch=lease.lease_epoch,
            lease_status=lease.lease_status,
            lease_checksum=lease.lease_checksum,
        )


def test_runtime_capability_lease_checksum_changes_on_epoch_change() -> None:
    first = runtime_capability_lease(request_id="lease-contract-epoch", lease_epoch=1)
    second = runtime_capability_lease(request_id="lease-contract-epoch", lease_epoch=2)

    assert first.lease_id != second.lease_id
    assert first.lease_checksum != second.lease_checksum


def test_runtime_capability_lease_rejects_empty_or_wildcard_scope() -> None:
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
    ) = capability_lease_parts(request_id="lease-contract-scope")

    with pytest.raises(ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_EMPTY_SCOPE.value):
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
            leased_capabilities=(),
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )
    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_WILDCARD_SCOPE.value
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
            leased_capabilities=("*",),
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )


def test_runtime_capability_lease_rejects_malformed_context_and_epoch() -> None:
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
    ) = capability_lease_parts(request_id="lease-contract-malformed")

    with pytest.raises(ValueError, match="context_authority_checksum"):
        issue_runtime_capability_lease(
            admission_decision=admission_decision,
            backend_descriptor=descriptor,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            dispatch_plan=plan,
            firewall_decision=decision,
            context_authority_checksum="bad",
            leased_capabilities=manifest.allowed_capabilities,
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=1,
        )
    with pytest.raises(ValueError, match="lease_epoch"):
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
            leased_runtime_kinds=manifest.allowed_runtime_kinds,
            lease_epoch=-1,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "admission_decision",
        "backend_descriptor",
        "authority_manifest",
        "backend_certification",
        "backend_replay_proof",
        "dispatch_plan",
        "firewall_decision",
    ],
)
def test_capability_lease_issue_block_reason_rejects_runtime_object_injection(
    field_name: str,
) -> None:
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
    ) = capability_lease_parts(request_id=f"lease-contract-object-injection-{field_name}")
    candidate_admission: object = admission_decision
    candidate_descriptor: object = descriptor
    candidate_manifest: object = manifest
    candidate_certification: object = certification
    candidate_replay_proof: object = replay_proof
    candidate_plan: object = plan
    candidate_firewall: object = decision
    injected = object()

    if field_name == "admission_decision":
        candidate_admission = injected
    elif field_name == "backend_descriptor":
        candidate_descriptor = injected
    elif field_name == "authority_manifest":
        candidate_manifest = injected
    elif field_name == "backend_certification":
        candidate_certification = injected
    elif field_name == "backend_replay_proof":
        candidate_replay_proof = injected
    elif field_name == "dispatch_plan":
        candidate_plan = injected
    else:
        candidate_firewall = injected

    reason = capability_lease_issue_block_reason(
        admission_decision=candidate_admission,
        backend_descriptor=candidate_descriptor,
        authority_manifest=candidate_manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=candidate_certification,
        backend_replay_proof=candidate_replay_proof,
        dispatch_plan=candidate_plan,
        firewall_decision=candidate_firewall,
        leased_capabilities=manifest.allowed_capabilities,
        leased_runtime_kinds=manifest.allowed_runtime_kinds,
    )

    assert reason is CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION


def test_capability_lease_normalizers_reject_non_canonical_boundary_values() -> None:
    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_WILDCARD_SCOPE.value
    ):
        normalize_lease_capabilities(("*",))
    with pytest.raises(ValueError, match="canonical dotted lowercase"):
        normalize_lease_capabilities(("Bad.Scope",))
    with pytest.raises(
        ValueError, match=CapabilityLeaseReason.CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION.value
    ):
        normalize_lease_runtime_kinds((lambda: RuntimeDispatchKind.ROS2_ACTION,))
    with pytest.raises(ValueError, match="undeclared kind"):
        normalize_lease_runtime_kinds(("not-a-runtime",))
    with pytest.raises(ValueError, match="lease_epoch"):
        normalize_lease_epoch(True)

    assert checksum_or_fallback("f" * 64) == "f" * 64
    assert checksum_or_fallback("not-a-checksum") == "0" * 64
