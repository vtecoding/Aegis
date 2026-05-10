"""Shared deterministic fixtures for ADR-0021 capability lease tests."""

from __future__ import annotations

from tests.backend_replay_fixtures import backend_replay_request

from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
)
from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution import (
    build_backend_authority_manifest,
    build_backend_authority_registry,
    issue_runtime_capability_lease,
    prove_backend_replay,
)
from aegis.execution.aegis_backend_admission import (
    BackendAdmissionDecision,
    BackendAdmissionRequest,
    admit_runtime_backend,
)
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_backend_registry import BackendAuthorityRegistry
from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease
from aegis.governance.aegis_context_authority import ContextAuthority


def capability_lease_context(*, request_id: str = "capability-lease") -> ContextAuthority:
    """Return deterministic context authority evidence for lease tests."""
    return ContextAuthority(
        context_id=f"{request_id}-context",
        request_id=request_id,
        evaluation_time_ms=1_000_000,
        caller_authority="lease-test-orchestrator",
        deployment_domain="dry-run-test-domain",
        context_schema_version="context-authority-v1",
    )


def capability_lease_parts(
    *,
    request_id: str = "capability-lease",
) -> tuple[
    RuntimeDispatchPlan,
    DispatchFirewallDecision,
    RuntimeBackendDescriptor,
    BackendCertificationResult,
    BackendReplayProofResult,
    BackendAuthorityManifest,
    BackendAuthorityRegistry,
    BackendAdmissionDecision,
    ContextAuthority,
]:
    """Return the positive ADR-0021 source evidence chain."""
    replay_request = backend_replay_request(request_id=request_id)
    replay_proof = prove_backend_replay(replay_request)
    manifest = build_backend_authority_manifest(replay_request.backend_descriptor)
    registry = build_backend_authority_registry(manifest)
    admission_request = BackendAdmissionRequest(
        backend_descriptor=replay_request.backend_descriptor,
        backend_certification=replay_request.expected_certification,
        backend_replay_proof=replay_proof,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
    )
    admission_decision = admit_runtime_backend(admission_request)
    context_authority = capability_lease_context(request_id=request_id)
    return (
        replay_request.dispatch_plan,
        replay_request.firewall_decision,
        replay_request.backend_descriptor,
        replay_request.expected_certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    )


def runtime_capability_lease(
    *,
    request_id: str = "capability-lease",
    lease_epoch: int = 1,
) -> RuntimeCapabilityLease:
    """Return a deterministic positive runtime capability lease."""
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
    return issue_runtime_capability_lease(
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
        lease_epoch=lease_epoch,
    )


__all__ = ["capability_lease_context", "capability_lease_parts", "runtime_capability_lease"]
