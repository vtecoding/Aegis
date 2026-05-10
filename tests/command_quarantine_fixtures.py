"""Shared deterministic fixtures for ADR-0022 command quarantine tests."""

from __future__ import annotations

from tests.capability_lease_fixtures import capability_lease_parts

from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
)
from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution.aegis_backend_admission import BackendAdmissionDecision
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_backend_registry import BackendAuthorityRegistry
from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    quarantine_item_checksums,
    quarantine_runtime_command,
)
from aegis.execution.aegis_operator_approval import (
    OperatorApprovalReceipt,
    OperatorApprovalStatus,
    build_operator_approval_receipt,
)
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)
from aegis.governance.aegis_context_authority import ContextAuthority


def command_quarantine_parts(
    *,
    request_id: str = "command-quarantine",
    lease_epoch: int = 1,
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
    RuntimeCapabilityLease,
]:
    """Return the positive ADR-0022 source evidence chain."""
    from aegis.execution.aegis_capability_lease import issue_runtime_capability_lease

    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id=request_id)
    capability_lease = issue_runtime_capability_lease(
        admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        leased_capabilities=authority_manifest.allowed_capabilities,
        leased_runtime_kinds=authority_manifest.allowed_runtime_kinds,
        lease_epoch=lease_epoch,
    )
    return (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    )


def command_quarantine_envelope(
    *,
    request_id: str = "command-quarantine",
    lease_epoch: int = 1,
    quarantine_epoch: int = 1,
) -> CommandQuarantineEnvelope:
    """Return a deterministic positive command quarantine envelope."""
    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id=request_id, lease_epoch=lease_epoch)
    return quarantine_runtime_command(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        quarantine_epoch=quarantine_epoch,
        current_lease_epoch=lease_epoch,
    )


def operator_approval_receipt(
    *,
    quarantine: CommandQuarantineEnvelope,
    approval_status: OperatorApprovalStatus | str = OperatorApprovalStatus.APPROVED,
    approval_epoch: int | None = None,
    approved_scope: frozenset[str] | None = None,
    operator_id: str = "operator-001",
    approval_reason: str = "fixture approval",
) -> OperatorApprovalReceipt:
    """Return a deterministic operator approval receipt for a quarantine envelope."""
    return build_operator_approval_receipt(
        quarantine=quarantine,
        operator_id=operator_id,
        approval_status=approval_status,
        approved_scope=approved_scope
        if approved_scope is not None
        else quarantine_item_checksums(quarantine),
        approval_epoch=quarantine.quarantine_epoch if approval_epoch is None else approval_epoch,
        approval_reason=approval_reason,
    )


def quarantine_release_decision(
    *,
    request_id: str = "command-quarantine",
    lease_epoch: int = 1,
    quarantine_epoch: int = 1,
) -> QuarantineReleaseDecision:
    """Return a deterministic positive quarantine release decision."""
    from tests.operator_authority_fixtures import operator_authority_parts

    parts = operator_authority_parts(
        request_id=request_id,
        lease_epoch=lease_epoch,
        quarantine_epoch=quarantine_epoch,
    )
    return evaluate_quarantine_release(
        quarantine=parts.quarantine,
        approval=parts.approval,
        approval_replay_validation=parts.replay_validation,
        capability_lease=parts.capability_lease,
        dispatch_plan=parts.dispatch_plan,
        backend_admission_decision=parts.backend_admission_decision,
        backend_descriptor=parts.backend_descriptor,
        authority_manifest=parts.backend_authority_manifest,
        registry_checksum=parts.backend_registry.registry_checksum,
        backend_certification=parts.backend_certification,
        backend_replay_proof=parts.backend_replay_proof,
        firewall_decision=parts.firewall_decision,
        context_authority_checksum=parts.context_authority.context_checksum,
        current_lease_epoch=lease_epoch,
    )


__all__ = [
    "command_quarantine_envelope",
    "command_quarantine_parts",
    "operator_approval_receipt",
    "quarantine_release_decision",
]
