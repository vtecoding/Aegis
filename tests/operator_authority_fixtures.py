"""Shared deterministic fixtures for ADR-0023 operator authority tests."""

from __future__ import annotations

from dataclasses import dataclass

from tests.command_quarantine_fixtures import command_quarantine_parts

from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
)
from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution.aegis_approval_replay import (
    ApprovalReplayValidationResult,
    AuthorityBoundApprovalReceipt,
    build_authority_bound_approval_receipt,
    validate_approval_replay,
)
from aegis.execution.aegis_backend_admission import BackendAdmissionDecision
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_backend_registry import BackendAuthorityRegistry
from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    quarantine_item_checksums,
    quarantine_runtime_command,
)
from aegis.execution.aegis_operator_approval import OperatorApprovalStatus
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityManifest,
    build_operator_authority_manifest,
)
from aegis.execution.aegis_operator_identity import (
    OperatorApprovalNonce,
    OperatorIdentityClaim,
    build_operator_approval_nonce,
    build_operator_identity_claim,
)
from aegis.governance.aegis_context_authority import ContextAuthority


@dataclass(frozen=True, slots=True)
class OperatorAuthorityParts:
    """Complete positive ADR-0023 source evidence chain."""

    dispatch_plan: RuntimeDispatchPlan
    firewall_decision: DispatchFirewallDecision
    backend_descriptor: RuntimeBackendDescriptor
    backend_certification: BackendCertificationResult
    backend_replay_proof: BackendReplayProofResult
    backend_authority_manifest: BackendAuthorityManifest
    backend_registry: BackendAuthorityRegistry
    backend_admission_decision: BackendAdmissionDecision
    context_authority: ContextAuthority
    capability_lease: RuntimeCapabilityLease
    quarantine: CommandQuarantineEnvelope
    operator_authority_manifest: OperatorAuthorityManifest
    operator_identity: OperatorIdentityClaim
    approval_nonce: OperatorApprovalNonce
    approval: AuthorityBoundApprovalReceipt
    replay_validation: ApprovalReplayValidationResult


def operator_authority_parts(
    *,
    request_id: str = "operator-authority",
    lease_epoch: int = 1,
    quarantine_epoch: int = 1,
    operator_id: str = "operator-001",
    operator_role: str = "release.operator",
    approval_status: OperatorApprovalStatus | str = OperatorApprovalStatus.APPROVED,
    approved_scope: frozenset[str] | None = None,
) -> OperatorAuthorityParts:
    """Return the positive ADR-0023 authority-bound approval source evidence."""
    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        backend_authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id=request_id, lease_epoch=lease_epoch)
    quarantine = quarantine_runtime_command(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=backend_authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        quarantine_epoch=quarantine_epoch,
        current_lease_epoch=lease_epoch,
    )
    authority_manifest = build_operator_authority_manifest(
        allowed_operator_roles=(operator_role,),
        allowed_approval_scopes=quarantine_item_checksums(quarantine),
        required_context_authority_checksum=context_authority.context_checksum,
        approval_epoch=quarantine.quarantine_epoch,
    )
    identity = build_operator_identity_claim(
        manifest=authority_manifest,
        operator_id=operator_id,
        operator_role=operator_role,
        context_authority_checksum=context_authority.context_checksum,
        identity_epoch=quarantine.quarantine_epoch,
    )
    nonce = build_operator_approval_nonce(
        quarantine=quarantine,
        operator_identity=identity,
        approval_epoch=quarantine.quarantine_epoch,
    )
    approval = build_authority_bound_approval_receipt(
        quarantine=quarantine,
        operator_identity=identity,
        authority_manifest=authority_manifest,
        approval_nonce=nonce,
        approval_status=approval_status,
        approved_scope=approved_scope
        if approved_scope is not None
        else quarantine_item_checksums(quarantine),
    )
    replay_validation = validate_approval_replay(
        quarantine=quarantine,
        approval=approval,
        operator_identity=identity,
        authority_manifest=authority_manifest,
        approval_nonce=nonce,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_backend_manifest=backend_authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=lease_epoch,
    )
    return OperatorAuthorityParts(
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        backend_descriptor=backend_descriptor,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        backend_authority_manifest=backend_authority_manifest,
        backend_registry=backend_registry,
        backend_admission_decision=backend_admission_decision,
        context_authority=context_authority,
        capability_lease=capability_lease,
        quarantine=quarantine,
        operator_authority_manifest=authority_manifest,
        operator_identity=identity,
        approval_nonce=nonce,
        approval=approval,
        replay_validation=replay_validation,
    )


__all__ = ["OperatorAuthorityParts", "operator_authority_parts"]
