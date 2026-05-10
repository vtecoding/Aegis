"""Integration tests from ADR-0023 operator authority to quarantine release."""

from __future__ import annotations

from tests.command_quarantine_fixtures import operator_approval_receipt
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_command_quarantine import CommandQuarantineReason
from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release


def test_valid_structural_operator_authority_releases_exact_quarantine() -> None:
    parts = operator_authority_parts(request_id="operator-authority-release-positive")

    release = evaluate_quarantine_release(
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
        current_lease_epoch=1,
    )

    assert release.status == "RELEASED_DRY_RUN"
    assert release.approval_checksum == parts.approval.authority_bound_checksum
    assert release.approval_replay_validation_checksum == (
        parts.replay_validation.replay_validation_checksum
    )


def test_structural_operator_approval_receipt_alone_cannot_release_quarantine() -> None:
    parts = operator_authority_parts(request_id="operator-authority-release-structural-only")
    structural_approval = operator_approval_receipt(quarantine=parts.quarantine)

    release = evaluate_quarantine_release(
        quarantine=parts.quarantine,
        approval=structural_approval,
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
        current_lease_epoch=1,
    )

    assert release.status == "BLOCKED"
    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    )
