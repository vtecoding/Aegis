"""Integration tests from ADR-0021 leases to ADR-0022 quarantine."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import command_quarantine_parts

from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineReason,
    quarantine_item_checksums,
    quarantine_items_from_dispatch_plan,
    quarantine_runtime_command,
)
from aegis.execution.aegis_operator_approval import build_operator_approval_receipt
from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release


def test_valid_lease_creates_quarantined_envelope() -> None:
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
    ) = command_quarantine_parts(request_id="lease-to-quarantine-positive")

    quarantine = quarantine_runtime_command(
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
        quarantine_epoch=1,
        current_lease_epoch=1,
    )

    assert quarantine.quarantine_status.value == "QUARANTINED"
    assert quarantine.quarantined_items == quarantine_items_from_dispatch_plan(dispatch_plan)


def test_missing_invalid_or_revoked_lease_blocks_quarantine() -> None:
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
    ) = command_quarantine_parts(request_id="lease-to-quarantine-invalid")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        quarantine_runtime_command(
            dispatch_plan=dispatch_plan,
            backend_admission_decision=backend_admission_decision,
            capability_lease=None,
            backend_descriptor=backend_descriptor,
            authority_manifest=authority_manifest,
            registry_checksum=backend_registry.registry_checksum,
            backend_certification=backend_certification,
            backend_replay_proof=backend_replay_proof,
            firewall_decision=firewall_decision,
            context_authority_checksum=context_authority.context_checksum,
            quarantine_epoch=1,
            current_lease_epoch=1,
        )
    object.__setattr__(capability_lease, "lease_checksum", "1" * 64)
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT.value
    ):
        quarantine_runtime_command(
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
            quarantine_epoch=1,
            current_lease_epoch=1,
        )


def test_approval_releases_only_dry_run_intent() -> None:
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
    ) = command_quarantine_parts(request_id="lease-to-quarantine-release")
    quarantine = quarantine_runtime_command(
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
        quarantine_epoch=1,
        current_lease_epoch=1,
    )
    approval = build_operator_approval_receipt(
        quarantine=quarantine,
        operator_id="operator-001",
        approval_status="APPROVED",
        approved_scope=quarantine_item_checksums(quarantine),
        approval_epoch=1,
        approval_reason="approve dry run",
    )

    release = evaluate_quarantine_release(
        quarantine=quarantine,
        approval=approval,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert release.status == "RELEASED_DRY_RUN"
    assert release.released_item_count == len(dispatch_plan.dispatch_items)
