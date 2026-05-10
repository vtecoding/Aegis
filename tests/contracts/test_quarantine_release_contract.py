"""Contract tests for ADR-0022 quarantine release decisions."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_command_quarantine import CommandQuarantineReason
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    recompute_quarantine_release_decision_checksum,
)


def test_quarantine_release_requires_approval_and_remains_dry_run() -> None:
    release = quarantine_release_decision(request_id="quarantine-release-contract")

    assert release.status == "RELEASED_DRY_RUN"
    assert release.reason_code == "COMMAND_QUARANTINE_RELEASED_DRY_RUN"
    assert release.released_item_count == 1
    assert not hasattr(release, "execute")
    assert not hasattr(release, "publish")
    assert release.decision_checksum == recompute_quarantine_release_decision_checksum(release)


def test_quarantine_release_decision_is_immutable_and_direct_release_is_blocked() -> None:
    release = quarantine_release_decision(request_id="quarantine-release-direct")

    with pytest.raises(FrozenInstanceError):
        release.released_item_count = 2
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.DIRECT_QUARANTINE_RELEASE_CONSTRUCTION.value
    ):
        QuarantineReleaseDecision(
            status="RELEASED_DRY_RUN",
            reason_code=release.reason_code,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            approval_replay_validation_checksum=release.approval_replay_validation_checksum,
            lease_checksum=release.lease_checksum,
            dispatch_plan_checksum=release.dispatch_plan_checksum,
            released_item_count=release.released_item_count,
        )


def test_blocked_quarantine_release_cannot_release_items() -> None:
    release = quarantine_release_decision(request_id="quarantine-release-blocked-contract")

    with pytest.raises(ValueError, match="cannot release items"):
        QuarantineReleaseDecision(
            status="BLOCKED",
            reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL.value,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            approval_replay_validation_checksum=release.approval_replay_validation_checksum,
            lease_checksum=release.lease_checksum,
            dispatch_plan_checksum=release.dispatch_plan_checksum,
            released_item_count=1,
        )


def test_quarantine_release_checksum_changes_on_bound_field_change() -> None:
    first = quarantine_release_decision(
        request_id="quarantine-release-checksum", quarantine_epoch=1
    )
    second = quarantine_release_decision(
        request_id="quarantine-release-checksum", quarantine_epoch=2
    )

    assert first.quarantine_checksum != second.quarantine_checksum
    assert first.approval_checksum != second.approval_checksum
    assert first.decision_checksum != second.decision_checksum


def test_rejected_approval_blocks_release() -> None:
    parts = operator_authority_parts(
        request_id="quarantine-release-rejected", approval_status="REJECTED"
    )
    from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release

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

    assert release.status == "BLOCKED"
    assert release.reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REJECTED.value
