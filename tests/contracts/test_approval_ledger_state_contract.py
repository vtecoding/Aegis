"""Contract tests for ADR-0026 approval ledger state boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger import append_approval_ledger_entry
from aegis.execution.aegis_approval_ledger_head import (
    append_to_approval_ledger_head,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_state import (
    ApprovalLedgerStateReason,
    ApprovalLedgerStateSnapshot,
    ApprovalLedgerStateTransition,
    LedgerStateValidationResult,
    append_to_approval_ledger_state,
    build_approval_ledger_state_snapshot,
    build_approval_ledger_state_transition,
    recompute_approval_ledger_state_snapshot_checksum,
    recompute_approval_ledger_state_transition_checksum,
    recompute_ledger_state_validation_checksum,
    validate_approval_ledger_state_snapshot,
    validate_approval_ledger_state_transition,
)

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"


def _epoch_manifest(*, epoch: int = 1):
    return build_ledger_epoch_manifest(
        session_epoch=epoch,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )


def _head(*, epoch: int = 1, entries: tuple = ()):
    return build_approval_ledger_head(
        session_epoch=epoch,
        context_authority_checksum=_CTX,
        prior_entries=entries,
    )


def test_snapshot_builder_is_immutable_and_checksum_bound() -> None:
    snapshot = build_approval_ledger_state_snapshot(
        ledger_head=_head(),
        ledger_epoch_manifest=_epoch_manifest(),
        state_source_id=_SOURCE,
    )
    assert snapshot.state_snapshot_checksum == recompute_approval_ledger_state_snapshot_checksum(
        snapshot
    )
    with pytest.raises(FrozenInstanceError):
        snapshot.state_source_id = "drifted"


def test_snapshot_direct_construction_is_blocked() -> None:
    manifest = _epoch_manifest()
    head = _head()
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_SNAPSHOT_CONSTRUCTION,
    ):
        ApprovalLedgerStateSnapshot(
            contract_version="approval-ledger-state-v1",
            ledger_epoch_manifest_checksum=manifest.manifest_checksum,
            ledger_head_checksum=head.head_checksum,
            latest_sequence_index=head.latest_sequence_index,
            latest_entry_checksum=head.latest_entry_checksum,
            genesis_checksum=head.genesis_checksum,
            context_authority_checksum=head.context_authority_checksum,
            backend_admission_checksum=manifest.backend_admission_checksum,
            state_source_id=_SOURCE,
        )


def test_transition_builder_is_checksum_bound_and_direct_construction_blocked() -> None:
    release = quarantine_release_decision(request_id="state-contract-transition")
    head0 = _head()
    manifest = _epoch_manifest()
    snapshot0 = build_approval_ledger_state_snapshot(
        ledger_head=head0,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    append = append_to_approval_ledger_head(
        prior_entries=(),
        head=head0,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    snapshot1 = build_approval_ledger_state_snapshot(
        ledger_head=append.new_head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    transition = build_approval_ledger_state_transition(
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    assert (
        transition.state_transition_checksum
        == recompute_approval_ledger_state_transition_checksum(transition)
    )
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_TRANSITION_CONSTRUCTION,
    ):
        ApprovalLedgerStateTransition(
            contract_version="approval-ledger-state-v1",
            previous_snapshot_checksum=snapshot0.state_snapshot_checksum,
            append_result_checksum=append.append_result_checksum,
            new_snapshot_checksum=snapshot1.state_snapshot_checksum,
            previous_sequence_index=snapshot0.latest_sequence_index,
            new_sequence_index=snapshot1.latest_sequence_index,
            previous_entry_checksum=snapshot0.latest_entry_checksum,
            new_entry_checksum=snapshot1.latest_entry_checksum,
            ledger_epoch_manifest_checksum=snapshot0.ledger_epoch_manifest_checksum,
            state_source_id=_SOURCE,
        )


def test_valid_state_validation_result_cannot_be_forged() -> None:
    snapshot = build_approval_ledger_state_snapshot(
        ledger_head=_head(),
        ledger_epoch_manifest=_epoch_manifest(),
        state_source_id=_SOURCE,
    )
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_VALIDATION_CONSTRUCTION,
    ):
        LedgerStateValidationResult(
            status="VALID",
            reason="APPROVAL_LEDGER_STATE_VALID",
            state_snapshot_checksum=snapshot.state_snapshot_checksum,
            ledger_head_checksum=snapshot.ledger_head_checksum,
            ledger_epoch_manifest_checksum=snapshot.ledger_epoch_manifest_checksum,
        )


def test_snapshot_and_transition_validation_results_are_checksum_bound() -> None:
    manifest = _epoch_manifest()
    head0 = _head()
    snapshot0 = build_approval_ledger_state_snapshot(
        ledger_head=head0,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    snapshot_validation = validate_approval_ledger_state_snapshot(
        state_snapshot=snapshot0,
        ledger_head=head0,
        ledger_epoch_manifest=manifest,
        expected_state_source_id=_SOURCE,
    )
    assert snapshot_validation.status == "VALID"
    assert snapshot_validation.validation_checksum == recompute_ledger_state_validation_checksum(
        snapshot_validation
    )

    release = quarantine_release_decision(request_id="state-contract-validation")
    append = append_to_approval_ledger_head(
        prior_entries=(),
        head=head0,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    snapshot1 = build_approval_ledger_state_snapshot(
        ledger_head=append.new_head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    transition = build_approval_ledger_state_transition(
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    transition_validation = validate_approval_ledger_state_transition(
        transition=transition,
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    assert transition_validation.status == "VALID"
    assert transition_validation.validation_checksum == recompute_ledger_state_validation_checksum(
        transition_validation
    )


def test_append_to_approval_ledger_state_returns_full_transition_evidence() -> None:
    manifest = _epoch_manifest()
    head0 = _head()
    snapshot0 = build_approval_ledger_state_snapshot(
        ledger_head=head0,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    release = quarantine_release_decision(request_id="state-contract-append-helper")
    entry, head1, append, snapshot1, transition, validation = append_to_approval_ledger_state(
        prior_entries=(),
        current_head=head0,
        current_state_snapshot=snapshot0,
        release_decision=release,
        ledger_epoch_manifest=manifest,
    )
    assert entry.sequence_index == 0
    assert head1.latest_sequence_index == 0
    assert append.new_entry.entry_checksum == entry.entry_checksum
    assert snapshot1.latest_entry_checksum == entry.entry_checksum
    assert transition.new_entry_checksum == entry.entry_checksum
    assert validation.status == "VALID"


def test_same_inputs_produce_same_snapshot_checksum() -> None:
    first = build_approval_ledger_state_snapshot(
        ledger_head=_head(),
        ledger_epoch_manifest=_epoch_manifest(),
        state_source_id=_SOURCE,
    )
    second = build_approval_ledger_state_snapshot(
        ledger_head=_head(),
        ledger_epoch_manifest=_epoch_manifest(),
        state_source_id=_SOURCE,
    )
    assert first.state_snapshot_checksum == second.state_snapshot_checksum


def test_snapshot_checksum_changes_when_tip_changes() -> None:
    release = quarantine_release_decision(request_id="state-contract-tip-change")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    manifest = _epoch_manifest()
    empty = build_approval_ledger_state_snapshot(
        ledger_head=_head(entries=()),
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    with_entry = build_approval_ledger_state_snapshot(
        ledger_head=_head(entries=(entry,)),
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    assert empty.state_snapshot_checksum != with_entry.state_snapshot_checksum
