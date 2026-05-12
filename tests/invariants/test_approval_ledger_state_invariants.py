"""Invariant tests for ADR-0026 approval ledger state boundary."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger_head import (
    append_to_approval_ledger_head,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_state import (
    build_approval_ledger_state_snapshot,
    build_approval_ledger_state_transition,
    recompute_approval_ledger_state_snapshot_checksum,
    recompute_approval_ledger_state_transition_checksum,
    validate_approval_ledger_state_transition,
)

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"


@given(st.integers(min_value=0, max_value=16))
@settings(max_examples=20)
def test_invariant_genesis_snapshot_checksum_is_stable(epoch: int) -> None:
    head = build_approval_ledger_head(
        session_epoch=epoch,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    manifest = build_ledger_epoch_manifest(
        session_epoch=epoch,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    first = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    second = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    assert first.state_snapshot_checksum == second.state_snapshot_checksum
    assert first.state_snapshot_checksum == recompute_approval_ledger_state_snapshot_checksum(first)


def test_invariant_field_mutation_changes_snapshot_checksum() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    manifest = build_ledger_epoch_manifest(
        session_epoch=1,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    baseline = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    changed = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=f"{_SOURCE}-changed",
    )
    assert baseline.state_snapshot_checksum != changed.state_snapshot_checksum


def test_invariant_transition_checksum_is_stable() -> None:
    release = quarantine_release_decision(request_id="state-invariant-transition")
    head0 = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    manifest = build_ledger_epoch_manifest(
        session_epoch=1,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
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
    t1 = build_approval_ledger_state_transition(
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    t2 = build_approval_ledger_state_transition(
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    assert t1.state_transition_checksum == t2.state_transition_checksum
    assert t1.state_transition_checksum == recompute_approval_ledger_state_transition_checksum(t1)


def test_invariant_append_n_then_n_plus_1_cannot_validate_as_n_plus_2() -> None:
    release = quarantine_release_decision(request_id="state-invariant-n-n1")
    head0 = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    manifest = build_ledger_epoch_manifest(
        session_epoch=1,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
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
    object.__setattr__(snapshot1, "latest_sequence_index", 2)
    result = validate_approval_ledger_state_transition(
        transition=transition,
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    assert result.status == "BLOCKED"
