"""Adversarial tests for ADR-0026 approval ledger state tamper resistance."""

from __future__ import annotations

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
    build_approval_ledger_state_snapshot,
    build_approval_ledger_state_transition,
    validate_approval_ledger_state_snapshot,
    validate_approval_ledger_state_transition,
)

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"


def _manifest(*, epoch: int = 1):
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


def _snapshot(*, epoch: int = 1, entries: tuple = (), source: str = _SOURCE):
    return build_approval_ledger_state_snapshot(
        ledger_head=_head(epoch=epoch, entries=entries),
        ledger_epoch_manifest=_manifest(epoch=epoch),
        state_source_id=source,
    )


def test_old_valid_snapshot_replayed_as_current_is_blocked() -> None:
    release = quarantine_release_decision(request_id="state-tamper-stale")
    e0 = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    stale_snapshot = _snapshot(entries=())
    result = validate_approval_ledger_state_snapshot(
        state_snapshot=stale_snapshot,
        ledger_head=_head(entries=(e0,)),
        ledger_epoch_manifest=_manifest(),
        expected_state_source_id=_SOURCE,
    )
    assert result.status == "BLOCKED"


def test_snapshot_with_wrong_epoch_is_blocked() -> None:
    snapshot = _snapshot(epoch=1)
    result = validate_approval_ledger_state_snapshot(
        state_snapshot=snapshot,
        ledger_head=_head(epoch=2),
        ledger_epoch_manifest=_manifest(epoch=2),
        expected_state_source_id=_SOURCE,
    )
    assert result.status == "BLOCKED"
    assert result.reason in {
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_HEAD_MISMATCH,
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_EPOCH_MISMATCH,
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT,
    }


def test_snapshot_with_wrong_context_authority_is_blocked() -> None:
    snapshot = _snapshot()
    drift_manifest = build_ledger_epoch_manifest(
        session_epoch=1,
        context_authority_checksum="f" * 64,
        backend_admission_checksum=_ADMISSION,
    )
    result = validate_approval_ledger_state_snapshot(
        state_snapshot=snapshot,
        ledger_head=_head(),
        ledger_epoch_manifest=drift_manifest,
        expected_state_source_id=_SOURCE,
    )
    assert result.status == "BLOCKED"


def test_source_drift_and_unsupported_source_values_block() -> None:
    snapshot = _snapshot()
    drift = validate_approval_ledger_state_snapshot(
        state_snapshot=snapshot,
        ledger_head=_head(),
        ledger_epoch_manifest=_manifest(),
        expected_state_source_id="other-authority",
    )
    assert drift.status == "BLOCKED"
    with pytest.raises(ValueError):
        build_approval_ledger_state_snapshot(
            ledger_head=_head(),
            ledger_epoch_manifest=_manifest(),
            state_source_id="",
        )
    with pytest.raises(ValueError):
        build_approval_ledger_state_snapshot(
            ledger_head=_head(),
            ledger_epoch_manifest=_manifest(),
            state_source_id="x" * 129,
        )
    with pytest.raises(ValueError):
        build_approval_ledger_state_snapshot(
            ledger_head=_head(),
            ledger_epoch_manifest=_manifest(),
            state_source_id=["mutable-list"],
        )


def test_mutable_and_callable_runtime_injection_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_approval_ledger_state_snapshot(
            ledger_head=_head(),
            ledger_epoch_manifest=_manifest(),
            state_source_id=lambda: _SOURCE,
        )
    result = validate_approval_ledger_state_snapshot(
        state_snapshot=object(),
        ledger_head=_head(),
        ledger_epoch_manifest=_manifest(),
    )
    assert result.status == "BLOCKED"
    assert result.reason == ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION


def test_transition_skip_and_rollback_are_blocked() -> None:
    release = quarantine_release_decision(request_id="state-tamper-transition")
    head0 = _head()
    manifest = _manifest()
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
        validate_approval_ledger_state_transition(
            transition=transition,
            previous_snapshot=snapshot0,
            append_result=append,
            new_snapshot=snapshot1,
        ).status
        == "VALID"
    )
    object.__setattr__(snapshot1, "latest_sequence_index", snapshot0.latest_sequence_index)
    rollback = validate_approval_ledger_state_transition(
        transition=transition,
        previous_snapshot=snapshot0,
        append_result=append,
        new_snapshot=snapshot1,
    )
    assert rollback.status == "BLOCKED"
