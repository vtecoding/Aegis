"""Adversarial tests for ADR-0028 persistence boundary fail-closed semantics."""

from __future__ import annotations

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_persistence import (
    ApprovalLedgerPersistenceStatus,
    InMemoryApprovalLedgerPersistenceAdapter,
    build_approval_ledger_persistence_record,
    load_and_recover_approval_ledger_state,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"
_REPOSITORY_ID = "repo-alpha"


def _record():
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
    snapshot = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    return build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=snapshot,
        state_source_id=_SOURCE,
        release_decision_checksums=(),
        evaluation_time_ms=1_000,
    )


def test_partial_write_is_detectable_and_recovery_blocks() -> None:
    record = _record()
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    adapter.set_partial_write_mode(True)
    receipt = adapter.persist_transition(persistence_record=record)
    assert receipt.status is ApprovalLedgerPersistenceStatus.NOT_PERSISTED
    recovered = load_and_recover_approval_ledger_state(
        adapter=adapter,
        expected_repository_id=_REPOSITORY_ID,
        expected_ledger_epoch=1,
        minimum_sequence=0,
        expected_head_checksum=record.head_checksum,
        expected_state_checksum=record.state_checksum,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.NOT_RECOVERED


def test_cross_repository_replay_is_rejected() -> None:
    record = _record()
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    adapter.persist_transition(persistence_record=record)
    recovered = load_and_recover_approval_ledger_state(
        adapter=adapter,
        expected_repository_id="repo-beta",
        expected_ledger_epoch=1,
        minimum_sequence=0,
        expected_head_checksum=record.head_checksum,
        expected_state_checksum=record.state_checksum,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.NOT_RECOVERED
    assert "CROSS_REPOSITORY_REPLAY" in recovered.reason


def test_adapter_unavailable_fails_closed() -> None:
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    adapter.set_availability(False)
    recovered = load_and_recover_approval_ledger_state(
        adapter=adapter,
        expected_repository_id=_REPOSITORY_ID,
        expected_ledger_epoch=1,
        minimum_sequence=0,
        expected_head_checksum="f" * 64,
        expected_state_checksum="e" * 64,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.NOT_RECOVERED
    assert "UNAVAILABLE" in recovered.reason


def test_persistence_recovery_rejects_head_fork_at_same_sequence() -> None:
    record = _record()
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    adapter.persist_transition(persistence_record=record)
    recovered = load_and_recover_approval_ledger_state(
        adapter=adapter,
        expected_repository_id=_REPOSITORY_ID,
        expected_ledger_epoch=1,
        minimum_sequence=record.sequence,
        expected_head_checksum="c" * 64,
        expected_state_checksum=record.state_checksum,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.NOT_RECOVERED
    assert "HEAD_FORK" in recovered.reason


def test_load_and_recover_rejects_non_adapter_runtime_object() -> None:
    record = _record()
    recovered = load_and_recover_approval_ledger_state(
        adapter=object(),
        expected_repository_id=_REPOSITORY_ID,
        expected_ledger_epoch=1,
        minimum_sequence=record.sequence,
        expected_head_checksum=record.head_checksum,
        expected_state_checksum=record.state_checksum,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.INVALID
    assert "RUNTIME_OBJECT_INJECTION" in recovered.reason
