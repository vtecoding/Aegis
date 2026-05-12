"""Integration tests for ADR-0028 persistence boundary."""

from __future__ import annotations

from tests.command_quarantine_fixtures import quarantine_release_decision

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
from aegis.execution.aegis_approval_ledger_repository import (
    InMemoryApprovalLedgerRepository,
    build_approval_ledger_repository_authority_evidence,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"
_REPOSITORY_ID = "repo-alpha"


def _baseline():
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
    repository = InMemoryApprovalLedgerRepository(
        initial_snapshot=snapshot,
        initial_head=head,
        initial_prior_entries=(),
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    release = quarantine_release_decision(request_id="persistence-integration")
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=release,
        authority_evidence=evidence,
    )
    commit = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert commit.status == "COMMITTED"
    return repository, manifest, release.decision_checksum


def test_read_after_write_recovery_consistency() -> None:
    repository, manifest, decision_checksum = _baseline()
    current = repository.current_snapshot
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    record = build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=current,
        state_source_id=_SOURCE,
        release_decision_checksums=(decision_checksum,),
        evaluation_time_ms=2_000,
    )
    receipt = adapter.persist_transition(persistence_record=record)
    assert receipt.status is ApprovalLedgerPersistenceStatus.PERSISTED
    recovered = load_and_recover_approval_ledger_state(
        adapter=adapter,
        expected_repository_id=_REPOSITORY_ID,
        expected_ledger_epoch=1,
        minimum_sequence=0,
        expected_head_checksum=current.ledger_head_checksum,
        expected_state_checksum=current.state_snapshot_checksum,
    )
    assert recovered.status is ApprovalLedgerPersistenceStatus.RECOVERED
    assert recovered.recovered_snapshot is not None
    assert recovered.recovered_snapshot.state_snapshot_checksum == current.state_snapshot_checksum


def test_failed_persist_does_not_mutate_repository_authority() -> None:
    repository, manifest, decision_checksum = _baseline()
    current_before = repository.current_snapshot
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    adapter.set_availability(False)
    record = build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=current_before,
        state_source_id=_SOURCE,
        release_decision_checksums=(decision_checksum,),
        evaluation_time_ms=2_100,
    )
    receipt = adapter.persist_transition(persistence_record=record)
    assert receipt.status is ApprovalLedgerPersistenceStatus.UNAVAILABLE
    current_after = repository.current_snapshot
    assert current_after.state_snapshot_checksum == current_before.state_snapshot_checksum
