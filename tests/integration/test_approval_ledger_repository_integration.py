"""Integration tests for ADR-0027 approval-ledger repository CAS semantics."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_repository import (
    ApprovalLedgerRepositoryReason,
    InMemoryApprovalLedgerRepository,
    build_approval_ledger_repository_authority_evidence,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"


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
    return repository, head, manifest, snapshot


def test_read_current_state_returns_detached_snapshot() -> None:
    repository, _, manifest, snapshot = _baseline()
    detached = repository.read_current_state(manifest)
    assert detached is not snapshot
    assert detached.state_snapshot_checksum == snapshot.state_snapshot_checksum


def test_current_snapshot_returns_detached_snapshot() -> None:
    repository, _, _, snapshot = _baseline()
    detached = repository.current_snapshot
    assert detached is not snapshot
    assert detached.state_snapshot_checksum == snapshot.state_snapshot_checksum


def test_current_head_returns_detached_head() -> None:
    repository, head, _, _ = _baseline()
    detached = repository.current_head
    assert detached is not head
    assert detached.head_checksum == head.head_checksum


def test_repository_commit_still_accepts_valid_transition_after_detached_reads() -> None:
    repository, head, manifest, snapshot = _baseline()
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=quarantine_release_decision(request_id="repository-integration-positive"),
        authority_evidence=evidence,
    )
    result = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert result.status == "COMMITTED"
    assert repository.current_snapshot.state_snapshot_checksum == result.committed_snapshot_checksum


def test_repository_cas_still_rejects_stale_transition_after_detached_reads() -> None:
    repository, head, manifest, snapshot = _baseline()
    detached_snapshot = repository.read_current_state(manifest)
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    first = repository.propose_append(
        previous_snapshot=detached_snapshot,
        release_decision=quarantine_release_decision(request_id="repository-integration-lost-1"),
        authority_evidence=evidence,
    )
    commit_first = repository.commit_transition(
        transition=first,
        expected_previous_snapshot_checksum=detached_snapshot.state_snapshot_checksum,
    )
    assert commit_first.status == "COMMITTED"
    stale = repository.commit_transition(
        transition=first,
        expected_previous_snapshot_checksum=detached_snapshot.state_snapshot_checksum,
    )
    assert stale.status == "BLOCKED"
    assert (
        stale.reason_code == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE
    )


def test_object_setattr_on_returned_state_does_not_mutate_repository() -> None:
    repository, _, manifest, _ = _baseline()
    detached = repository.read_current_state(manifest)
    object.__setattr__(detached, "latest_sequence_index", 999)
    assert repository.read_current_state(manifest).latest_sequence_index == -1


def test_object_setattr_on_returned_snapshot_does_not_mutate_repository() -> None:
    repository, _, _, _ = _baseline()
    detached = repository.current_snapshot
    object.__setattr__(detached, "latest_sequence_index", 888)
    assert repository.current_snapshot.latest_sequence_index == -1


def test_object_setattr_on_returned_head_does_not_mutate_repository() -> None:
    repository, _, _, _ = _baseline()
    detached = repository.current_head
    object.__setattr__(detached, "latest_sequence_index", 777)
    assert repository.current_head.latest_sequence_index == -1


def test_mutated_returned_read_object_cannot_be_committed_as_valid_state_without_validation() -> (
    None
):
    repository, head, manifest, _ = _baseline()
    detached = repository.read_current_state(manifest)
    object.__setattr__(detached, "latest_sequence_index", 500)
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    with pytest.raises(ValueError):
        repository.propose_append(
            previous_snapshot=detached,
            release_decision=quarantine_release_decision(
                request_id="repository-integration-mutated-read-object"
            ),
            authority_evidence=evidence,
        )


def test_cross_epoch_read_is_rejected() -> None:
    repository, _, _, _ = _baseline()
    wrong_manifest = build_ledger_epoch_manifest(
        session_epoch=2,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    try:
        repository.read_current_state(wrong_manifest)
    except ValueError as exc:
        assert (
            str(exc)
            == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED
        )
    else:
        raise AssertionError("expected cross-epoch read to fail")


def test_read_current_state_rejects_runtime_object_injection() -> None:
    repository, _, _, _ = _baseline()
    with pytest.raises(ValueError) as exc_info:
        repository.read_current_state(object())
    assert (
        str(exc_info.value)
        == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
    )


def test_read_current_state_rejects_tampered_manifest_checksum() -> None:
    repository, _, manifest, _ = _baseline()
    object.__setattr__(manifest, "manifest_checksum", "f" * 64)
    with pytest.raises(ValueError) as exc_info:
        repository.read_current_state(manifest)
    assert (
        str(exc_info.value)
        == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT
    )
