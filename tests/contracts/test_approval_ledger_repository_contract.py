"""Contract tests for ADR-0027 approval-ledger repository boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_repository import (
    ApprovalLedgerRepositoryReason,
    InMemoryApprovalLedgerRepository,
    RepositoryCommitResult,
    build_approval_ledger_repository_authority_evidence,
    recompute_repository_commit_result_checksum,
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
    return head, manifest, snapshot


def _repository() -> InMemoryApprovalLedgerRepository:
    head, manifest, snapshot = _baseline()
    return InMemoryApprovalLedgerRepository(
        initial_snapshot=snapshot,
        initial_head=head,
        initial_prior_entries=(),
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )


def test_authority_evidence_is_checksum_bound() -> None:
    head, manifest, _ = _baseline()
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    assert evidence.authority_evidence_checksum != "0" * 64


def test_commit_result_is_immutable_and_checksum_bound() -> None:
    repository = _repository()
    head, manifest, snapshot = _baseline()
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=quarantine_release_decision(request_id="repository-contract-commit"),
        authority_evidence=evidence,
    )
    result = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert result.status == "COMMITTED"
    assert result.commit_result_checksum == recompute_repository_commit_result_checksum(result)
    with pytest.raises(FrozenInstanceError):
        result.status = "BLOCKED"


def test_committed_result_cannot_be_forged_directly() -> None:
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMIT_WITHOUT_CAS_PROOF,
    ):
        RepositoryCommitResult(
            status="COMMITTED",
            reason_code=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMITTED,
            expected_previous_snapshot_checksum="1" * 64,
            previous_snapshot_checksum="1" * 64,
            committed_snapshot_checksum="2" * 64,
            committed_transition_checksum="3" * 64,
            repository_epoch_manifest_checksum="4" * 64,
            expected_previous_snapshot_matched=True,
            transition_valid=True,
            new_snapshot_became_current=True,
            stale_write_rejected=True,
            fork_rejected=True,
            rollback_rejected=True,
            cross_epoch_rejected=True,
        )
