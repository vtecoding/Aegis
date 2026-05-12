"""Adversarial tests for ADR-0027 approval-ledger repository tamper resistance."""

from __future__ import annotations

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
    evidence = build_approval_ledger_repository_authority_evidence(
        prior_entries=(),
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    return repository, snapshot, evidence


def test_commit_without_proposal_is_blocked() -> None:
    repository, snapshot, _ = _baseline()
    blocked = repository.commit_transition(
        transition=object(),
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code
        == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
    )


def test_forged_transition_checksum_is_blocked() -> None:
    repository, snapshot, evidence = _baseline()
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=quarantine_release_decision(request_id="repository-adversarial-forged"),
        authority_evidence=evidence,
    )
    object.__setattr__(transition, "state_transition_checksum", "f" * 64)
    blocked = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code
        == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_FORGED_APPEND_RESULT
    )


def test_repository_unavailable_still_blocks() -> None:
    repository, snapshot, evidence = _baseline()
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=quarantine_release_decision(
            request_id="repository-adversarial-unavailable"
        ),
        authority_evidence=evidence,
    )
    repository.set_repository_availability(False)
    blocked = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum=snapshot.state_snapshot_checksum,
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code == ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE
    )
