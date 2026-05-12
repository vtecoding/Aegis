"""Invariant tests for ADR-0027 approval-ledger repository boundary."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_repository import (
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
    return repository, head, manifest, snapshot, evidence


@given(
    st.text(min_size=1, max_size=32, alphabet=st.characters(min_codepoint=97, max_codepoint=122))
)
@settings(max_examples=15)
def test_invariant_same_input_produces_same_transition_checksum(request_suffix: str) -> None:
    repository_a, _, _, snapshot_a, evidence_a = _baseline()
    repository_b, _, _, snapshot_b, evidence_b = _baseline()
    release = quarantine_release_decision(request_id=f"repository-invariant-{request_suffix}")
    transition_a = repository_a.propose_append(
        previous_snapshot=snapshot_a,
        release_decision=release,
        authority_evidence=evidence_a,
    )
    transition_b = repository_b.propose_append(
        previous_snapshot=snapshot_b,
        release_decision=release,
        authority_evidence=evidence_b,
    )
    assert transition_a.state_transition_checksum == transition_b.state_transition_checksum


def test_invariant_blocked_commit_does_not_mutate_current_snapshot() -> None:
    repository, _, _, snapshot, evidence = _baseline()
    transition = repository.propose_append(
        previous_snapshot=snapshot,
        release_decision=quarantine_release_decision(request_id="repository-invariant-mutation"),
        authority_evidence=evidence,
    )
    baseline_checksum = repository.current_snapshot.state_snapshot_checksum
    blocked = repository.commit_transition(
        transition=transition,
        expected_previous_snapshot_checksum="f" * 64,
    )
    assert blocked.status == "BLOCKED"
    assert repository.current_snapshot.state_snapshot_checksum == baseline_checksum
