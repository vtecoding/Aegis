"""Invariant tests for ADR-0025 approval ledger head."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger_head import (
    append_to_approval_ledger_head,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
    recompute_approval_ledger_append_result_checksum,
    recompute_approval_ledger_head_checksum,
    recompute_ledger_epoch_manifest_checksum,
)

_CTX = "a" * 64
_ADMISSION = "b" * 64


@given(st.integers(min_value=0, max_value=100))
@settings(max_examples=10)
def test_invariant_head_checksum_deterministic(session_epoch: int) -> None:
    head1 = build_approval_ledger_head(
        session_epoch=session_epoch,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    head2 = build_approval_ledger_head(
        session_epoch=session_epoch,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    assert head1.head_checksum == head2.head_checksum
    assert recompute_approval_ledger_head_checksum(head1) == head1.head_checksum


@given(st.integers(min_value=0, max_value=100))
@settings(max_examples=10)
def test_invariant_epoch_manifest_checksum_deterministic(session_epoch: int) -> None:
    m1 = build_ledger_epoch_manifest(
        session_epoch=session_epoch,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    m2 = build_ledger_epoch_manifest(
        session_epoch=session_epoch,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    assert m1.manifest_checksum == m2.manifest_checksum
    assert recompute_ledger_epoch_manifest_checksum(m1) == m1.manifest_checksum


def test_invariant_append_result_checksum_deterministic() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    release = quarantine_release_decision(request_id="head-invariant-append-result")
    result1 = append_to_approval_ledger_head(
        prior_entries=(),
        head=head,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    result2 = append_to_approval_ledger_head(
        prior_entries=(),
        head=head,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert result1.append_result_checksum == result2.append_result_checksum
    recomputed = recompute_approval_ledger_append_result_checksum(result1)
    assert recomputed == result1.append_result_checksum


def test_invariant_head_grows_monotonically() -> None:
    head0 = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    assert head0.latest_sequence_index == -1

    release1 = quarantine_release_decision(request_id="head-invariant-grow-r1")
    result1 = append_to_approval_ledger_head(
        prior_entries=(),
        head=head0,
        release_status=release1.status,
        release_decision_checksum=release1.decision_checksum,
    )
    assert result1.new_head.latest_sequence_index == 0
    recomputed1 = recompute_approval_ledger_head_checksum(result1.new_head)
    assert result1.new_head.head_checksum == recomputed1

    release2 = quarantine_release_decision(request_id="head-invariant-grow-r2")
    result2 = append_to_approval_ledger_head(
        prior_entries=(result1.new_entry,),
        head=result1.new_head,
        release_status=release2.status,
        release_decision_checksum=release2.decision_checksum,
    )
    assert result2.new_head.latest_sequence_index == 1
    recomputed2 = recompute_approval_ledger_head_checksum(result2.new_head)
    assert result2.new_head.head_checksum == recomputed2


def test_invariant_chain_validation_stable_across_appends() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    release = quarantine_release_decision(request_id="head-invariant-chain-stable")
    result = append_to_approval_ledger_head(
        prior_entries=(),
        head=head,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert result.chain_validation.status == "VALID"
    assert result.chain_validation.chain_depth == 1
    assert result.chain_validation.chain_tip_checksum == result.new_entry.entry_checksum
