"""Contract tests for ADR-0025 approval ledger head."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.aegis_constants import APPROVAL_LEDGER_CONTRACT_VERSION
from aegis.execution.aegis_approval_ledger import (
    append_approval_ledger_entry,
    approval_ledger_genesis_head_checksum,
)
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerAppendResult,
    ApprovalLedgerHead,
    ApprovalLedgerHeadReason,
    LedgerEpochManifest,
    append_to_approval_ledger_head,
    approval_ledger_append_result_checksum,
    approval_ledger_head_checksum,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
    ledger_epoch_manifest_checksum,
    recompute_approval_ledger_append_result_checksum,
    recompute_approval_ledger_head_checksum,
    recompute_ledger_epoch_manifest_checksum,
    validate_approval_ledger_head,
)

_CTX = "a" * 64
_ADMISSION = "b" * 64


def test_build_head_empty_prefix() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    assert head.session_epoch == 1
    assert head.context_authority_checksum == _CTX
    assert head.latest_sequence_index == -1
    assert head.latest_entry_checksum == approval_ledger_genesis_head_checksum()
    assert head.genesis_checksum == approval_ledger_genesis_head_checksum()
    assert head.ledger_contract_version == APPROVAL_LEDGER_CONTRACT_VERSION
    assert head.head_checksum == recompute_approval_ledger_head_checksum(head)


def test_build_head_with_one_entry() -> None:
    release = quarantine_release_decision(request_id="head-contract-one-entry")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    head = build_approval_ledger_head(
        session_epoch=3,
        context_authority_checksum=_CTX,
        prior_entries=(entry,),
    )
    assert head.latest_sequence_index == 0
    assert head.latest_entry_checksum == entry.entry_checksum
    assert head.head_checksum == recompute_approval_ledger_head_checksum(head)


def test_direct_head_construction_blocked() -> None:
    genesis = approval_ledger_genesis_head_checksum()
    reason = ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION
    with pytest.raises(ValueError, match=reason):
        ApprovalLedgerHead(
            ledger_contract_version=APPROVAL_LEDGER_CONTRACT_VERSION,
            session_epoch=1,
            latest_sequence_index=-1,
            latest_entry_checksum=genesis,
            genesis_checksum=genesis,
            context_authority_checksum=_CTX,
        )


def test_direct_append_result_construction_blocked() -> None:
    release = quarantine_release_decision(request_id="head-contract-direct-append")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(entry,),
    )
    from aegis.execution.aegis_approval_ledger import validate_approval_ledger_chain

    chain = validate_approval_ledger_chain((entry,))
    reason = ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION
    with pytest.raises(ValueError, match=reason):
        ApprovalLedgerAppendResult(
            new_entry=entry,
            new_head=head,
            chain_validation=chain,
        )


def test_head_checksum_recomputation_stable() -> None:
    head = build_approval_ledger_head(
        session_epoch=7,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    assert recompute_approval_ledger_head_checksum(head) == head.head_checksum
    recomputed = recompute_approval_ledger_head_checksum(head)
    assert recomputed == recompute_approval_ledger_head_checksum(head)


def test_append_to_head_basic() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    release = quarantine_release_decision(request_id="head-contract-append-basic")
    result = append_to_approval_ledger_head(
        prior_entries=(),
        head=head,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert isinstance(result, ApprovalLedgerAppendResult)
    assert result.new_entry.sequence_index == 0
    assert result.new_head.latest_sequence_index == 0
    assert result.new_head.latest_entry_checksum == result.new_entry.entry_checksum
    assert result.chain_validation.status == "VALID"
    assert result.append_result_checksum == recompute_approval_ledger_append_result_checksum(result)


def test_append_result_checksum_matches_public_function() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    release = quarantine_release_decision(request_id="head-contract-append-checksum")
    result = append_to_approval_ledger_head(
        prior_entries=(),
        head=head,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    computed = approval_ledger_append_result_checksum(
        new_entry_checksum=result.new_entry.entry_checksum,
        new_head_checksum=result.new_head.head_checksum,
        chain_validation_checksum=result.chain_validation.ledger_validation_checksum,
    )
    assert computed == result.append_result_checksum


def test_head_checksum_public_function_matches_head_field() -> None:
    head = build_approval_ledger_head(
        session_epoch=2,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    computed = approval_ledger_head_checksum(
        ledger_contract_version=head.ledger_contract_version,
        session_epoch=head.session_epoch,
        latest_sequence_index=head.latest_sequence_index,
        latest_entry_checksum=head.latest_entry_checksum,
        genesis_checksum=head.genesis_checksum,
        context_authority_checksum=head.context_authority_checksum,
    )
    assert computed == head.head_checksum


def test_build_ledger_epoch_manifest() -> None:
    manifest = build_ledger_epoch_manifest(
        session_epoch=5,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    assert isinstance(manifest, LedgerEpochManifest)
    assert manifest.session_epoch == 5
    assert manifest.context_authority_checksum == _CTX
    assert manifest.backend_admission_checksum == _ADMISSION
    assert manifest.manifest_checksum == recompute_ledger_epoch_manifest_checksum(manifest)


def test_epoch_manifest_checksum_matches_public_function() -> None:
    manifest = build_ledger_epoch_manifest(
        session_epoch=5,
        context_authority_checksum=_CTX,
        backend_admission_checksum=_ADMISSION,
    )
    computed = ledger_epoch_manifest_checksum(
        manifest_id=manifest.manifest_id,
        session_epoch=manifest.session_epoch,
        context_authority_checksum=manifest.context_authority_checksum,
        backend_admission_checksum=manifest.backend_admission_checksum,
    )
    assert computed == manifest.manifest_checksum


def test_validate_head_valid_empty_prefix() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "VALID"
    assert result.reason_code == ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_VALID


def test_validate_head_blocked_stale_epoch() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=2,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_STALE_EPOCH


def test_validate_head_blocked_context_drift() -> None:
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(),
    )
    different_ctx = "c" * 64
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=different_ctx,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == (
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_CONTEXT_AUTHORITY_DRIFT
    )


def test_validate_head_blocked_tip_mismatch() -> None:
    release = quarantine_release_decision(request_id="head-contract-tip-mismatch")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=_CTX,
        prior_entries=(entry,),
    )
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"


def test_build_head_rejects_invalid_prior_chain() -> None:
    release = quarantine_release_decision(request_id="head-contract-invalid-prior")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    with pytest.raises(ValueError):
        build_approval_ledger_head(
            session_epoch=1,
            context_authority_checksum=_CTX,
            prior_entries=(entry, entry),
        )
