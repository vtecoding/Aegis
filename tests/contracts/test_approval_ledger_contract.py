"""Contract tests for ADR-0024 approval ledger."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerChainValidationResult,
    ApprovalLedgerEntry,
    ApprovalLedgerReason,
    append_approval_ledger_entry,
    approval_ledger_chain_validation_checksum,
    approval_ledger_entry_checksum,
    approval_ledger_genesis_head_checksum,
    approval_ledger_prior_chain_block_reason,
    recompute_approval_ledger_chain_validation_checksum,
    recompute_approval_ledger_entry_checksum,
    validate_approval_ledger_chain,
)


def test_genesis_head_is_deterministic() -> None:
    assert approval_ledger_genesis_head_checksum() == approval_ledger_genesis_head_checksum()


def test_append_emits_linked_entry() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-release")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert entry.sequence_index == 0
    assert entry.prior_entry_checksum == approval_ledger_genesis_head_checksum()
    assert entry.release_decision_checksum == release.decision_checksum
    assert entry.entry_checksum == recompute_approval_ledger_entry_checksum(entry)


def test_append_rejects_blocked_release_status() -> None:
    from tests.operator_authority_fixtures import operator_authority_parts

    from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release

    parts = operator_authority_parts(request_id="ledger-contract-blocked-release")
    blocked = evaluate_quarantine_release(
        quarantine=parts.quarantine,
        approval=None,
        capability_lease=parts.capability_lease,
        dispatch_plan=parts.dispatch_plan,
        backend_admission_decision=parts.backend_admission_decision,
        backend_descriptor=parts.backend_descriptor,
        authority_manifest=parts.backend_authority_manifest,
        registry_checksum=parts.backend_registry.registry_checksum,
        backend_certification=parts.backend_certification,
        backend_replay_proof=parts.backend_replay_proof,
        firewall_decision=parts.firewall_decision,
        context_authority_checksum=parts.context_authority.context_checksum,
        current_lease_epoch=1,
    )
    assert blocked.status == "BLOCKED"
    with pytest.raises(
        ValueError, match=ApprovalLedgerReason.APPROVAL_LEDGER_RELEASE_STATUS_INVALID.value
    ):
        append_approval_ledger_entry(
            prior_entries=(),
            release_status=blocked.status,
            release_decision_checksum=blocked.decision_checksum,
        )


def test_direct_entry_construction_blocked() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-direct-entry")
    with pytest.raises(
        ValueError, match=ApprovalLedgerReason.DIRECT_APPROVAL_LEDGER_ENTRY_CONSTRUCTION.value
    ):
        ApprovalLedgerEntry(
            sequence_index=0,
            prior_entry_checksum=approval_ledger_genesis_head_checksum(),
            release_decision_checksum=release.decision_checksum,
        )


def test_direct_valid_chain_validation_blocked() -> None:
    tip = approval_ledger_genesis_head_checksum()
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerReason.DIRECT_APPROVAL_LEDGER_CHAIN_VALIDATION_CONSTRUCTION.value,
    ):
        ApprovalLedgerChainValidationResult(
            status="VALID",
            reason_code=ApprovalLedgerReason.APPROVAL_LEDGER_VALID.value,
            chain_depth=0,
            chain_tip_checksum=tip,
        )


def test_validate_chain_blocked_emits_stable_checksum() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-blocked-validation")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    result = validate_approval_ledger_chain((entry, entry))
    assert result.status == "BLOCKED"
    assert result.ledger_validation_checksum == recompute_approval_ledger_chain_validation_checksum(
        result
    )


def test_approval_ledger_entry_checksum_matches_public_function() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-public-checksum")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert (
        approval_ledger_entry_checksum(
            sequence_index=entry.sequence_index,
            prior_entry_checksum=entry.prior_entry_checksum,
            release_decision_checksum=entry.release_decision_checksum,
        )
        == entry.entry_checksum
    )


def test_chain_validation_checksum_matches_public_function() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-chain-checksum")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    validated = validate_approval_ledger_chain((entry,))
    assert validated.status == "VALID"
    assert (
        approval_ledger_chain_validation_checksum(
            status=validated.status,
            reason_code=validated.reason_code,
            chain_depth=validated.chain_depth,
            chain_tip_checksum=validated.chain_tip_checksum,
        )
        == validated.ledger_validation_checksum
    )


def test_append_rejects_invalid_prior_chain() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-append-invalid")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    with pytest.raises(ValueError):
        append_approval_ledger_entry(
            prior_entries=(entry, entry),
            release_status=release.status,
            release_decision_checksum=release.decision_checksum,
        )


def test_prior_chain_block_reason_none_for_valid_prefix() -> None:
    release = quarantine_release_decision(request_id="ledger-contract-prefix-ok")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert approval_ledger_prior_chain_block_reason((entry,)) is None
