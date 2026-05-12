"""Adversarial tests for ADR-0024 approval ledger tamper resistance."""

from __future__ import annotations

from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerReason,
    append_approval_ledger_entry,
    approval_ledger_prior_chain_block_reason,
    approval_ledger_prior_chain_quarantine_block_reason,
    validate_approval_ledger_chain,
)
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason


def test_non_tuple_prior_maps_to_runtime_object_injection() -> None:
    reason = approval_ledger_prior_chain_quarantine_block_reason([])
    assert reason is CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION


def test_non_ledger_entry_in_tuple_maps_to_runtime_object_injection() -> None:
    reason = approval_ledger_prior_chain_quarantine_block_reason((object(),))
    assert reason is CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION


def test_reordered_chain_fails_validation() -> None:
    r0 = quarantine_release_decision(request_id="ledger-tamper-order-a")
    r1 = quarantine_release_decision(request_id="ledger-tamper-order-b")
    e0 = append_approval_ledger_entry(
        prior_entries=(),
        release_status=r0.status,
        release_decision_checksum=r0.decision_checksum,
    )
    e1 = append_approval_ledger_entry(
        prior_entries=(e0,),
        release_status=r1.status,
        release_decision_checksum=r1.decision_checksum,
    )
    result = validate_approval_ledger_chain((e1, e0))
    assert result.status == "BLOCKED"
    assert result.reason_code == ApprovalLedgerReason.APPROVAL_LEDGER_SEQUENCE_INVALID.value


def test_duplicate_tail_entry_fails_chain() -> None:
    release = quarantine_release_decision(request_id="ledger-tamper-dup")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    assert (
        approval_ledger_prior_chain_block_reason((entry, entry))
        is ApprovalLedgerReason.APPROVAL_LEDGER_SEQUENCE_INVALID
    )
