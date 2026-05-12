"""Invariant tests for ADR-0024 approval ledger."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger import (
    append_approval_ledger_entry,
    approval_ledger_genesis_head_checksum,
    recompute_approval_ledger_chain_validation_checksum,
    validate_approval_ledger_chain,
)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=6)
def test_invariant_genesis_head_stable(request_number: int) -> None:
    first = approval_ledger_genesis_head_checksum()
    second = approval_ledger_genesis_head_checksum()
    assert first == second
    assert request_number >= 1


def test_invariant_chain_validation_checksum_stable_for_valid_chain() -> None:
    release = quarantine_release_decision(request_id="ledger-invariant-validation")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )
    first = validate_approval_ledger_chain((entry,))
    second = validate_approval_ledger_chain((entry,))
    assert first.ledger_validation_checksum == second.ledger_validation_checksum
    assert first.ledger_validation_checksum == recompute_approval_ledger_chain_validation_checksum(
        first
    )
