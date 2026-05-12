"""Invariant tests for ADR-0028 persistence boundary."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_persistence import (
    ApprovalLedgerPersistenceStatus,
    InMemoryApprovalLedgerPersistenceAdapter,
    build_approval_ledger_persistence_record,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"
_REPOSITORY_ID = "repo-alpha"


def _record(evaluation_time_ms: int):
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
    return build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=snapshot,
        state_source_id=_SOURCE,
        release_decision_checksums=(),
        evaluation_time_ms=evaluation_time_ms,
    )


@given(st.integers(min_value=1, max_value=10_000))
@settings(max_examples=20)
def test_invariant_canonical_serialization_is_deterministic(evaluation_time_ms: int) -> None:
    record_a = _record(evaluation_time_ms)
    record_b = _record(evaluation_time_ms)
    assert record_a.canonical_json == record_b.canonical_json
    assert record_a.checksum == record_b.checksum


def test_invariant_read_after_write_load_status_is_loaded() -> None:
    adapter = InMemoryApprovalLedgerPersistenceAdapter(repository_id=_REPOSITORY_ID)
    record = _record(1_000)
    receipt = adapter.persist_transition(persistence_record=record)
    assert receipt.status is ApprovalLedgerPersistenceStatus.PERSISTED
    load_result = adapter.load_current()
    assert load_result.status is ApprovalLedgerPersistenceStatus.LOADED
    assert load_result.persisted_payload_json == record.canonical_json
