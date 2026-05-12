"""Contract tests for ADR-0028 approval-ledger persistence boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_persistence import (
    ApprovalLedgerPersistenceReason,
    ApprovalLedgerPersistenceStatus,
    build_approval_ledger_persistence_record,
    deserialize_approval_ledger_persistence_record,
    recompute_approval_ledger_persistence_record_checksum,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot

_CTX = "a" * 64
_ADMISSION = "b" * 64
_SOURCE = "canonical-memory-authority"
_REPOSITORY_ID = "repo-alpha"


def _baseline() -> tuple[object, object, object]:
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
    return manifest, snapshot, ()


def test_persistence_record_is_checksum_bound_and_immutable() -> None:
    manifest, snapshot, release_checksums = _baseline()
    record = build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=snapshot,
        state_source_id=_SOURCE,
        release_decision_checksums=release_checksums,
        evaluation_time_ms=1_000,
    )
    assert record.checksum == recompute_approval_ledger_persistence_record_checksum(record)
    with pytest.raises(FrozenInstanceError):
        record.repository_id = "other"


def test_persistence_record_requires_canonical_json_round_trip() -> None:
    manifest, snapshot, release_checksums = _baseline()
    record = build_approval_ledger_persistence_record(
        repository_id=_REPOSITORY_ID,
        ledger_epoch_manifest=manifest,
        state_snapshot=snapshot,
        state_source_id=_SOURCE,
        release_decision_checksums=release_checksums,
        evaluation_time_ms=1_000,
    )
    loaded = deserialize_approval_ledger_persistence_record(record.canonical_json)
    assert loaded.checksum == record.checksum
    assert loaded.repository_id == _REPOSITORY_ID


def test_persistence_record_rejects_sequence_mismatch() -> None:
    manifest, snapshot, _ = _baseline()
    with pytest.raises(
        ValueError,
        match=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK,
    ):
        build_approval_ledger_persistence_record(
            repository_id=_REPOSITORY_ID,
            ledger_epoch_manifest=manifest,
            state_snapshot=snapshot,
            state_source_id=_SOURCE,
            release_decision_checksums=("c" * 64,),
            evaluation_time_ms=1_000,
        )


def test_deserialize_rejects_corrupt_json() -> None:
    with pytest.raises(
        ValueError, match=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CORRUPT
    ):
        deserialize_approval_ledger_persistence_record("{not-json")


def test_deserialize_rejects_missing_required_field() -> None:
    bad_payload = (
        '{"contract_version":"approval-ledger-persistence-v1","repository_id":"repo-alpha",'
        '"ledger_epoch":1,"head_checksum":"'
        + ("a" * 64)
        + '","state_checksum":"'
        + ("b" * 64)
        + '",'
        '"sequence":0,"evaluation_time_ms":1000,"state_source_id":"canonical-memory-authority",'
        '"context_authority_checksum":"'
        + ("c" * 64)
        + '","release_decision_checksums":["'
        + ("d" * 64)
        + '"]}'
    )
    with pytest.raises(
        ValueError, match=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_MALFORMED
    ):
        deserialize_approval_ledger_persistence_record(bad_payload)


def test_status_enum_contains_required_values() -> None:
    required = {
        "PERSISTED",
        "NOT_PERSISTED",
        "LOADED",
        "NOT_LOADED",
        "RECOVERED",
        "NOT_RECOVERED",
        "VALID",
        "INVALID",
        "CORRUPT",
        "STALE",
        "ROLLED_BACK",
        "FORKED",
        "UNAVAILABLE",
        "CHECKSUM_MISMATCH",
    }
    assert required.issubset({status.value for status in ApprovalLedgerPersistenceStatus})
