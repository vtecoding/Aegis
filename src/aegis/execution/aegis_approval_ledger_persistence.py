"""Deterministic approval-ledger persistence boundary contracts for ADR-0028."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

from aegis.aegis_constants import APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION
from aegis.execution.aegis_approval_ledger import ApprovalLedgerEntry, append_approval_ledger_entry
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerHead,
    LedgerEpochManifest,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_state import (
    ApprovalLedgerStateSnapshot,
    build_approval_ledger_state_snapshot,
    validate_approval_ledger_state_snapshot,
)
from aegis.execution.aegis_capability_lease import checksum_or_fallback

type CanonicalPersistenceValue = (
    str | int | bool | None | list[CanonicalPersistenceValue] | dict[str, CanonicalPersistenceValue]
)


class ApprovalLedgerPersistenceReason(StrEnum):
    """Stable ADR-0028 persistence reason codes."""

    APPROVAL_LEDGER_PERSISTENCE_PERSISTED = "APPROVAL_LEDGER_PERSISTENCE_PERSISTED"
    APPROVAL_LEDGER_PERSISTENCE_NOT_PERSISTED = "APPROVAL_LEDGER_PERSISTENCE_NOT_PERSISTED"
    APPROVAL_LEDGER_PERSISTENCE_LOADED = "APPROVAL_LEDGER_PERSISTENCE_LOADED"
    APPROVAL_LEDGER_PERSISTENCE_NOT_LOADED = "APPROVAL_LEDGER_PERSISTENCE_NOT_LOADED"
    APPROVAL_LEDGER_PERSISTENCE_RECOVERED = "APPROVAL_LEDGER_PERSISTENCE_RECOVERED"
    APPROVAL_LEDGER_PERSISTENCE_NOT_RECOVERED = "APPROVAL_LEDGER_PERSISTENCE_NOT_RECOVERED"
    APPROVAL_LEDGER_PERSISTENCE_VALID = "APPROVAL_LEDGER_PERSISTENCE_VALID"
    APPROVAL_LEDGER_PERSISTENCE_INVALID = "APPROVAL_LEDGER_PERSISTENCE_INVALID"
    APPROVAL_LEDGER_PERSISTENCE_CORRUPT = "APPROVAL_LEDGER_PERSISTENCE_CORRUPT"
    APPROVAL_LEDGER_PERSISTENCE_STALE = "APPROVAL_LEDGER_PERSISTENCE_STALE"
    APPROVAL_LEDGER_PERSISTENCE_ROLLED_BACK = "APPROVAL_LEDGER_PERSISTENCE_ROLLED_BACK"
    APPROVAL_LEDGER_PERSISTENCE_FORKED = "APPROVAL_LEDGER_PERSISTENCE_FORKED"
    APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE = "APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE"
    APPROVAL_LEDGER_PERSISTENCE_CHECKSUM_MISMATCH = "APPROVAL_LEDGER_PERSISTENCE_CHECKSUM_MISMATCH"
    APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION = (
        "APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION"
    )
    APPROVAL_LEDGER_PERSISTENCE_MALFORMED = "APPROVAL_LEDGER_PERSISTENCE_MALFORMED"
    APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE = "APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE"
    APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION_UNKNOWN = (
        "APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION_UNKNOWN"
    )
    APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY = (
        "APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY"
    )
    APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY = (
        "APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY"
    )
    APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK = "APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK"
    APPROVAL_LEDGER_PERSISTENCE_HEAD_FORK = "APPROVAL_LEDGER_PERSISTENCE_HEAD_FORK"
    APPROVAL_LEDGER_PERSISTENCE_STATE_CHECKSUM_MISMATCH = (
        "APPROVAL_LEDGER_PERSISTENCE_STATE_CHECKSUM_MISMATCH"
    )


class ApprovalLedgerPersistenceStatus(StrEnum):
    """Closed ADR-0028 status values."""

    PERSISTED = "PERSISTED"
    NOT_PERSISTED = "NOT_PERSISTED"
    LOADED = "LOADED"
    NOT_LOADED = "NOT_LOADED"
    RECOVERED = "RECOVERED"
    NOT_RECOVERED = "NOT_RECOVERED"
    VALID = "VALID"
    INVALID = "INVALID"
    CORRUPT = "CORRUPT"
    STALE = "STALE"
    ROLLED_BACK = "ROLLED_BACK"
    FORKED = "FORKED"
    UNAVAILABLE = "UNAVAILABLE"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"


@dataclass(frozen=True, slots=True)
class ApprovalLedgerPersistenceRecord:
    """Canonical persistence payload stored by deterministic adapters."""

    contract_version: str
    repository_id: str
    ledger_epoch: int
    head_checksum: str
    state_checksum: str
    sequence: int
    evaluation_time_ms: int
    state_source_id: str
    context_authority_checksum: str
    backend_admission_checksum: str
    release_decision_checksums: tuple[str, ...]
    canonical_json: str
    checksum: str


@dataclass(frozen=True, slots=True)
class ApprovalLedgerPersistenceReceipt:
    """Result of one persistence write attempt."""

    status: ApprovalLedgerPersistenceStatus
    reason: str
    contract_version: str
    repository_id: str
    ledger_epoch: int
    head_checksum: str
    state_checksum: str
    sequence: int
    evaluation_time_ms: int
    checksum: str


@dataclass(frozen=True, slots=True)
class ApprovalLedgerPersistenceLoadResult:
    """Result of loading persisted state from an adapter."""

    status: ApprovalLedgerPersistenceStatus
    reason: str
    contract_version: str
    repository_id: str
    ledger_epoch: int
    head_checksum: str
    state_checksum: str
    sequence: int
    evaluation_time_ms: int
    persisted_payload_json: str
    checksum: str


@dataclass(frozen=True, slots=True)
class ApprovalLedgerPersistenceValidationResult:
    """Validation result for one loaded persistence payload."""

    status: ApprovalLedgerPersistenceStatus
    reason: str
    contract_version: str
    repository_id: str
    ledger_epoch: int
    head_checksum: str
    state_checksum: str
    sequence: int
    evaluation_time_ms: int
    checksum: str


@dataclass(frozen=True, slots=True)
class ApprovalLedgerRecoveryResult:
    """Deterministic recovery result from persisted payload."""

    status: ApprovalLedgerPersistenceStatus
    reason: str
    contract_version: str
    repository_id: str
    ledger_epoch: int
    head_checksum: str
    state_checksum: str
    sequence: int
    evaluation_time_ms: int
    recovered_snapshot: ApprovalLedgerStateSnapshot | None
    recovered_head: ApprovalLedgerHead | None
    recovered_manifest: LedgerEpochManifest | None
    recovered_entries: tuple[ApprovalLedgerEntry, ...]
    checksum: str


@dataclass(frozen=True, slots=True)
class ApprovalLedgerPersistenceAdapterDescriptor:
    """Descriptor for a deterministic persistence adapter implementation."""

    adapter_id: str
    adapter_kind: str
    supports_persistence: bool
    supports_durable_storage: bool
    checksum: str


@runtime_checkable
class ApprovalLedgerPersistenceAdapter(Protocol):
    """Minimal deterministic persistence boundary for ADR-0028."""

    def load_current(self) -> ApprovalLedgerPersistenceLoadResult:
        """Load current persisted payload from adapter storage."""
        ...

    def persist_transition(self, *, persistence_record: object) -> ApprovalLedgerPersistenceReceipt:
        """Persist one canonical detached record."""
        ...


class InMemoryApprovalLedgerPersistenceAdapter:
    """Reference ADR-0028 in-memory persistence adapter."""

    def __init__(self, *, repository_id: object) -> None:
        self._repository_id = _normalize_required_text(repository_id, "repository_id")
        self._stored_record: ApprovalLedgerPersistenceRecord | None = None
        self._available = True
        self._simulate_partial_write = False

    def set_availability(self, value: object) -> None:
        """Set deterministic adapter availability for tests."""
        self._available = _normalize_bool(value, "available")

    def set_partial_write_mode(self, value: object) -> None:
        """Enable deterministic partial-write simulation for tests."""
        self._simulate_partial_write = _normalize_bool(value, "partial_write")

    @property
    def descriptor(self) -> ApprovalLedgerPersistenceAdapterDescriptor:
        """Return deterministic adapter descriptor."""
        return build_approval_ledger_persistence_adapter_descriptor(
            adapter_id=f"memory:{self._repository_id}",
            adapter_kind="IN_MEMORY",
            supports_persistence=True,
            supports_durable_storage=False,
        )

    def persist_transition(self, *, persistence_record: object) -> ApprovalLedgerPersistenceReceipt:
        """Persist one canonical detached record."""
        fallback = _record_fallback(
            repository_id=self._repository_id,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_NOT_PERSISTED,
            status=ApprovalLedgerPersistenceStatus.NOT_PERSISTED,
        )
        if not self._available:
            return _receipt_from_fallback(
                fallback=fallback,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE,
                status=ApprovalLedgerPersistenceStatus.UNAVAILABLE,
            )
        if type(persistence_record) is not ApprovalLedgerPersistenceRecord:
            return _receipt_from_fallback(
                fallback=fallback,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION,
                status=ApprovalLedgerPersistenceStatus.INVALID,
            )
        record = persistence_record
        if record.repository_id != self._repository_id:
            return _receipt_from_fallback(
                fallback=fallback,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY,
                status=ApprovalLedgerPersistenceStatus.INVALID,
            )
        if record.checksum != recompute_approval_ledger_persistence_record_checksum(record):
            return _receipt_from_fallback(
                fallback=fallback,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CHECKSUM_MISMATCH,
                status=ApprovalLedgerPersistenceStatus.CHECKSUM_MISMATCH,
            )
        if self._simulate_partial_write:
            partial_json = record.canonical_json[: max(1, len(record.canonical_json) // 2)]
            self._stored_record = ApprovalLedgerPersistenceRecord(
                contract_version=record.contract_version,
                repository_id=record.repository_id,
                ledger_epoch=record.ledger_epoch,
                head_checksum=record.head_checksum,
                state_checksum=record.state_checksum,
                sequence=record.sequence,
                evaluation_time_ms=record.evaluation_time_ms,
                state_source_id=record.state_source_id,
                context_authority_checksum=record.context_authority_checksum,
                backend_admission_checksum=record.backend_admission_checksum,
                release_decision_checksums=record.release_decision_checksums,
                canonical_json=partial_json,
                checksum=record.checksum,
            )
            return _receipt_from_fallback(
                fallback=_record_fallback_from_record(record),
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE,
                status=ApprovalLedgerPersistenceStatus.NOT_PERSISTED,
            )
        self._stored_record = record
        return _receipt_from_fallback(
            fallback=_record_fallback_from_record(record),
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_PERSISTED,
            status=ApprovalLedgerPersistenceStatus.PERSISTED,
        )

    def load_current(self) -> ApprovalLedgerPersistenceLoadResult:
        """Load current persisted payload from adapter storage."""
        if not self._available:
            return _load_result(
                status=ApprovalLedgerPersistenceStatus.UNAVAILABLE,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE,
                repository_id=self._repository_id,
            )
        if self._stored_record is None:
            return _load_result(
                status=ApprovalLedgerPersistenceStatus.NOT_LOADED,
                reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_NOT_LOADED,
                repository_id=self._repository_id,
            )
        return _load_result(
            status=ApprovalLedgerPersistenceStatus.LOADED,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_LOADED,
            repository_id=self._stored_record.repository_id,
            ledger_epoch=self._stored_record.ledger_epoch,
            head_checksum=self._stored_record.head_checksum,
            state_checksum=self._stored_record.state_checksum,
            sequence=self._stored_record.sequence,
            evaluation_time_ms=self._stored_record.evaluation_time_ms,
            payload_json=self._stored_record.canonical_json,
        )


def build_approval_ledger_persistence_record(
    *,
    repository_id: object,
    ledger_epoch_manifest: object,
    state_snapshot: object,
    state_source_id: object,
    release_decision_checksums: object,
    evaluation_time_ms: object,
) -> ApprovalLedgerPersistenceRecord:
    """Build canonical persisted record from detached canonical repository state."""
    manifest = _normalize_manifest(ledger_epoch_manifest)
    snapshot = _normalize_snapshot(state_snapshot)
    source_id = _normalize_required_text(state_source_id, "state_source_id")
    if snapshot.state_source_id != source_id:
        raise ValueError(ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_INVALID)
    if snapshot.ledger_epoch_manifest_checksum != manifest.manifest_checksum:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY
        )
    checksums = _normalize_release_checksums(release_decision_checksums)
    if len(checksums) != snapshot.latest_sequence_index + 1:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK
        )
    repo_id = _normalize_required_text(repository_id, "repository_id")
    eval_ms = _normalize_non_negative_int(evaluation_time_ms, "evaluation_time_ms")
    payload = {
        "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        "repository_id": repo_id,
        "ledger_epoch": manifest.session_epoch,
        "head_checksum": snapshot.ledger_head_checksum,
        "state_checksum": snapshot.state_snapshot_checksum,
        "sequence": snapshot.latest_sequence_index,
        "evaluation_time_ms": eval_ms,
        "state_source_id": source_id,
        "context_authority_checksum": snapshot.context_authority_checksum,
        "backend_admission_checksum": snapshot.backend_admission_checksum,
        "release_decision_checksums": list(checksums),
    }
    canonical_json = _canonical_json(payload)
    return ApprovalLedgerPersistenceRecord(
        contract_version=APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        repository_id=repo_id,
        ledger_epoch=manifest.session_epoch,
        head_checksum=snapshot.ledger_head_checksum,
        state_checksum=snapshot.state_snapshot_checksum,
        sequence=snapshot.latest_sequence_index,
        evaluation_time_ms=eval_ms,
        state_source_id=source_id,
        context_authority_checksum=snapshot.context_authority_checksum,
        backend_admission_checksum=snapshot.backend_admission_checksum,
        release_decision_checksums=checksums,
        canonical_json=canonical_json,
        checksum=approval_ledger_persistence_record_checksum(canonical_json=canonical_json),
    )


def load_and_recover_approval_ledger_state(
    *,
    adapter: object,
    expected_repository_id: object,
    expected_ledger_epoch: object,
    minimum_sequence: object,
    expected_head_checksum: object,
    expected_state_checksum: object,
) -> ApprovalLedgerRecoveryResult:
    """Load, validate, and recover canonical state from persistence adapter."""
    repository_id = _normalize_required_text(expected_repository_id, "expected_repository_id")
    expected_epoch = _normalize_non_negative_int(expected_ledger_epoch, "expected_ledger_epoch")
    minimum_seq = _normalize_sequence(minimum_sequence, "minimum_sequence")
    expected_head = _normalize_checksum(expected_head_checksum, "expected_head_checksum")
    expected_state = _normalize_checksum(expected_state_checksum, "expected_state_checksum")
    if not isinstance(adapter, ApprovalLedgerPersistenceAdapter):
        return _recovery_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION,
            repository_id=repository_id,
            ledger_epoch=expected_epoch,
            head_checksum=expected_head,
            state_checksum=expected_state,
            sequence=minimum_seq,
            evaluation_time_ms=0,
            recovered_snapshot=None,
            recovered_head=None,
            recovered_manifest=None,
            recovered_entries=(),
        )
    load_result = adapter.load_current()
    if load_result.status in {
        ApprovalLedgerPersistenceStatus.NOT_LOADED,
        ApprovalLedgerPersistenceStatus.UNAVAILABLE,
    }:
        return _recovery_result(
            status=ApprovalLedgerPersistenceStatus.NOT_RECOVERED,
            reason=load_result.reason,
            repository_id=repository_id,
            ledger_epoch=expected_epoch,
            head_checksum=expected_head,
            state_checksum=expected_state,
            sequence=minimum_seq,
            evaluation_time_ms=load_result.evaluation_time_ms,
            recovered_snapshot=None,
            recovered_head=None,
            recovered_manifest=None,
            recovered_entries=(),
        )
    validation = validate_approval_ledger_persistence_payload(
        load_result=load_result,
        expected_repository_id=repository_id,
        expected_ledger_epoch=expected_epoch,
        minimum_sequence=minimum_seq,
        expected_head_checksum=expected_head,
        expected_state_checksum=expected_state,
    )
    if validation.status is not ApprovalLedgerPersistenceStatus.VALID:
        return _recovery_result(
            status=ApprovalLedgerPersistenceStatus.NOT_RECOVERED,
            reason=validation.reason,
            repository_id=validation.repository_id,
            ledger_epoch=validation.ledger_epoch,
            head_checksum=validation.head_checksum,
            state_checksum=validation.state_checksum,
            sequence=validation.sequence,
            evaluation_time_ms=validation.evaluation_time_ms,
            recovered_snapshot=None,
            recovered_head=None,
            recovered_manifest=None,
            recovered_entries=(),
        )
    record = deserialize_approval_ledger_persistence_record(load_result.persisted_payload_json)
    recovered_entries = _rebuild_entries(record.release_decision_checksums)
    recovered_head = build_approval_ledger_head(
        session_epoch=record.ledger_epoch,
        context_authority_checksum=record.context_authority_checksum,
        prior_entries=recovered_entries,
    )
    recovered_manifest = build_ledger_epoch_manifest(
        session_epoch=record.ledger_epoch,
        context_authority_checksum=record.context_authority_checksum,
        backend_admission_checksum=record.backend_admission_checksum,
    )
    recovered_snapshot = build_approval_ledger_state_snapshot(
        ledger_head=recovered_head,
        ledger_epoch_manifest=recovered_manifest,
        state_source_id=record.state_source_id,
    )
    if recovered_snapshot.state_snapshot_checksum != record.state_checksum:
        return _recovery_result(
            status=ApprovalLedgerPersistenceStatus.NOT_RECOVERED,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_STATE_CHECKSUM_MISMATCH,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
            recovered_snapshot=None,
            recovered_head=None,
            recovered_manifest=None,
            recovered_entries=(),
        )
    snapshot_validation = validate_approval_ledger_state_snapshot(
        state_snapshot=recovered_snapshot,
        ledger_head=recovered_head,
        ledger_epoch_manifest=recovered_manifest,
        expected_state_source_id=record.state_source_id,
    )
    if snapshot_validation.status != "VALID":
        return _recovery_result(
            status=ApprovalLedgerPersistenceStatus.NOT_RECOVERED,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CORRUPT,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
            recovered_snapshot=None,
            recovered_head=None,
            recovered_manifest=None,
            recovered_entries=(),
        )
    return _recovery_result(
        status=ApprovalLedgerPersistenceStatus.RECOVERED,
        reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RECOVERED,
        repository_id=record.repository_id,
        ledger_epoch=record.ledger_epoch,
        head_checksum=record.head_checksum,
        state_checksum=record.state_checksum,
        sequence=record.sequence,
        evaluation_time_ms=record.evaluation_time_ms,
        recovered_snapshot=recovered_snapshot,
        recovered_head=recovered_head,
        recovered_manifest=recovered_manifest,
        recovered_entries=recovered_entries,
    )


def validate_approval_ledger_persistence_payload(
    *,
    load_result: object,
    expected_repository_id: object,
    expected_ledger_epoch: object,
    minimum_sequence: object,
    expected_head_checksum: object,
    expected_state_checksum: object,
) -> ApprovalLedgerPersistenceValidationResult:
    """Validate one load result against expected repository authority inputs."""
    repository_id = _normalize_required_text(expected_repository_id, "expected_repository_id")
    expected_epoch = _normalize_non_negative_int(expected_ledger_epoch, "expected_ledger_epoch")
    minimum_seq = _normalize_sequence(minimum_sequence, "minimum_sequence")
    expected_head = _normalize_checksum(expected_head_checksum, "expected_head_checksum")
    expected_state = _normalize_checksum(expected_state_checksum, "expected_state_checksum")
    if type(load_result) is not ApprovalLedgerPersistenceLoadResult:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION,
            repository_id=repository_id,
            ledger_epoch=expected_epoch,
            head_checksum=expected_head,
            state_checksum=expected_state,
            sequence=minimum_seq,
            evaluation_time_ms=0,
        )
    if load_result.status is not ApprovalLedgerPersistenceStatus.LOADED:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=load_result.reason,
            repository_id=repository_id,
            ledger_epoch=expected_epoch,
            head_checksum=expected_head,
            state_checksum=expected_state,
            sequence=minimum_seq,
            evaluation_time_ms=load_result.evaluation_time_ms,
        )
    try:
        record = deserialize_approval_ledger_persistence_record(load_result.persisted_payload_json)
    except ValueError:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.CORRUPT,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CORRUPT,
            repository_id=repository_id,
            ledger_epoch=expected_epoch,
            head_checksum=expected_head,
            state_checksum=expected_state,
            sequence=minimum_seq,
            evaluation_time_ms=load_result.evaluation_time_ms,
        )
    if record.contract_version != APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION_UNKNOWN,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    if record.repository_id != repository_id:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    if record.ledger_epoch != expected_epoch:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.INVALID,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    if record.sequence < minimum_seq:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.ROLLED_BACK,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    if record.sequence == minimum_seq and record.head_checksum != expected_head:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.FORKED,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_HEAD_FORK,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    if record.sequence == minimum_seq and record.state_checksum != expected_state:
        return _validation_result(
            status=ApprovalLedgerPersistenceStatus.CHECKSUM_MISMATCH,
            reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_STATE_CHECKSUM_MISMATCH,
            repository_id=record.repository_id,
            ledger_epoch=record.ledger_epoch,
            head_checksum=record.head_checksum,
            state_checksum=record.state_checksum,
            sequence=record.sequence,
            evaluation_time_ms=record.evaluation_time_ms,
        )
    return _validation_result(
        status=ApprovalLedgerPersistenceStatus.VALID,
        reason=ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_VALID,
        repository_id=record.repository_id,
        ledger_epoch=record.ledger_epoch,
        head_checksum=record.head_checksum,
        state_checksum=record.state_checksum,
        sequence=record.sequence,
        evaluation_time_ms=record.evaluation_time_ms,
    )


def deserialize_approval_ledger_persistence_record(
    payload_json: object,
) -> ApprovalLedgerPersistenceRecord:
    """Deserialize and validate canonical JSON into a persistence record."""
    canonical_json = _normalize_required_text(payload_json, "payload_json")
    try:
        payload = json.loads(canonical_json)
    except json.JSONDecodeError as exc:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_CORRUPT
        ) from exc
    if type(payload) is not dict:
        raise ValueError(ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_MALFORMED)
    values = cast(dict[str, object], payload)
    _assert_required_fields(
        values,
        (
            "contract_version",
            "repository_id",
            "ledger_epoch",
            "head_checksum",
            "state_checksum",
            "sequence",
            "evaluation_time_ms",
            "state_source_id",
            "context_authority_checksum",
            "backend_admission_checksum",
            "release_decision_checksums",
        ),
    )
    checksums = _normalize_release_checksums(values["release_decision_checksums"])
    if len(checksums) != _normalize_sequence(values["sequence"], "sequence") + 1:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_SEQUENCE_ROLLBACK
        )
    if canonical_json != _canonical_json(values):
        raise ValueError(ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_MALFORMED)
    return ApprovalLedgerPersistenceRecord(
        contract_version=_normalize_required_text(values["contract_version"], "contract_version"),
        repository_id=_normalize_required_text(values["repository_id"], "repository_id"),
        ledger_epoch=_normalize_non_negative_int(values["ledger_epoch"], "ledger_epoch"),
        head_checksum=_normalize_checksum(values["head_checksum"], "head_checksum"),
        state_checksum=_normalize_checksum(values["state_checksum"], "state_checksum"),
        sequence=_normalize_sequence(values["sequence"], "sequence"),
        evaluation_time_ms=_normalize_non_negative_int(
            values["evaluation_time_ms"], "evaluation_time_ms"
        ),
        state_source_id=_normalize_required_text(values["state_source_id"], "state_source_id"),
        context_authority_checksum=_normalize_checksum(
            values["context_authority_checksum"], "context_authority_checksum"
        ),
        backend_admission_checksum=_normalize_checksum(
            values["backend_admission_checksum"], "backend_admission_checksum"
        ),
        release_decision_checksums=checksums,
        canonical_json=canonical_json,
        checksum=approval_ledger_persistence_record_checksum(canonical_json=canonical_json),
    )


def build_approval_ledger_persistence_adapter_descriptor(
    *,
    adapter_id: object,
    adapter_kind: object,
    supports_persistence: object,
    supports_durable_storage: object,
) -> ApprovalLedgerPersistenceAdapterDescriptor:
    """Build checksum-bound adapter descriptor."""
    normalized_id = _normalize_required_text(adapter_id, "adapter_id")
    normalized_kind = _normalize_required_text(adapter_kind, "adapter_kind")
    persistence = _normalize_bool(supports_persistence, "supports_persistence")
    durable = _normalize_bool(supports_durable_storage, "supports_durable_storage")
    checksum = _sha256(
        {
            "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
            "adapter_id": normalized_id,
            "adapter_kind": normalized_kind,
            "supports_persistence": persistence,
            "supports_durable_storage": durable,
        }
    )
    return ApprovalLedgerPersistenceAdapterDescriptor(
        adapter_id=normalized_id,
        adapter_kind=normalized_kind,
        supports_persistence=persistence,
        supports_durable_storage=durable,
        checksum=checksum,
    )


def approval_ledger_persistence_record_checksum(*, canonical_json: str) -> str:
    """Return checksum for canonical persistence payload."""
    normalized_json = _normalize_required_text(canonical_json, "canonical_json")
    return hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()


def recompute_approval_ledger_persistence_record_checksum(
    record: ApprovalLedgerPersistenceRecord,
) -> str:
    """Recompute record checksum from canonical JSON payload."""
    return approval_ledger_persistence_record_checksum(canonical_json=record.canonical_json)


def _record_fallback(
    *,
    repository_id: str,
    reason: ApprovalLedgerPersistenceReason,
    status: ApprovalLedgerPersistenceStatus,
) -> ApprovalLedgerPersistenceRecord:
    empty_payload: dict[str, CanonicalPersistenceValue] = {
        "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        "repository_id": repository_id,
        "ledger_epoch": 0,
        "head_checksum": checksum_or_fallback(None),
        "state_checksum": checksum_or_fallback(None),
        "sequence": -1,
        "evaluation_time_ms": 0,
        "state_source_id": "unavailable",
        "context_authority_checksum": checksum_or_fallback(None),
        "backend_admission_checksum": checksum_or_fallback(None),
        "release_decision_checksums": cast(list[CanonicalPersistenceValue], []),
        "status": status.value,
        "reason": reason.value,
    }
    canonical_json = _canonical_json(empty_payload)
    return ApprovalLedgerPersistenceRecord(
        contract_version=APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        repository_id=repository_id,
        ledger_epoch=0,
        head_checksum=checksum_or_fallback(None),
        state_checksum=checksum_or_fallback(None),
        sequence=-1,
        evaluation_time_ms=0,
        state_source_id="unavailable",
        context_authority_checksum=checksum_or_fallback(None),
        backend_admission_checksum=checksum_or_fallback(None),
        release_decision_checksums=(),
        canonical_json=canonical_json,
        checksum=approval_ledger_persistence_record_checksum(canonical_json=canonical_json),
    )


def _record_fallback_from_record(
    record: ApprovalLedgerPersistenceRecord,
) -> ApprovalLedgerPersistenceRecord:
    return record


def _receipt_from_fallback(
    *,
    fallback: ApprovalLedgerPersistenceRecord,
    reason: ApprovalLedgerPersistenceReason,
    status: ApprovalLedgerPersistenceStatus,
) -> ApprovalLedgerPersistenceReceipt:
    payload = {
        "status": status.value,
        "reason": reason.value,
        "contract_version": fallback.contract_version,
        "repository_id": fallback.repository_id,
        "ledger_epoch": fallback.ledger_epoch,
        "head_checksum": fallback.head_checksum,
        "state_checksum": fallback.state_checksum,
        "sequence": fallback.sequence,
        "evaluation_time_ms": fallback.evaluation_time_ms,
    }
    checksum = _sha256(payload)
    return ApprovalLedgerPersistenceReceipt(
        status=status,
        reason=reason.value,
        contract_version=fallback.contract_version,
        repository_id=fallback.repository_id,
        ledger_epoch=fallback.ledger_epoch,
        head_checksum=fallback.head_checksum,
        state_checksum=fallback.state_checksum,
        sequence=fallback.sequence,
        evaluation_time_ms=fallback.evaluation_time_ms,
        checksum=checksum,
    )


def _load_result(
    *,
    status: ApprovalLedgerPersistenceStatus,
    reason: ApprovalLedgerPersistenceReason,
    repository_id: str,
    ledger_epoch: int = 0,
    head_checksum: str = "",
    state_checksum: str = "",
    sequence: int = -1,
    evaluation_time_ms: int = 0,
    payload_json: str = "{}",
) -> ApprovalLedgerPersistenceLoadResult:
    normalized_head = checksum_or_fallback(head_checksum)
    normalized_state = checksum_or_fallback(state_checksum)
    normalized_payload = _normalize_required_text(payload_json, "payload_json")
    checksum = _sha256(
        {
            "status": status.value,
            "reason": reason.value,
            "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
            "repository_id": repository_id,
            "ledger_epoch": ledger_epoch,
            "head_checksum": normalized_head,
            "state_checksum": normalized_state,
            "sequence": sequence,
            "evaluation_time_ms": evaluation_time_ms,
            "persisted_payload_json": normalized_payload,
        }
    )
    return ApprovalLedgerPersistenceLoadResult(
        status=status,
        reason=reason.value,
        contract_version=APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        repository_id=repository_id,
        ledger_epoch=ledger_epoch,
        head_checksum=normalized_head,
        state_checksum=normalized_state,
        sequence=sequence,
        evaluation_time_ms=evaluation_time_ms,
        persisted_payload_json=normalized_payload,
        checksum=checksum,
    )


def _validation_result(
    *,
    status: ApprovalLedgerPersistenceStatus,
    reason: ApprovalLedgerPersistenceReason | str,
    repository_id: str,
    ledger_epoch: int,
    head_checksum: str,
    state_checksum: str,
    sequence: int,
    evaluation_time_ms: int,
) -> ApprovalLedgerPersistenceValidationResult:
    reason_text = reason.value if isinstance(reason, ApprovalLedgerPersistenceReason) else reason
    checksum = _sha256(
        {
            "status": status.value,
            "reason": reason_text,
            "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
            "repository_id": repository_id,
            "ledger_epoch": ledger_epoch,
            "head_checksum": head_checksum,
            "state_checksum": state_checksum,
            "sequence": sequence,
            "evaluation_time_ms": evaluation_time_ms,
        }
    )
    return ApprovalLedgerPersistenceValidationResult(
        status=status,
        reason=reason_text,
        contract_version=APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        repository_id=repository_id,
        ledger_epoch=ledger_epoch,
        head_checksum=head_checksum,
        state_checksum=state_checksum,
        sequence=sequence,
        evaluation_time_ms=evaluation_time_ms,
        checksum=checksum,
    )


def _recovery_result(
    *,
    status: ApprovalLedgerPersistenceStatus,
    reason: ApprovalLedgerPersistenceReason | str,
    repository_id: str,
    ledger_epoch: int,
    head_checksum: str,
    state_checksum: str,
    sequence: int,
    evaluation_time_ms: int,
    recovered_snapshot: ApprovalLedgerStateSnapshot | None,
    recovered_head: ApprovalLedgerHead | None,
    recovered_manifest: LedgerEpochManifest | None,
    recovered_entries: tuple[ApprovalLedgerEntry, ...],
) -> ApprovalLedgerRecoveryResult:
    reason_text = reason.value if isinstance(reason, ApprovalLedgerPersistenceReason) else reason
    checksum = _sha256(
        {
            "status": status.value,
            "reason": reason_text,
            "contract_version": APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
            "repository_id": repository_id,
            "ledger_epoch": ledger_epoch,
            "head_checksum": head_checksum,
            "state_checksum": state_checksum,
            "sequence": sequence,
            "evaluation_time_ms": evaluation_time_ms,
            "recovered_snapshot_checksum": (
                recovered_snapshot.state_snapshot_checksum
                if recovered_snapshot is not None
                else None
            ),
            "recovered_head_checksum": recovered_head.head_checksum
            if recovered_head is not None
            else None,
            "recovered_manifest_checksum": (
                recovered_manifest.manifest_checksum if recovered_manifest is not None else None
            ),
            "recovered_entry_checksums": [entry.entry_checksum for entry in recovered_entries],
        }
    )
    return ApprovalLedgerRecoveryResult(
        status=status,
        reason=reason_text,
        contract_version=APPROVAL_LEDGER_PERSISTENCE_CONTRACT_VERSION,
        repository_id=repository_id,
        ledger_epoch=ledger_epoch,
        head_checksum=head_checksum,
        state_checksum=state_checksum,
        sequence=sequence,
        evaluation_time_ms=evaluation_time_ms,
        recovered_snapshot=recovered_snapshot,
        recovered_head=recovered_head,
        recovered_manifest=recovered_manifest,
        recovered_entries=recovered_entries,
        checksum=checksum,
    )


def _rebuild_entries(
    release_decision_checksums: tuple[str, ...],
) -> tuple[ApprovalLedgerEntry, ...]:
    entries: tuple[ApprovalLedgerEntry, ...] = ()
    for decision_checksum in release_decision_checksums:
        entries = entries + (
            append_approval_ledger_entry(
                prior_entries=entries,
                release_status="RELEASED_DRY_RUN",
                release_decision_checksum=decision_checksum,
            ),
        )
    return entries


def _normalize_release_checksums(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        items: tuple[object, ...] = tuple(cast(list[object], value))
    elif isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
    else:
        raise ValueError(ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_MALFORMED)
    normalized = tuple(_normalize_checksum(item, "release_decision_checksum") for item in items)
    return normalized


def _normalize_snapshot(value: object) -> ApprovalLedgerStateSnapshot:
    if type(value) is not ApprovalLedgerStateSnapshot:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION
        )
    return value


def _normalize_manifest(value: object) -> LedgerEpochManifest:
    if type(value) is not LedgerEpochManifest:
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION
        )
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(
            ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_RUNTIME_OBJECT_INJECTION
        )
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if checksum_or_fallback(normalized) != normalized:
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_sequence(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < -1:
        raise ValueError(f"{field_name} must be >= -1")
    return value


def _normalize_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be bool")
    return value


def _canonical_json(payload: Mapping[str, object]) -> str:
    return json.dumps(
        _canonical_mapping(cast(Mapping[str, CanonicalPersistenceValue], payload)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _canonical_mapping(
    values: Mapping[str, CanonicalPersistenceValue],
) -> dict[str, CanonicalPersistenceValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalPersistenceValue) -> CanonicalPersistenceValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalPersistenceValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def _assert_required_fields(values: Mapping[str, object], required_fields: tuple[str, ...]) -> None:
    for field_name in required_fields:
        if field_name not in values:
            raise ValueError(ApprovalLedgerPersistenceReason.APPROVAL_LEDGER_PERSISTENCE_MALFORMED)


def _sha256(payload: Mapping[str, CanonicalPersistenceValue]) -> str:
    canonical = _canonical_json(cast(Mapping[str, object], payload))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "ApprovalLedgerPersistenceAdapter",
    "ApprovalLedgerPersistenceAdapterDescriptor",
    "ApprovalLedgerPersistenceLoadResult",
    "ApprovalLedgerPersistenceReason",
    "ApprovalLedgerPersistenceReceipt",
    "ApprovalLedgerPersistenceRecord",
    "ApprovalLedgerPersistenceStatus",
    "ApprovalLedgerPersistenceValidationResult",
    "ApprovalLedgerRecoveryResult",
    "InMemoryApprovalLedgerPersistenceAdapter",
    "approval_ledger_persistence_record_checksum",
    "build_approval_ledger_persistence_adapter_descriptor",
    "build_approval_ledger_persistence_record",
    "deserialize_approval_ledger_persistence_record",
    "load_and_recover_approval_ledger_state",
    "recompute_approval_ledger_persistence_record_checksum",
    "validate_approval_ledger_persistence_payload",
]
