"""Deterministic canonical approval ledger state boundary for ADR-0026."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import APPROVAL_LEDGER_STATE_CONTRACT_VERSION
from aegis.execution.aegis_approval_ledger import ApprovalLedgerEntry
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerAppendResult,
    ApprovalLedgerHead,
    LedgerEpochManifest,
    append_to_approval_ledger_head,
    recompute_approval_ledger_append_result_checksum,
    recompute_approval_ledger_head_checksum,
    recompute_ledger_epoch_manifest_checksum,
)
from aegis.execution.aegis_capability_lease import checksum_or_fallback
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason

type LedgerStateStatusValue = Literal["VALID", "BLOCKED"]
type CanonicalApprovalLedgerStateValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalApprovalLedgerStateValue]
    | dict[str, CanonicalApprovalLedgerStateValue]
)

_SNAPSHOT_CONSTRUCTION_TOKEN = object()
_TRANSITION_CONSTRUCTION_TOKEN = object()
_STATE_VALIDATION_TOKEN = object()

_MAX_STATE_SOURCE_ID_LENGTH = 128


class ApprovalLedgerStateReason(StrEnum):
    """Stable ADR-0026 canonical state boundary reason codes."""

    APPROVAL_LEDGER_STATE_VALID = "APPROVAL_LEDGER_STATE_VALID"
    APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID = "APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID"
    APPROVAL_LEDGER_STATE_TRANSITION_INVALID = "APPROVAL_LEDGER_STATE_TRANSITION_INVALID"
    APPROVAL_LEDGER_STATE_HEAD_MISMATCH = "APPROVAL_LEDGER_STATE_HEAD_MISMATCH"
    APPROVAL_LEDGER_STATE_EPOCH_MISMATCH = "APPROVAL_LEDGER_STATE_EPOCH_MISMATCH"
    APPROVAL_LEDGER_STATE_CONTEXT_AUTHORITY_DRIFT = "APPROVAL_LEDGER_STATE_CONTEXT_AUTHORITY_DRIFT"
    APPROVAL_LEDGER_STATE_BACKEND_ADMISSION_DRIFT = "APPROVAL_LEDGER_STATE_BACKEND_ADMISSION_DRIFT"
    APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK = "APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK"
    APPROVAL_LEDGER_STATE_SEQUENCE_SKIP = "APPROVAL_LEDGER_STATE_SEQUENCE_SKIP"
    APPROVAL_LEDGER_STATE_ENTRY_MISMATCH = "APPROVAL_LEDGER_STATE_ENTRY_MISMATCH"
    APPROVAL_LEDGER_STATE_SOURCE_DRIFT = "APPROVAL_LEDGER_STATE_SOURCE_DRIFT"
    APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT = "APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT"
    APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION = (
        "APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION"
    )
    APPROVAL_LEDGER_STATE_DIRECT_SNAPSHOT_CONSTRUCTION = (
        "APPROVAL_LEDGER_STATE_DIRECT_SNAPSHOT_CONSTRUCTION"
    )
    APPROVAL_LEDGER_STATE_DIRECT_TRANSITION_CONSTRUCTION = (
        "APPROVAL_LEDGER_STATE_DIRECT_TRANSITION_CONSTRUCTION"
    )
    APPROVAL_LEDGER_STATE_DIRECT_VALIDATION_CONSTRUCTION = (
        "APPROVAL_LEDGER_STATE_DIRECT_VALIDATION_CONSTRUCTION"
    )


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerStateSnapshot:
    """Canonical checksum-bound state snapshot for one ledger epoch."""

    contract_version: str
    ledger_epoch_manifest_checksum: str
    ledger_head_checksum: str
    latest_sequence_index: int
    latest_entry_checksum: str
    genesis_checksum: str
    context_authority_checksum: str
    backend_admission_checksum: str
    state_source_id: str
    state_snapshot_checksum: str

    def __init__(
        self,
        *,
        contract_version: object,
        ledger_epoch_manifest_checksum: object,
        ledger_head_checksum: object,
        latest_sequence_index: object,
        latest_entry_checksum: object,
        genesis_checksum: object,
        context_authority_checksum: object,
        backend_admission_checksum: object,
        state_source_id: object,
        state_snapshot_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _SNAPSHOT_CONSTRUCTION_TOKEN:
            raise ValueError(
                ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_SNAPSHOT_CONSTRUCTION
            )
        normalized_version = _normalize_contract_version(contract_version)
        normalized_manifest = _normalize_required_checksum(
            ledger_epoch_manifest_checksum, "ledger_epoch_manifest_checksum"
        )
        normalized_head = _normalize_required_checksum(ledger_head_checksum, "ledger_head_checksum")
        normalized_sequence = _normalize_sequence_index(latest_sequence_index)
        normalized_entry = _normalize_required_checksum(
            latest_entry_checksum, "latest_entry_checksum"
        )
        normalized_genesis = _normalize_required_checksum(genesis_checksum, "genesis_checksum")
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        normalized_admission = _normalize_required_checksum(
            backend_admission_checksum, "backend_admission_checksum"
        )
        normalized_source = _normalize_state_source_id(state_source_id)
        computed = approval_ledger_state_snapshot_checksum(
            contract_version=normalized_version,
            ledger_epoch_manifest_checksum=normalized_manifest,
            ledger_head_checksum=normalized_head,
            latest_sequence_index=normalized_sequence,
            latest_entry_checksum=normalized_entry,
            genesis_checksum=normalized_genesis,
            context_authority_checksum=normalized_context,
            backend_admission_checksum=normalized_admission,
            state_source_id=normalized_source,
        )
        normalized_checksum = _normalize_supplied_checksum(
            state_snapshot_checksum, computed, "state_snapshot_checksum"
        )
        object.__setattr__(self, "contract_version", normalized_version)
        object.__setattr__(self, "ledger_epoch_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "ledger_head_checksum", normalized_head)
        object.__setattr__(self, "latest_sequence_index", normalized_sequence)
        object.__setattr__(self, "latest_entry_checksum", normalized_entry)
        object.__setattr__(self, "genesis_checksum", normalized_genesis)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "backend_admission_checksum", normalized_admission)
        object.__setattr__(self, "state_source_id", normalized_source)
        object.__setattr__(self, "state_snapshot_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerStateTransition:
    """Canonical checksum-bound proof for one append-driven state transition."""

    contract_version: str
    previous_snapshot_checksum: str
    append_result_checksum: str
    new_snapshot_checksum: str
    previous_sequence_index: int
    new_sequence_index: int
    previous_entry_checksum: str
    new_entry_checksum: str
    ledger_epoch_manifest_checksum: str
    state_source_id: str
    state_transition_checksum: str

    def __init__(
        self,
        *,
        contract_version: object,
        previous_snapshot_checksum: object,
        append_result_checksum: object,
        new_snapshot_checksum: object,
        previous_sequence_index: object,
        new_sequence_index: object,
        previous_entry_checksum: object,
        new_entry_checksum: object,
        ledger_epoch_manifest_checksum: object,
        state_source_id: object,
        state_transition_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _TRANSITION_CONSTRUCTION_TOKEN:
            raise ValueError(
                ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_TRANSITION_CONSTRUCTION
            )
        normalized_version = _normalize_contract_version(contract_version)
        normalized_previous_snapshot = _normalize_required_checksum(
            previous_snapshot_checksum, "previous_snapshot_checksum"
        )
        normalized_append = _normalize_required_checksum(
            append_result_checksum, "append_result_checksum"
        )
        normalized_new_snapshot = _normalize_required_checksum(
            new_snapshot_checksum, "new_snapshot_checksum"
        )
        normalized_previous_sequence = _normalize_sequence_index(previous_sequence_index)
        normalized_new_sequence = _normalize_sequence_index(new_sequence_index)
        normalized_previous_entry = _normalize_required_checksum(
            previous_entry_checksum, "previous_entry_checksum"
        )
        normalized_new_entry = _normalize_required_checksum(
            new_entry_checksum, "new_entry_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            ledger_epoch_manifest_checksum, "ledger_epoch_manifest_checksum"
        )
        normalized_source = _normalize_state_source_id(state_source_id)
        computed = approval_ledger_state_transition_checksum(
            contract_version=normalized_version,
            previous_snapshot_checksum=normalized_previous_snapshot,
            append_result_checksum=normalized_append,
            new_snapshot_checksum=normalized_new_snapshot,
            previous_sequence_index=normalized_previous_sequence,
            new_sequence_index=normalized_new_sequence,
            previous_entry_checksum=normalized_previous_entry,
            new_entry_checksum=normalized_new_entry,
            ledger_epoch_manifest_checksum=normalized_manifest,
            state_source_id=normalized_source,
        )
        normalized_checksum = _normalize_supplied_checksum(
            state_transition_checksum, computed, "state_transition_checksum"
        )
        object.__setattr__(self, "contract_version", normalized_version)
        object.__setattr__(self, "previous_snapshot_checksum", normalized_previous_snapshot)
        object.__setattr__(self, "append_result_checksum", normalized_append)
        object.__setattr__(self, "new_snapshot_checksum", normalized_new_snapshot)
        object.__setattr__(self, "previous_sequence_index", normalized_previous_sequence)
        object.__setattr__(self, "new_sequence_index", normalized_new_sequence)
        object.__setattr__(self, "previous_entry_checksum", normalized_previous_entry)
        object.__setattr__(self, "new_entry_checksum", normalized_new_entry)
        object.__setattr__(self, "ledger_epoch_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "state_source_id", normalized_source)
        object.__setattr__(self, "state_transition_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class LedgerStateValidationResult:
    """Checksum-bound VALID/BLOCKED state boundary result."""

    status: LedgerStateStatusValue
    reason: str
    state_snapshot_checksum: str
    ledger_head_checksum: str
    ledger_epoch_manifest_checksum: str
    validation_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason: object,
        state_snapshot_checksum: object,
        ledger_head_checksum: object,
        ledger_epoch_manifest_checksum: object,
        validation_checksum: str | None = None,
        _validation_token: object | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason)
        if normalized_status == "VALID":
            if _validation_token is not _STATE_VALIDATION_TOKEN:
                raise ValueError(
                    ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_VALIDATION_CONSTRUCTION
                )
            if normalized_reason != ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_VALID.value:
                raise ValueError(
                    "VALID ledger state result requires APPROVAL_LEDGER_STATE_VALID reason"
                )
        if (
            normalized_status == "BLOCKED"
            and normalized_reason == ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_VALID.value
        ):
            raise ValueError("BLOCKED ledger state result requires a blocking reason")
        normalized_snapshot = _normalize_required_checksum(
            state_snapshot_checksum, "state_snapshot_checksum"
        )
        normalized_head = _normalize_required_checksum(ledger_head_checksum, "ledger_head_checksum")
        normalized_manifest = _normalize_required_checksum(
            ledger_epoch_manifest_checksum, "ledger_epoch_manifest_checksum"
        )
        computed = ledger_state_validation_checksum(
            status=normalized_status,
            reason=normalized_reason,
            state_snapshot_checksum=normalized_snapshot,
            ledger_head_checksum=normalized_head,
            ledger_epoch_manifest_checksum=normalized_manifest,
        )
        normalized_validation = _normalize_supplied_checksum(
            validation_checksum, computed, "validation_checksum"
        )
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "state_snapshot_checksum", normalized_snapshot)
        object.__setattr__(self, "ledger_head_checksum", normalized_head)
        object.__setattr__(self, "ledger_epoch_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "validation_checksum", normalized_validation)


def build_approval_ledger_state_snapshot(
    *,
    ledger_head: object,
    ledger_epoch_manifest: object,
    state_source_id: object,
) -> ApprovalLedgerStateSnapshot:
    """Build a canonical state snapshot bound to one head and one epoch manifest."""
    reason = approval_ledger_state_block_reason(
        state_snapshot=None,
        ledger_head=ledger_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
        expected_state_source_id=state_source_id,
    )
    if reason is not None:
        raise ValueError(reason.value)
    head = cast(ApprovalLedgerHead, ledger_head)
    manifest = cast(LedgerEpochManifest, ledger_epoch_manifest)
    normalized_source = _normalize_state_source_id(state_source_id)
    return ApprovalLedgerStateSnapshot(
        contract_version=APPROVAL_LEDGER_STATE_CONTRACT_VERSION,
        ledger_epoch_manifest_checksum=manifest.manifest_checksum,
        ledger_head_checksum=head.head_checksum,
        latest_sequence_index=head.latest_sequence_index,
        latest_entry_checksum=head.latest_entry_checksum,
        genesis_checksum=head.genesis_checksum,
        context_authority_checksum=head.context_authority_checksum,
        backend_admission_checksum=manifest.backend_admission_checksum,
        state_source_id=normalized_source,
        _construction_token=_SNAPSHOT_CONSTRUCTION_TOKEN,
    )


def validate_approval_ledger_state_snapshot(
    *,
    state_snapshot: object,
    ledger_head: object,
    ledger_epoch_manifest: object,
    expected_state_source_id: object | None = None,
) -> LedgerStateValidationResult:
    """Return checksum-bound VALID/BLOCKED result for one state snapshot."""
    reason = approval_ledger_state_block_reason(
        state_snapshot=state_snapshot,
        ledger_head=ledger_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
        expected_state_source_id=expected_state_source_id,
    )
    snapshot_checksum = _state_snapshot_checksum_or_fallback(state_snapshot)
    head_checksum = _head_checksum_or_fallback(ledger_head)
    manifest_checksum = _manifest_checksum_or_fallback(ledger_epoch_manifest)
    if reason is None:
        return LedgerStateValidationResult(
            status="VALID",
            reason=ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_VALID,
            state_snapshot_checksum=snapshot_checksum,
            ledger_head_checksum=head_checksum,
            ledger_epoch_manifest_checksum=manifest_checksum,
            _validation_token=_STATE_VALIDATION_TOKEN,
        )
    return LedgerStateValidationResult(
        status="BLOCKED",
        reason=reason,
        state_snapshot_checksum=snapshot_checksum,
        ledger_head_checksum=head_checksum,
        ledger_epoch_manifest_checksum=manifest_checksum,
    )


def build_approval_ledger_state_transition(
    *,
    previous_snapshot: object,
    append_result: object,
    new_snapshot: object,
) -> ApprovalLedgerStateTransition:
    """Build transition proof for one append moving canonical state forward by one."""
    reason = _state_transition_block_reason(
        previous_snapshot=previous_snapshot,
        append_result=append_result,
        new_snapshot=new_snapshot,
        transition=None,
    )
    if reason is not None:
        raise ValueError(reason.value)
    prior = cast(ApprovalLedgerStateSnapshot, previous_snapshot)
    result = cast(ApprovalLedgerAppendResult, append_result)
    new_state = cast(ApprovalLedgerStateSnapshot, new_snapshot)
    return ApprovalLedgerStateTransition(
        contract_version=APPROVAL_LEDGER_STATE_CONTRACT_VERSION,
        previous_snapshot_checksum=prior.state_snapshot_checksum,
        append_result_checksum=result.append_result_checksum,
        new_snapshot_checksum=new_state.state_snapshot_checksum,
        previous_sequence_index=prior.latest_sequence_index,
        new_sequence_index=new_state.latest_sequence_index,
        previous_entry_checksum=prior.latest_entry_checksum,
        new_entry_checksum=new_state.latest_entry_checksum,
        ledger_epoch_manifest_checksum=prior.ledger_epoch_manifest_checksum,
        state_source_id=prior.state_source_id,
        _construction_token=_TRANSITION_CONSTRUCTION_TOKEN,
    )


def validate_approval_ledger_state_transition(
    *,
    transition: object,
    previous_snapshot: object,
    append_result: object,
    new_snapshot: object,
) -> LedgerStateValidationResult:
    """Return checksum-bound VALID/BLOCKED result for one state transition."""
    reason = _state_transition_block_reason(
        previous_snapshot=previous_snapshot,
        append_result=append_result,
        new_snapshot=new_snapshot,
        transition=transition,
    )
    snapshot_checksum = _state_snapshot_checksum_or_fallback(new_snapshot)
    head_checksum = _append_result_head_checksum_or_fallback(append_result)
    manifest_checksum = _manifest_checksum_from_snapshot_or_fallback(new_snapshot)
    if reason is None:
        return LedgerStateValidationResult(
            status="VALID",
            reason=ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_VALID,
            state_snapshot_checksum=snapshot_checksum,
            ledger_head_checksum=head_checksum,
            ledger_epoch_manifest_checksum=manifest_checksum,
            _validation_token=_STATE_VALIDATION_TOKEN,
        )
    return LedgerStateValidationResult(
        status="BLOCKED",
        reason=reason,
        state_snapshot_checksum=snapshot_checksum,
        ledger_head_checksum=head_checksum,
        ledger_epoch_manifest_checksum=manifest_checksum,
    )


def approval_ledger_state_block_reason(
    *,
    state_snapshot: object | None,
    ledger_head: object,
    ledger_epoch_manifest: object,
    expected_state_source_id: object | None = None,
) -> ApprovalLedgerStateReason | None:
    """Return first deterministic reason supplied snapshot/head/manifest is not canonical."""
    if type(ledger_head) is not ApprovalLedgerHead:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    if type(ledger_epoch_manifest) is not LedgerEpochManifest:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    head = ledger_head
    manifest = ledger_epoch_manifest
    if head.head_checksum != recompute_approval_ledger_head_checksum(head):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if manifest.manifest_checksum != recompute_ledger_epoch_manifest_checksum(manifest):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if manifest.session_epoch != head.session_epoch:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT
    if manifest.context_authority_checksum != head.context_authority_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CONTEXT_AUTHORITY_DRIFT
    if expected_state_source_id is not None:
        try:
            expected_source = _normalize_state_source_id(expected_state_source_id)
        except ValueError as exc:
            if (
                str(exc)
                == ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION.value
            ):
                return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
            return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SOURCE_DRIFT
    else:
        expected_source = None
    if state_snapshot is None:
        return None
    if type(state_snapshot) is not ApprovalLedgerStateSnapshot:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    snapshot = state_snapshot
    if snapshot.state_snapshot_checksum != recompute_approval_ledger_state_snapshot_checksum(
        snapshot
    ):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if snapshot.contract_version != APPROVAL_LEDGER_STATE_CONTRACT_VERSION:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if snapshot.ledger_head_checksum != head.head_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_HEAD_MISMATCH
    if snapshot.ledger_epoch_manifest_checksum != manifest.manifest_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_EPOCH_MISMATCH
    if snapshot.latest_sequence_index != head.latest_sequence_index:
        if snapshot.latest_sequence_index < head.latest_sequence_index:
            return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SEQUENCE_SKIP
    if snapshot.latest_entry_checksum != head.latest_entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_ENTRY_MISMATCH
    if snapshot.genesis_checksum != head.genesis_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if snapshot.context_authority_checksum != head.context_authority_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CONTEXT_AUTHORITY_DRIFT
    if snapshot.backend_admission_checksum != manifest.backend_admission_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_BACKEND_ADMISSION_DRIFT
    if expected_source is not None and snapshot.state_source_id != expected_source:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SOURCE_DRIFT
    return None


def approval_ledger_state_quarantine_block_reason(
    *,
    state_snapshot: object,
    ledger_head: object,
    ledger_epoch_manifest: object,
    expected_state_source_id: object | None = None,
) -> CommandQuarantineReason | None:
    """Map ADR-0026 state block reason to command quarantine reasons."""
    reason = approval_ledger_state_block_reason(
        state_snapshot=state_snapshot,
        ledger_head=ledger_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
        expected_state_source_id=expected_state_source_id,
    )
    if reason is None:
        return None
    if reason in {
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION,
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_SNAPSHOT_CONSTRUCTION,
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_TRANSITION_CONSTRUCTION,
        ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_DIRECT_VALIDATION_CONSTRUCTION,
    }:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID


def append_to_approval_ledger_state(
    *,
    prior_entries: object,
    current_head: object,
    current_state_snapshot: object,
    release_decision: object,
    ledger_epoch_manifest: object,
) -> tuple[
    ApprovalLedgerEntry,
    ApprovalLedgerHead,
    ApprovalLedgerAppendResult,
    ApprovalLedgerStateSnapshot,
    ApprovalLedgerStateTransition,
    LedgerStateValidationResult,
]:
    """Append one release decision and produce complete canonical state transition evidence."""
    if type(current_state_snapshot) is not ApprovalLedgerStateSnapshot:
        raise ValueError(
            ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION.value
        )
    state_snapshot = current_state_snapshot
    state_validation = validate_approval_ledger_state_snapshot(
        state_snapshot=state_snapshot,
        ledger_head=current_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
    )
    if state_validation.status != "VALID":
        raise ValueError(state_validation.reason)
    release_status = getattr(release_decision, "status", None)
    release_checksum = getattr(release_decision, "decision_checksum", None)
    append_result = append_to_approval_ledger_head(
        prior_entries=prior_entries,
        head=current_head,
        release_status=release_status,
        release_decision_checksum=release_checksum,
    )
    new_snapshot = build_approval_ledger_state_snapshot(
        ledger_head=append_result.new_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
        state_source_id=state_snapshot.state_source_id,
    )
    transition = build_approval_ledger_state_transition(
        previous_snapshot=state_snapshot,
        append_result=append_result,
        new_snapshot=new_snapshot,
    )
    transition_validation = validate_approval_ledger_state_transition(
        transition=transition,
        previous_snapshot=state_snapshot,
        append_result=append_result,
        new_snapshot=new_snapshot,
    )
    return (
        append_result.new_entry,
        append_result.new_head,
        append_result,
        new_snapshot,
        transition,
        transition_validation,
    )


def approval_ledger_state_snapshot_checksum(
    *,
    contract_version: str,
    ledger_epoch_manifest_checksum: str,
    ledger_head_checksum: str,
    latest_sequence_index: int,
    latest_entry_checksum: str,
    genesis_checksum: str,
    context_authority_checksum: str,
    backend_admission_checksum: str,
    state_source_id: str,
) -> str:
    """Return deterministic checksum for one approval ledger state snapshot."""
    return _sha256(
        {
            "approval_ledger_state_contract_version": contract_version,
            "ledger_epoch_manifest_checksum": ledger_epoch_manifest_checksum,
            "ledger_head_checksum": ledger_head_checksum,
            "latest_sequence_index": latest_sequence_index,
            "latest_entry_checksum": latest_entry_checksum,
            "genesis_checksum": genesis_checksum,
            "context_authority_checksum": context_authority_checksum,
            "backend_admission_checksum": backend_admission_checksum,
            "state_source_id": state_source_id,
        }
    )


def approval_ledger_state_transition_checksum(
    *,
    contract_version: str,
    previous_snapshot_checksum: str,
    append_result_checksum: str,
    new_snapshot_checksum: str,
    previous_sequence_index: int,
    new_sequence_index: int,
    previous_entry_checksum: str,
    new_entry_checksum: str,
    ledger_epoch_manifest_checksum: str,
    state_source_id: str,
) -> str:
    """Return deterministic checksum for one approval ledger state transition."""
    return _sha256(
        {
            "approval_ledger_state_contract_version": contract_version,
            "previous_snapshot_checksum": previous_snapshot_checksum,
            "append_result_checksum": append_result_checksum,
            "new_snapshot_checksum": new_snapshot_checksum,
            "previous_sequence_index": previous_sequence_index,
            "new_sequence_index": new_sequence_index,
            "previous_entry_checksum": previous_entry_checksum,
            "new_entry_checksum": new_entry_checksum,
            "ledger_epoch_manifest_checksum": ledger_epoch_manifest_checksum,
            "state_source_id": state_source_id,
        }
    )


def ledger_state_validation_checksum(
    *,
    status: LedgerStateStatusValue,
    reason: str,
    state_snapshot_checksum: str,
    ledger_head_checksum: str,
    ledger_epoch_manifest_checksum: str,
) -> str:
    """Return deterministic checksum for one ledger state validation result."""
    return _sha256(
        {
            "approval_ledger_state_contract_version": APPROVAL_LEDGER_STATE_CONTRACT_VERSION,
            "status": status,
            "reason": reason,
            "state_snapshot_checksum": state_snapshot_checksum,
            "ledger_head_checksum": ledger_head_checksum,
            "ledger_epoch_manifest_checksum": ledger_epoch_manifest_checksum,
        }
    )


def recompute_approval_ledger_state_snapshot_checksum(snapshot: ApprovalLedgerStateSnapshot) -> str:
    """Recompute ApprovalLedgerStateSnapshot checksum from authoritative fields."""
    return approval_ledger_state_snapshot_checksum(
        contract_version=snapshot.contract_version,
        ledger_epoch_manifest_checksum=snapshot.ledger_epoch_manifest_checksum,
        ledger_head_checksum=snapshot.ledger_head_checksum,
        latest_sequence_index=snapshot.latest_sequence_index,
        latest_entry_checksum=snapshot.latest_entry_checksum,
        genesis_checksum=snapshot.genesis_checksum,
        context_authority_checksum=snapshot.context_authority_checksum,
        backend_admission_checksum=snapshot.backend_admission_checksum,
        state_source_id=snapshot.state_source_id,
    )


def recompute_approval_ledger_state_transition_checksum(
    transition: ApprovalLedgerStateTransition,
) -> str:
    """Recompute ApprovalLedgerStateTransition checksum from authoritative fields."""
    return approval_ledger_state_transition_checksum(
        contract_version=transition.contract_version,
        previous_snapshot_checksum=transition.previous_snapshot_checksum,
        append_result_checksum=transition.append_result_checksum,
        new_snapshot_checksum=transition.new_snapshot_checksum,
        previous_sequence_index=transition.previous_sequence_index,
        new_sequence_index=transition.new_sequence_index,
        previous_entry_checksum=transition.previous_entry_checksum,
        new_entry_checksum=transition.new_entry_checksum,
        ledger_epoch_manifest_checksum=transition.ledger_epoch_manifest_checksum,
        state_source_id=transition.state_source_id,
    )


def recompute_ledger_state_validation_checksum(result: LedgerStateValidationResult) -> str:
    """Recompute LedgerStateValidationResult checksum from authoritative fields."""
    return ledger_state_validation_checksum(
        status=result.status,
        reason=result.reason,
        state_snapshot_checksum=result.state_snapshot_checksum,
        ledger_head_checksum=result.ledger_head_checksum,
        ledger_epoch_manifest_checksum=result.ledger_epoch_manifest_checksum,
    )


def _state_transition_block_reason(
    *,
    previous_snapshot: object,
    append_result: object,
    new_snapshot: object,
    transition: object | None,
) -> ApprovalLedgerStateReason | None:
    if type(previous_snapshot) is not ApprovalLedgerStateSnapshot:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    if type(append_result) is not ApprovalLedgerAppendResult:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    if type(new_snapshot) is not ApprovalLedgerStateSnapshot:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    previous = previous_snapshot
    result = append_result
    new_state = new_snapshot
    if previous.state_snapshot_checksum != recompute_approval_ledger_state_snapshot_checksum(
        previous
    ):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if new_state.state_snapshot_checksum != recompute_approval_ledger_state_snapshot_checksum(
        new_state
    ):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SNAPSHOT_INVALID
    if result.append_result_checksum != recompute_approval_ledger_append_result_checksum(result):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if previous.ledger_epoch_manifest_checksum != new_state.ledger_epoch_manifest_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT
    if previous.context_authority_checksum != new_state.context_authority_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CONTEXT_AUTHORITY_DRIFT
    if previous.backend_admission_checksum != new_state.backend_admission_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_BACKEND_ADMISSION_DRIFT
    if previous.genesis_checksum != new_state.genesis_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT
    if previous.state_source_id != new_state.state_source_id:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SOURCE_DRIFT
    if new_state.latest_sequence_index <= previous.latest_sequence_index:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK
    if new_state.latest_sequence_index != previous.latest_sequence_index + 1:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SEQUENCE_SKIP
    if previous.latest_entry_checksum != result.new_entry.prior_entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_ENTRY_MISMATCH
    if new_state.latest_entry_checksum != result.new_entry.entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_ENTRY_MISMATCH
    if result.new_head.head_checksum != new_state.ledger_head_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_HEAD_MISMATCH
    if result.new_head.latest_sequence_index != new_state.latest_sequence_index:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if result.new_head.latest_entry_checksum != new_state.latest_entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_ENTRY_MISMATCH
    if transition is None:
        return None
    if type(transition) is not ApprovalLedgerStateTransition:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION
    typed_transition = transition
    if (
        typed_transition.state_transition_checksum
        != recompute_approval_ledger_state_transition_checksum(typed_transition)
    ):
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.previous_snapshot_checksum != previous.state_snapshot_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.append_result_checksum != result.append_result_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.new_snapshot_checksum != new_state.state_snapshot_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.previous_sequence_index != previous.latest_sequence_index:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.new_sequence_index != new_state.latest_sequence_index:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.previous_entry_checksum != previous.latest_entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.new_entry_checksum != new_state.latest_entry_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.ledger_epoch_manifest_checksum != previous.ledger_epoch_manifest_checksum:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_TRANSITION_INVALID
    if typed_transition.state_source_id != previous.state_source_id:
        return ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_SOURCE_DRIFT
    return None


def _normalize_contract_version(value: object) -> str:
    normalized = _normalize_required_text(value, "contract_version")
    if normalized != APPROVAL_LEDGER_STATE_CONTRACT_VERSION:
        raise ValueError(f"contract_version must be {APPROVAL_LEDGER_STATE_CONTRACT_VERSION!r}")
    return normalized


def _normalize_status(value: object) -> LedgerStateStatusValue:
    if value in {"VALID", "BLOCKED"}:
        return cast(LedgerStateStatusValue, value)
    raise ValueError("status must be VALID or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason must be an uppercase machine reason code")
    return normalized


def _normalize_sequence_index(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("sequence index must be an integer")
    if value < -1:
        raise ValueError("sequence index must be >= -1")
    return value


def _normalize_state_source_id(value: object) -> str:
    normalized = _normalize_required_text(value, "state_source_id")
    if len(normalized) > _MAX_STATE_SOURCE_ID_LENGTH:
        raise ValueError("state_source_id exceeds deterministic length bound")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(
            ApprovalLedgerStateReason.APPROVAL_LEDGER_STATE_RUNTIME_OBJECT_INJECTION.value
        )
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if checksum_or_fallback(normalized) != normalized:
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied_checksum, field_name)
    if normalized is None:
        return computed_checksum
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _state_snapshot_checksum_or_fallback(value: object) -> str:
    if type(value) is ApprovalLedgerStateSnapshot:
        return checksum_or_fallback(value.state_snapshot_checksum)
    return checksum_or_fallback(getattr(value, "state_snapshot_checksum", None))


def _head_checksum_or_fallback(value: object) -> str:
    if type(value) is ApprovalLedgerHead:
        return checksum_or_fallback(value.head_checksum)
    return checksum_or_fallback(getattr(value, "head_checksum", None))


def _manifest_checksum_or_fallback(value: object) -> str:
    if type(value) is LedgerEpochManifest:
        return checksum_or_fallback(value.manifest_checksum)
    return checksum_or_fallback(getattr(value, "manifest_checksum", None))


def _append_result_head_checksum_or_fallback(value: object) -> str:
    if type(value) is ApprovalLedgerAppendResult:
        return checksum_or_fallback(value.new_head.head_checksum)
    new_head = getattr(value, "new_head", None)
    return checksum_or_fallback(getattr(new_head, "head_checksum", None))


def _manifest_checksum_from_snapshot_or_fallback(value: object) -> str:
    if type(value) is ApprovalLedgerStateSnapshot:
        return checksum_or_fallback(value.ledger_epoch_manifest_checksum)
    return checksum_or_fallback(getattr(value, "ledger_epoch_manifest_checksum", None))


def _sha256(payload: Mapping[str, CanonicalApprovalLedgerStateValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalApprovalLedgerStateValue],
) -> dict[str, CanonicalApprovalLedgerStateValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalApprovalLedgerStateValue,
) -> CanonicalApprovalLedgerStateValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalApprovalLedgerStateValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "ApprovalLedgerStateReason",
    "ApprovalLedgerStateSnapshot",
    "ApprovalLedgerStateTransition",
    "LedgerStateStatusValue",
    "LedgerStateValidationResult",
    "append_to_approval_ledger_state",
    "approval_ledger_state_block_reason",
    "approval_ledger_state_quarantine_block_reason",
    "approval_ledger_state_snapshot_checksum",
    "approval_ledger_state_transition_checksum",
    "build_approval_ledger_state_snapshot",
    "build_approval_ledger_state_transition",
    "ledger_state_validation_checksum",
    "recompute_approval_ledger_state_snapshot_checksum",
    "recompute_approval_ledger_state_transition_checksum",
    "recompute_ledger_state_validation_checksum",
    "validate_approval_ledger_state_snapshot",
    "validate_approval_ledger_state_transition",
]
