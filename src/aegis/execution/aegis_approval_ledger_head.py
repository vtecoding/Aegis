"""Deterministic ledger head, epoch manifest, and append result for ADR-0025."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import (
    APPROVAL_LEDGER_CONTRACT_VERSION,
    APPROVAL_LEDGER_HEAD_CONTRACT_VERSION,
)
from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerChainValidationResult,
    ApprovalLedgerEntry,
    append_approval_ledger_entry,
    approval_ledger_genesis_head_checksum,
    approval_ledger_prior_chain_block_reason,
    validate_approval_ledger_chain,
)
from aegis.execution.aegis_capability_lease import checksum_or_fallback
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason

type ApprovalLedgerHeadStatusValue = Literal["VALID", "BLOCKED"]
type CanonicalLedgerHeadValue = (
    str | int | bool | None | list[CanonicalLedgerHeadValue] | dict[str, CanonicalLedgerHeadValue]
)

_HEAD_CONSTRUCTION_TOKEN = object()
_APPEND_RESULT_CONSTRUCTION_TOKEN = object()

_EMPTY_SEQUENCE_INDEX = -1


class ApprovalLedgerHeadReason(StrEnum):
    """Stable ADR-0025 approval ledger head reason codes."""

    APPROVAL_LEDGER_HEAD_VALID = "APPROVAL_LEDGER_HEAD_VALID"
    APPROVAL_LEDGER_HEAD_STALE_EPOCH = "APPROVAL_LEDGER_HEAD_STALE_EPOCH"
    APPROVAL_LEDGER_HEAD_CONTEXT_AUTHORITY_DRIFT = "APPROVAL_LEDGER_HEAD_CONTEXT_AUTHORITY_DRIFT"
    APPROVAL_LEDGER_HEAD_TIP_MISMATCH = "APPROVAL_LEDGER_HEAD_TIP_MISMATCH"
    APPROVAL_LEDGER_HEAD_SEQUENCE_MISMATCH = "APPROVAL_LEDGER_HEAD_SEQUENCE_MISMATCH"
    APPROVAL_LEDGER_HEAD_GENESIS_MISMATCH = "APPROVAL_LEDGER_HEAD_GENESIS_MISMATCH"
    APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION = "APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION"
    APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION = "APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION"
    APPROVAL_LEDGER_HEAD_SHAPE_INVALID = "APPROVAL_LEDGER_HEAD_SHAPE_INVALID"


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerHead:
    """Epoch- and context-bound snapshot of ledger state for ADR-0025."""

    ledger_contract_version: str
    session_epoch: int
    latest_sequence_index: int
    latest_entry_checksum: str
    genesis_checksum: str
    context_authority_checksum: str
    head_checksum: str

    def __init__(
        self,
        *,
        ledger_contract_version: object,
        session_epoch: object,
        latest_sequence_index: object,
        latest_entry_checksum: object,
        genesis_checksum: object,
        context_authority_checksum: object,
        head_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _HEAD_CONSTRUCTION_TOKEN:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION)
        normalized_version = _normalize_contract_version(ledger_contract_version)
        normalized_epoch = _normalize_non_negative_int(session_epoch, "session_epoch")
        normalized_seq = _normalize_sequence_index(latest_sequence_index)
        normalized_entry = _normalize_required_checksum(
            latest_entry_checksum, "latest_entry_checksum"
        )
        normalized_genesis = _normalize_required_checksum(genesis_checksum, "genesis_checksum")
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        computed = approval_ledger_head_checksum(
            ledger_contract_version=normalized_version,
            session_epoch=normalized_epoch,
            latest_sequence_index=normalized_seq,
            latest_entry_checksum=normalized_entry,
            genesis_checksum=normalized_genesis,
            context_authority_checksum=normalized_context,
        )
        normalized_head = _normalize_supplied_checksum(head_checksum, computed, "head_checksum")
        object.__setattr__(self, "ledger_contract_version", normalized_version)
        object.__setattr__(self, "session_epoch", normalized_epoch)
        object.__setattr__(self, "latest_sequence_index", normalized_seq)
        object.__setattr__(self, "latest_entry_checksum", normalized_entry)
        object.__setattr__(self, "genesis_checksum", normalized_genesis)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "head_checksum", normalized_head)


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerAppendResult:
    """Checksum-bound result of appending one entry to the approval ledger head."""

    new_entry: ApprovalLedgerEntry
    new_head: ApprovalLedgerHead
    chain_validation: ApprovalLedgerChainValidationResult
    append_result_checksum: str

    def __init__(
        self,
        *,
        new_entry: object,
        new_head: object,
        chain_validation: object,
        append_result_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _APPEND_RESULT_CONSTRUCTION_TOKEN:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION)
        if type(new_entry) is not ApprovalLedgerEntry:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
        if type(new_head) is not ApprovalLedgerHead:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
        if type(chain_validation) is not ApprovalLedgerChainValidationResult:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
        computed = approval_ledger_append_result_checksum(
            new_entry_checksum=new_entry.entry_checksum,
            new_head_checksum=new_head.head_checksum,
            chain_validation_checksum=chain_validation.ledger_validation_checksum,
        )
        normalized_result = _normalize_supplied_checksum(
            append_result_checksum, computed, "append_result_checksum"
        )
        object.__setattr__(self, "new_entry", new_entry)
        object.__setattr__(self, "new_head", new_head)
        object.__setattr__(self, "chain_validation", chain_validation)
        object.__setattr__(self, "append_result_checksum", normalized_result)


@dataclass(frozen=True, slots=True, init=False)
class LedgerEpochManifest:
    """Deterministic epoch binding manifest for one ledger release session."""

    manifest_id: str
    session_epoch: int
    context_authority_checksum: str
    backend_admission_checksum: str
    manifest_checksum: str

    def __init__(
        self,
        *,
        manifest_id: object,
        session_epoch: object,
        context_authority_checksum: object,
        backend_admission_checksum: object,
        manifest_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_required_checksum(manifest_id, "manifest_id")
        normalized_epoch = _normalize_non_negative_int(session_epoch, "session_epoch")
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        normalized_admission = _normalize_required_checksum(
            backend_admission_checksum, "backend_admission_checksum"
        )
        computed = ledger_epoch_manifest_checksum(
            manifest_id=normalized_id,
            session_epoch=normalized_epoch,
            context_authority_checksum=normalized_context,
            backend_admission_checksum=normalized_admission,
        )
        normalized_manifest = _normalize_supplied_checksum(
            manifest_checksum, computed, "manifest_checksum"
        )
        object.__setattr__(self, "manifest_id", normalized_id)
        object.__setattr__(self, "session_epoch", normalized_epoch)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "backend_admission_checksum", normalized_admission)
        object.__setattr__(self, "manifest_checksum", normalized_manifest)


@dataclass(frozen=True, slots=True)
class ApprovalLedgerHeadValidationResult:
    """Result of validating an ApprovalLedgerHead against current evidence."""

    status: ApprovalLedgerHeadStatusValue
    reason_code: str


def build_approval_ledger_head(
    *,
    session_epoch: object,
    context_authority_checksum: object,
    prior_entries: object,
) -> ApprovalLedgerHead:
    """Build an ApprovalLedgerHead from a validated prior entries prefix."""
    if not isinstance(prior_entries, tuple):
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
    for item in cast(tuple[object, ...], prior_entries):
        if type(item) is not ApprovalLedgerEntry:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
    typed_entries = cast(tuple[ApprovalLedgerEntry, ...], prior_entries)
    chain_reason = approval_ledger_prior_chain_block_reason(typed_entries)
    if chain_reason is not None:
        raise ValueError(chain_reason.value)
    normalized_epoch = _normalize_non_negative_int(session_epoch, "session_epoch")
    normalized_context = _normalize_required_checksum(
        context_authority_checksum, "context_authority_checksum"
    )
    genesis = approval_ledger_genesis_head_checksum()
    if typed_entries:
        tip = typed_entries[-1].entry_checksum
        seq = typed_entries[-1].sequence_index
    else:
        tip = genesis
        seq = _EMPTY_SEQUENCE_INDEX
    return ApprovalLedgerHead(
        ledger_contract_version=APPROVAL_LEDGER_CONTRACT_VERSION,
        session_epoch=normalized_epoch,
        latest_sequence_index=seq,
        latest_entry_checksum=tip,
        genesis_checksum=genesis,
        context_authority_checksum=normalized_context,
        _construction_token=_HEAD_CONSTRUCTION_TOKEN,
    )


def append_to_approval_ledger_head(
    *,
    prior_entries: object,
    head: object,
    release_status: object,
    release_decision_checksum: object,
) -> ApprovalLedgerAppendResult:
    """Append one entry to the ledger head, validating chain integrity first."""
    if type(head) is not ApprovalLedgerHead:
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
    if not isinstance(prior_entries, tuple):
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
    for item in cast(tuple[object, ...], prior_entries):
        if type(item) is not ApprovalLedgerEntry:
            raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
    typed_entries = cast(tuple[ApprovalLedgerEntry, ...], prior_entries)
    _validate_head_chain_consistency(head, typed_entries)
    new_entry = append_approval_ledger_entry(
        prior_entries=typed_entries,
        release_status=release_status,
        release_decision_checksum=release_decision_checksum,
    )
    new_entries = typed_entries + (new_entry,)
    new_head = build_approval_ledger_head(
        session_epoch=head.session_epoch,
        context_authority_checksum=head.context_authority_checksum,
        prior_entries=new_entries,
    )
    chain_validation = validate_approval_ledger_chain(new_entries)
    return ApprovalLedgerAppendResult(
        new_entry=new_entry,
        new_head=new_head,
        chain_validation=chain_validation,
        _construction_token=_APPEND_RESULT_CONSTRUCTION_TOKEN,
    )


def validate_approval_ledger_head(
    *,
    head: object,
    prior_entries: object,
    context_authority_checksum: object,
    session_epoch: object,
) -> ApprovalLedgerHeadValidationResult:
    """Return VALID or BLOCKED with reason for a head against current evidence."""
    if type(head) is not ApprovalLedgerHead:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION,
        )
    if head.head_checksum != recompute_approval_ledger_head_checksum(head):
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SHAPE_INVALID,
        )
    if head.genesis_checksum != approval_ledger_genesis_head_checksum():
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_GENESIS_MISMATCH,
        )
    if not isinstance(session_epoch, int) or isinstance(session_epoch, bool):
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SHAPE_INVALID,
        )
    if head.session_epoch != session_epoch:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_STALE_EPOCH,
        )
    if checksum_or_fallback(context_authority_checksum) != context_authority_checksum:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SHAPE_INVALID,
        )
    if head.context_authority_checksum != context_authority_checksum:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_CONTEXT_AUTHORITY_DRIFT,
        )
    if not isinstance(prior_entries, tuple):
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION,
        )
    for item in cast(tuple[object, ...], prior_entries):
        if type(item) is not ApprovalLedgerEntry:
            return ApprovalLedgerHeadValidationResult(
                status="BLOCKED",
                reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION,
            )
    typed_entries = cast(tuple[ApprovalLedgerEntry, ...], prior_entries)
    chain_reason = approval_ledger_prior_chain_block_reason(typed_entries)
    if chain_reason is not None:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SHAPE_INVALID,
        )
    expected_seq = typed_entries[-1].sequence_index if typed_entries else _EMPTY_SEQUENCE_INDEX
    if head.latest_sequence_index != expected_seq:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SEQUENCE_MISMATCH,
        )
    genesis = approval_ledger_genesis_head_checksum()
    expected_tip = typed_entries[-1].entry_checksum if typed_entries else genesis
    if head.latest_entry_checksum != expected_tip:
        return ApprovalLedgerHeadValidationResult(
            status="BLOCKED",
            reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_TIP_MISMATCH,
        )
    return ApprovalLedgerHeadValidationResult(
        status="VALID",
        reason_code=ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_VALID,
    )


def build_ledger_epoch_manifest(
    *,
    session_epoch: object,
    context_authority_checksum: object,
    backend_admission_checksum: object,
) -> LedgerEpochManifest:
    """Build a deterministic ledger epoch manifest for one release session."""
    normalized_epoch = _normalize_non_negative_int(session_epoch, "session_epoch")
    normalized_context = _normalize_required_checksum(
        context_authority_checksum, "context_authority_checksum"
    )
    normalized_admission = _normalize_required_checksum(
        backend_admission_checksum, "backend_admission_checksum"
    )
    manifest_id = _sha256(
        {
            "approval_ledger_head_contract_version": APPROVAL_LEDGER_HEAD_CONTRACT_VERSION,
            "manifest_anchor": "LEDGER_EPOCH_MANIFEST",
            "session_epoch": normalized_epoch,
            "context_authority_checksum": normalized_context,
            "backend_admission_checksum": normalized_admission,
        }
    )
    return LedgerEpochManifest(
        manifest_id=manifest_id,
        session_epoch=normalized_epoch,
        context_authority_checksum=normalized_context,
        backend_admission_checksum=normalized_admission,
    )


def approval_ledger_head_checksum(
    *,
    ledger_contract_version: str,
    session_epoch: int,
    latest_sequence_index: int,
    latest_entry_checksum: str,
    genesis_checksum: str,
    context_authority_checksum: str,
) -> str:
    """Return the deterministic checksum for an ApprovalLedgerHead."""
    return _sha256(
        {
            "approval_ledger_head_contract_version": APPROVAL_LEDGER_HEAD_CONTRACT_VERSION,
            "ledger_contract_version": ledger_contract_version,
            "session_epoch": session_epoch,
            "latest_sequence_index": latest_sequence_index,
            "latest_entry_checksum": latest_entry_checksum,
            "genesis_checksum": genesis_checksum,
            "context_authority_checksum": context_authority_checksum,
        }
    )


def ledger_epoch_manifest_checksum(
    *,
    manifest_id: str,
    session_epoch: int,
    context_authority_checksum: str,
    backend_admission_checksum: str,
) -> str:
    """Return the deterministic checksum for a LedgerEpochManifest."""
    return _sha256(
        {
            "approval_ledger_head_contract_version": APPROVAL_LEDGER_HEAD_CONTRACT_VERSION,
            "manifest_id": manifest_id,
            "session_epoch": session_epoch,
            "context_authority_checksum": context_authority_checksum,
            "backend_admission_checksum": backend_admission_checksum,
        }
    )


def approval_ledger_append_result_checksum(
    *,
    new_entry_checksum: str,
    new_head_checksum: str,
    chain_validation_checksum: str,
) -> str:
    """Return the deterministic checksum for an ApprovalLedgerAppendResult."""
    return _sha256(
        {
            "approval_ledger_head_contract_version": APPROVAL_LEDGER_HEAD_CONTRACT_VERSION,
            "new_entry_checksum": new_entry_checksum,
            "new_head_checksum": new_head_checksum,
            "chain_validation_checksum": chain_validation_checksum,
        }
    )


def recompute_approval_ledger_head_checksum(head: ApprovalLedgerHead) -> str:
    """Recompute an ApprovalLedgerHead checksum from authoritative fields."""
    return approval_ledger_head_checksum(
        ledger_contract_version=head.ledger_contract_version,
        session_epoch=head.session_epoch,
        latest_sequence_index=head.latest_sequence_index,
        latest_entry_checksum=head.latest_entry_checksum,
        genesis_checksum=head.genesis_checksum,
        context_authority_checksum=head.context_authority_checksum,
    )


def recompute_ledger_epoch_manifest_checksum(manifest: LedgerEpochManifest) -> str:
    """Recompute a LedgerEpochManifest checksum from authoritative fields."""
    return ledger_epoch_manifest_checksum(
        manifest_id=manifest.manifest_id,
        session_epoch=manifest.session_epoch,
        context_authority_checksum=manifest.context_authority_checksum,
        backend_admission_checksum=manifest.backend_admission_checksum,
    )


def recompute_approval_ledger_append_result_checksum(
    result: ApprovalLedgerAppendResult,
) -> str:
    """Recompute an ApprovalLedgerAppendResult checksum from authoritative fields."""
    return approval_ledger_append_result_checksum(
        new_entry_checksum=result.new_entry.entry_checksum,
        new_head_checksum=result.new_head.head_checksum,
        chain_validation_checksum=result.chain_validation.ledger_validation_checksum,
    )


def approval_ledger_prior_chain_quarantine_head_block_reason(
    *,
    head: object,
    prior_entries: object,
    context_authority_checksum: object,
    session_epoch: object,
) -> CommandQuarantineReason | None:
    """Map head validation failures to CommandQuarantineReason, or None if valid."""
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=prior_entries,
        context_authority_checksum=context_authority_checksum,
        session_epoch=session_epoch,
    )
    if result.status == "VALID":
        return None
    reason_code = result.reason_code
    if reason_code in {
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION,
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION,
    }:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID


def _validate_head_chain_consistency(
    head: ApprovalLedgerHead,
    entries: tuple[ApprovalLedgerEntry, ...],
) -> None:
    """Raise ValueError if head does not match the given prior entries chain."""
    chain_reason = approval_ledger_prior_chain_block_reason(entries)
    if chain_reason is not None:
        raise ValueError(chain_reason.value)
    genesis = approval_ledger_genesis_head_checksum()
    expected_seq = entries[-1].sequence_index if entries else _EMPTY_SEQUENCE_INDEX
    expected_tip = entries[-1].entry_checksum if entries else genesis
    if head.latest_sequence_index != expected_seq:
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SEQUENCE_MISMATCH)
    if head.latest_entry_checksum != expected_tip:
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_TIP_MISMATCH)
    if head.genesis_checksum != genesis:
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_GENESIS_MISMATCH)


def _normalize_contract_version(value: object) -> str:
    normalized = _normalize_required_text(value, "ledger_contract_version")
    if normalized != APPROVAL_LEDGER_CONTRACT_VERSION:
        raise ValueError(f"ledger_contract_version must be {APPROVAL_LEDGER_CONTRACT_VERSION!r}")
    return normalized


def _normalize_sequence_index(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("latest_sequence_index must be an integer")
    if value < -1:
        raise ValueError("latest_sequence_index must be >= -1")
    return value


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION)
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
    supplied: str | None,
    computed: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied, field_name)
    if normalized is None:
        return computed
    if normalized != computed:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _sha256(payload: Mapping[str, CanonicalLedgerHeadValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalLedgerHeadValue],
) -> dict[str, CanonicalLedgerHeadValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalLedgerHeadValue) -> CanonicalLedgerHeadValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalLedgerHeadValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "ApprovalLedgerAppendResult",
    "ApprovalLedgerHead",
    "ApprovalLedgerHeadReason",
    "ApprovalLedgerHeadStatusValue",
    "ApprovalLedgerHeadValidationResult",
    "LedgerEpochManifest",
    "append_to_approval_ledger_head",
    "approval_ledger_append_result_checksum",
    "approval_ledger_head_checksum",
    "approval_ledger_prior_chain_quarantine_head_block_reason",
    "build_approval_ledger_head",
    "build_ledger_epoch_manifest",
    "ledger_epoch_manifest_checksum",
    "recompute_approval_ledger_append_result_checksum",
    "recompute_approval_ledger_head_checksum",
    "recompute_ledger_epoch_manifest_checksum",
    "validate_approval_ledger_head",
]
