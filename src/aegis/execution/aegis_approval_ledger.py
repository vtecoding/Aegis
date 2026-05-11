"""Deterministic tamper-evident approval ledger for ADR-0024."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import APPROVAL_LEDGER_CONTRACT_VERSION
from aegis.execution.aegis_capability_lease import checksum_or_fallback
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason

type ApprovalLedgerChainStatusValue = Literal["VALID", "BLOCKED"]
type CanonicalApprovalLedgerValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalApprovalLedgerValue]
    | dict[str, CanonicalApprovalLedgerValue]
)

_LEDGER_ENTRY_CONSTRUCTION_TOKEN = object()
_LEDGER_CHAIN_VALIDATION_TOKEN = object()


class ApprovalLedgerReason(StrEnum):
    """Stable ADR-0024 approval ledger reason codes."""

    APPROVAL_LEDGER_VALID = "APPROVAL_LEDGER_VALID"
    APPROVAL_LEDGER_CHAIN_BREAK = "APPROVAL_LEDGER_CHAIN_BREAK"
    APPROVAL_LEDGER_SEQUENCE_INVALID = "APPROVAL_LEDGER_SEQUENCE_INVALID"
    APPROVAL_LEDGER_ENTRY_CHECKSUM_DRIFT = "APPROVAL_LEDGER_ENTRY_CHECKSUM_DRIFT"
    APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION = "APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION"
    DIRECT_APPROVAL_LEDGER_ENTRY_CONSTRUCTION = "DIRECT_APPROVAL_LEDGER_ENTRY_CONSTRUCTION"
    DIRECT_APPROVAL_LEDGER_CHAIN_VALIDATION_CONSTRUCTION = (
        "DIRECT_APPROVAL_LEDGER_CHAIN_VALIDATION_CONSTRUCTION"
    )
    APPROVAL_LEDGER_RELEASE_STATUS_INVALID = "APPROVAL_LEDGER_RELEASE_STATUS_INVALID"


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerEntry:
    """One hash-linked ledger row binding a prior head to one release decision checksum."""

    sequence_index: int
    prior_entry_checksum: str
    release_decision_checksum: str
    entry_checksum: str

    def __init__(
        self,
        *,
        sequence_index: object,
        prior_entry_checksum: object,
        release_decision_checksum: object,
        entry_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _LEDGER_ENTRY_CONSTRUCTION_TOKEN:
            raise ValueError(ApprovalLedgerReason.DIRECT_APPROVAL_LEDGER_ENTRY_CONSTRUCTION.value)
        normalized_sequence = _normalize_non_negative_int(sequence_index, "sequence_index")
        normalized_prior = _normalize_required_checksum(
            prior_entry_checksum, "prior_entry_checksum"
        )
        normalized_release = _normalize_required_checksum(
            release_decision_checksum, "release_decision_checksum"
        )
        computed = approval_ledger_entry_checksum(
            sequence_index=normalized_sequence,
            prior_entry_checksum=normalized_prior,
            release_decision_checksum=normalized_release,
        )
        normalized_entry = _normalize_supplied_checksum(entry_checksum, computed, "entry_checksum")
        object.__setattr__(self, "sequence_index", normalized_sequence)
        object.__setattr__(self, "prior_entry_checksum", normalized_prior)
        object.__setattr__(self, "release_decision_checksum", normalized_release)
        object.__setattr__(self, "entry_checksum", normalized_entry)


@dataclass(frozen=True, slots=True, init=False)
class ApprovalLedgerChainValidationResult:
    """Checksum-bound evidence that a ledger prefix is intact or blocked."""

    status: ApprovalLedgerChainStatusValue
    reason_code: str
    chain_depth: int
    chain_tip_checksum: str
    ledger_validation_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        chain_depth: object,
        chain_tip_checksum: object,
        ledger_validation_checksum: str | None = None,
        _validation_token: object | None = None,
    ) -> None:
        normalized_status = _normalize_chain_status(status)
        normalized_reason = _normalize_reason_code(reason_code)
        if normalized_status == "VALID" and _validation_token is not _LEDGER_CHAIN_VALIDATION_TOKEN:
            raise ValueError(
                ApprovalLedgerReason.DIRECT_APPROVAL_LEDGER_CHAIN_VALIDATION_CONSTRUCTION.value
            )
        if (
            normalized_status == "VALID"
            and normalized_reason != ApprovalLedgerReason.APPROVAL_LEDGER_VALID.value
        ):
            raise ValueError("VALID approval ledger chain requires APPROVAL_LEDGER_VALID")
        if (
            normalized_status == "BLOCKED"
            and normalized_reason == ApprovalLedgerReason.APPROVAL_LEDGER_VALID.value
        ):
            raise ValueError("BLOCKED approval ledger chain requires a blocking reason")
        normalized_depth = _normalize_non_negative_int(chain_depth, "chain_depth")
        normalized_tip = _normalize_required_checksum(chain_tip_checksum, "chain_tip_checksum")
        computed = approval_ledger_chain_validation_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            chain_depth=normalized_depth,
            chain_tip_checksum=normalized_tip,
        )
        normalized_validation = _normalize_supplied_checksum(
            ledger_validation_checksum, computed, "ledger_validation_checksum"
        )
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "chain_depth", normalized_depth)
        object.__setattr__(self, "chain_tip_checksum", normalized_tip)
        object.__setattr__(self, "ledger_validation_checksum", normalized_validation)


def approval_ledger_genesis_head_checksum() -> str:
    """Return the deterministic genesis head checksum for an empty ledger prefix."""
    return _sha256(
        {
            "approval_ledger_contract_version": APPROVAL_LEDGER_CONTRACT_VERSION,
            "ledger_anchor": "GENESIS_HEAD",
        }
    )


def approval_ledger_entry_checksum(
    *,
    sequence_index: int,
    prior_entry_checksum: str,
    release_decision_checksum: str,
) -> str:
    """Return the deterministic checksum for one approval ledger entry."""
    return _sha256(
        {
            "approval_ledger_contract_version": APPROVAL_LEDGER_CONTRACT_VERSION,
            "sequence_index": sequence_index,
            "prior_entry_checksum": prior_entry_checksum,
            "release_decision_checksum": release_decision_checksum,
        }
    )


def recompute_approval_ledger_entry_checksum(entry: ApprovalLedgerEntry) -> str:
    """Recompute an ApprovalLedgerEntry checksum from authoritative fields."""
    return approval_ledger_entry_checksum(
        sequence_index=entry.sequence_index,
        prior_entry_checksum=entry.prior_entry_checksum,
        release_decision_checksum=entry.release_decision_checksum,
    )


def approval_ledger_chain_validation_checksum(
    *,
    status: ApprovalLedgerChainStatusValue,
    reason_code: str,
    chain_depth: int,
    chain_tip_checksum: str,
) -> str:
    """Return the deterministic checksum for an approval ledger chain validation result."""
    return _sha256(
        {
            "approval_ledger_contract_version": APPROVAL_LEDGER_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "chain_depth": chain_depth,
            "chain_tip_checksum": chain_tip_checksum,
        }
    )


def recompute_approval_ledger_chain_validation_checksum(
    result: ApprovalLedgerChainValidationResult,
) -> str:
    """Recompute an ApprovalLedgerChainValidationResult checksum from authoritative fields."""
    return approval_ledger_chain_validation_checksum(
        status=result.status,
        reason_code=result.reason_code,
        chain_depth=result.chain_depth,
        chain_tip_checksum=result.chain_tip_checksum,
    )


def approval_ledger_prior_chain_block_reason(
    entries: tuple[ApprovalLedgerEntry, ...],
) -> ApprovalLedgerReason | None:
    """Return the first deterministic reason a ledger prefix is not well-formed."""
    expected_prior = approval_ledger_genesis_head_checksum()
    for expected_sequence, entry in enumerate(entries):
        if type(entry) is not ApprovalLedgerEntry:
            return ApprovalLedgerReason.APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION
        if entry.sequence_index != expected_sequence:
            return ApprovalLedgerReason.APPROVAL_LEDGER_SEQUENCE_INVALID
        if entry.prior_entry_checksum != expected_prior:
            return ApprovalLedgerReason.APPROVAL_LEDGER_CHAIN_BREAK
        if entry.entry_checksum != recompute_approval_ledger_entry_checksum(entry):
            return ApprovalLedgerReason.APPROVAL_LEDGER_ENTRY_CHECKSUM_DRIFT
        expected_prior = entry.entry_checksum
    return None


def approval_ledger_prior_chain_quarantine_block_reason(
    prior_entries: object,
) -> CommandQuarantineReason | None:
    """Map a supplied prior ledger prefix to a quarantine release block reason, if any."""
    if not isinstance(prior_entries, tuple):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    typed_entries: list[ApprovalLedgerEntry] = []
    for item in cast(tuple[object, ...], prior_entries):
        if type(item) is not ApprovalLedgerEntry:
            return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
        typed_entries.append(item)
    ledger_reason = approval_ledger_prior_chain_block_reason(tuple(typed_entries))
    if ledger_reason is None:
        return None
    if ledger_reason is ApprovalLedgerReason.APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_CHAIN_INVALID


def validate_approval_ledger_chain(
    entries: tuple[ApprovalLedgerEntry, ...],
) -> ApprovalLedgerChainValidationResult:
    """Return a checksum-bound validation result for one ledger prefix."""
    reason = approval_ledger_prior_chain_block_reason(entries)
    if reason is not None:
        return ApprovalLedgerChainValidationResult(
            status="BLOCKED",
            reason_code=reason.value,
            chain_depth=0,
            chain_tip_checksum=checksum_or_fallback(None),
            ledger_validation_checksum=None,
        )
    tip = entries[-1].entry_checksum if entries else approval_ledger_genesis_head_checksum()
    return ApprovalLedgerChainValidationResult(
        status="VALID",
        reason_code=ApprovalLedgerReason.APPROVAL_LEDGER_VALID.value,
        chain_depth=len(entries),
        chain_tip_checksum=tip,
        ledger_validation_checksum=None,
        _validation_token=_LEDGER_CHAIN_VALIDATION_TOKEN,
    )


def append_approval_ledger_entry(
    *,
    prior_entries: tuple[ApprovalLedgerEntry, ...],
    release_status: object,
    release_decision_checksum: object,
) -> ApprovalLedgerEntry:
    """Append one ledger row after validating the prior prefix and release status."""
    chain_reason = approval_ledger_prior_chain_block_reason(prior_entries)
    if chain_reason is not None:
        raise ValueError(chain_reason.value)
    _normalize_release_status(release_status)
    normalized_release = _normalize_required_checksum(
        release_decision_checksum, "release_decision_checksum"
    )
    prior_head = (
        prior_entries[-1].entry_checksum
        if prior_entries
        else approval_ledger_genesis_head_checksum()
    )
    sequence_index = len(prior_entries)
    return ApprovalLedgerEntry(
        sequence_index=sequence_index,
        prior_entry_checksum=prior_head,
        release_decision_checksum=normalized_release,
        _construction_token=_LEDGER_ENTRY_CONSTRUCTION_TOKEN,
    )


def _normalize_release_status(value: object) -> str:
    if value == "RELEASED_DRY_RUN":
        return "RELEASED_DRY_RUN"
    raise ValueError(ApprovalLedgerReason.APPROVAL_LEDGER_RELEASE_STATUS_INVALID.value)


def _normalize_chain_status(value: object) -> ApprovalLedgerChainStatusValue:
    if value in {"VALID", "BLOCKED"}:
        return cast(ApprovalLedgerChainStatusValue, value)
    raise ValueError("status must be VALID or BLOCKED")


def _normalize_reason_code(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(ApprovalLedgerReason.APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION.value)
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


def _sha256(payload: Mapping[str, CanonicalApprovalLedgerValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalApprovalLedgerValue],
) -> dict[str, CanonicalApprovalLedgerValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalApprovalLedgerValue) -> CanonicalApprovalLedgerValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalApprovalLedgerValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "ApprovalLedgerChainStatusValue",
    "ApprovalLedgerChainValidationResult",
    "ApprovalLedgerEntry",
    "ApprovalLedgerReason",
    "append_approval_ledger_entry",
    "approval_ledger_chain_validation_checksum",
    "approval_ledger_entry_checksum",
    "approval_ledger_genesis_head_checksum",
    "approval_ledger_prior_chain_block_reason",
    "approval_ledger_prior_chain_quarantine_block_reason",
    "recompute_approval_ledger_chain_validation_checksum",
    "recompute_approval_ledger_entry_checksum",
    "validate_approval_ledger_chain",
]
