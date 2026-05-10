"""Operator approval receipts for ADR-0022 quarantine release."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, cast

from aegis.aegis_constants import COMMAND_QUARANTINE_CONTRACT_VERSION
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    CommandQuarantineReason,
    checksum_or_fallback,
    quarantine_item_checksums,
    recompute_command_quarantine_checksum,
)

type OperatorApprovalStatusValue = Literal["APPROVED", "REJECTED"]
type CanonicalOperatorApprovalValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalOperatorApprovalValue]
    | dict[str, CanonicalOperatorApprovalValue]
)


class OperatorApprovalStatus(StrEnum):
    """Closed ADR-0022 operator approval statuses."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True, init=False)
class OperatorApprovalReceipt:
    """Checksum-bound explicit operator approval or rejection receipt."""

    approval_id: str
    operator_id: str
    approval_status: OperatorApprovalStatus
    quarantine_checksum: str
    approved_scope: frozenset[str]
    approval_epoch: int
    approval_reason: str
    approval_checksum: str

    def __init__(
        self,
        *,
        approval_id: object,
        operator_id: object,
        approval_status: object,
        quarantine_checksum: object,
        approved_scope: Iterable[object],
        approval_epoch: object,
        approval_reason: object,
        approval_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_required_checksum(approval_id, "approval_id")
        normalized_operator = normalize_operator_id(operator_id)
        normalized_status = _normalize_approval_status(approval_status)
        normalized_quarantine = _normalize_required_checksum(
            quarantine_checksum, "quarantine_checksum"
        )
        normalized_scope = normalize_approval_scope(approved_scope)
        normalized_epoch = _normalize_non_negative_int(approval_epoch, "approval_epoch")
        normalized_reason = _normalize_required_text(approval_reason, "approval_reason")
        computed_checksum = operator_approval_receipt_checksum(
            approval_id=normalized_id,
            operator_id=normalized_operator,
            approval_status=normalized_status,
            quarantine_checksum=normalized_quarantine,
            approved_scope=normalized_scope,
            approval_epoch=normalized_epoch,
            approval_reason=normalized_reason,
        )
        normalized_checksum = _normalize_supplied_checksum(
            approval_checksum, computed_checksum, "approval_checksum"
        )

        object.__setattr__(self, "approval_id", normalized_id)
        object.__setattr__(self, "operator_id", normalized_operator)
        object.__setattr__(self, "approval_status", normalized_status)
        object.__setattr__(self, "quarantine_checksum", normalized_quarantine)
        object.__setattr__(self, "approved_scope", normalized_scope)
        object.__setattr__(self, "approval_epoch", normalized_epoch)
        object.__setattr__(self, "approval_reason", normalized_reason)
        object.__setattr__(self, "approval_checksum", normalized_checksum)


def build_operator_approval_receipt(
    *,
    quarantine: object,
    operator_id: object,
    approval_status: object,
    approved_scope: Iterable[object],
    approval_epoch: object,
    approval_reason: object,
) -> OperatorApprovalReceipt:
    """Build an operator receipt scoped to a concrete quarantine envelope.

    Args:
        quarantine: Quarantine envelope whose checksum the receipt approves or rejects.
        operator_id: Explicit operator identifier. This is structural only; ADR-0023 owns auth.
        approval_status: APPROVED or REJECTED.
        approved_scope: Explicit non-wildcard set of quarantined item checksums.
        approval_epoch: Caller-supplied deterministic approval epoch.
        approval_reason: Non-empty operator-supplied machine/audit reason.

    Returns:
        A checksum-bound operator approval or rejection receipt.

    Raises:
        ValueError: If quarantine evidence is drifted or scope is not subset-bounded.
    """
    if type(quarantine) is not CommandQuarantineEnvelope:
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    if quarantine.quarantine_checksum != recompute_command_quarantine_checksum(quarantine):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_CHECKSUM_DRIFT.value)
    normalized_scope = normalize_approval_scope(approved_scope)
    item_scope = quarantine_item_checksums(quarantine)
    if not normalized_scope.issubset(item_scope):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE.value)
    normalized_operator = normalize_operator_id(operator_id)
    normalized_status = _normalize_approval_status(approval_status)
    normalized_epoch = _normalize_non_negative_int(approval_epoch, "approval_epoch")
    normalized_reason = _normalize_required_text(approval_reason, "approval_reason")
    approval_id = operator_approval_id(
        operator_id=normalized_operator,
        approval_status=normalized_status,
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=normalized_scope,
        approval_epoch=normalized_epoch,
        approval_reason=normalized_reason,
    )
    return OperatorApprovalReceipt(
        approval_id=approval_id,
        operator_id=normalized_operator,
        approval_status=normalized_status,
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=normalized_scope,
        approval_epoch=normalized_epoch,
        approval_reason=normalized_reason,
    )


def operator_approval_id(
    *,
    operator_id: str,
    approval_status: OperatorApprovalStatus | str,
    quarantine_checksum: str,
    approved_scope: Iterable[str],
    approval_epoch: int,
    approval_reason: str,
) -> str:
    """Return the deterministic identifier for an operator approval receipt."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "operator_id": operator_id,
            "approval_status": _status_checksum_value(approval_status),
            "quarantine_checksum": quarantine_checksum,
            "approved_scope": _canonical_string_sequence(sorted(approved_scope)),
            "approval_epoch": approval_epoch,
            "approval_reason": approval_reason,
        }
    )


def operator_approval_receipt_checksum(
    *,
    approval_id: str,
    operator_id: str,
    approval_status: OperatorApprovalStatus | str,
    quarantine_checksum: str,
    approved_scope: Iterable[str],
    approval_epoch: int,
    approval_reason: str,
) -> str:
    """Return the deterministic checksum for an operator approval receipt."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "approval_id": approval_id,
            "operator_id": operator_id,
            "approval_status": _status_checksum_value(approval_status),
            "quarantine_checksum": quarantine_checksum,
            "approved_scope": _canonical_string_sequence(sorted(approved_scope)),
            "approval_epoch": approval_epoch,
            "approval_reason": approval_reason,
        }
    )


def recompute_operator_approval_checksum(receipt: OperatorApprovalReceipt) -> str:
    """Recompute an OperatorApprovalReceipt checksum from authoritative fields."""
    return operator_approval_receipt_checksum(
        approval_id=receipt.approval_id,
        operator_id=receipt.operator_id,
        approval_status=receipt.approval_status,
        quarantine_checksum=receipt.quarantine_checksum,
        approved_scope=receipt.approved_scope,
        approval_epoch=receipt.approval_epoch,
        approval_reason=receipt.approval_reason,
    )


def normalize_approval_scope(values: Iterable[object]) -> frozenset[str]:
    """Normalize an explicit non-wildcard set of quarantined item checksums."""
    if isinstance(values, (str, Mapping)) or callable(values):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
    normalized: set[str] = set()
    for value in values:
        if callable(value):
            raise ValueError(
                CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
            )
        if value == "*":
            raise ValueError(
                CommandQuarantineReason.COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE.value
            )
        normalized.add(_normalize_required_checksum(value, "approved_scope"))
    if not normalized:
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY.value)
    return frozenset(normalized)


def normalize_operator_id(value: object) -> str:
    """Normalize the structural operator identifier used by ADR-0022 receipts."""
    try:
        normalized = _normalize_required_text(value, "operator_id")
    except ValueError as exc:
        raise ValueError(
            CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED.value
        ) from exc
    if normalized == "*" or fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", normalized) is None:
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED.value)
    return normalized


def approval_checksum_or_fallback(value: object) -> str:
    """Return a valid approval checksum string or the closed fallback checksum."""
    if type(value) is OperatorApprovalReceipt:
        return checksum_or_fallback(value.approval_checksum)
    return checksum_or_fallback(getattr(value, "approval_checksum", None))


def _normalize_approval_status(value: object) -> OperatorApprovalStatus:
    if isinstance(value, OperatorApprovalStatus):
        return value
    if isinstance(value, str):
        try:
            return OperatorApprovalStatus(value)
        except ValueError:
            raise ValueError(
                CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value
            ) from None
    raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value)


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value)
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


def _status_checksum_value(value: OperatorApprovalStatus | str) -> str:
    if isinstance(value, OperatorApprovalStatus):
        return value.value
    return value


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalOperatorApprovalValue]:
    return [str(value) for value in values]


def _sha256(payload: Mapping[str, CanonicalOperatorApprovalValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalOperatorApprovalValue],
) -> dict[str, CanonicalOperatorApprovalValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalOperatorApprovalValue) -> CanonicalOperatorApprovalValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalOperatorApprovalValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "OperatorApprovalReceipt",
    "OperatorApprovalStatus",
    "OperatorApprovalStatusValue",
    "approval_checksum_or_fallback",
    "build_operator_approval_receipt",
    "normalize_approval_scope",
    "normalize_operator_id",
    "operator_approval_id",
    "operator_approval_receipt_checksum",
    "recompute_operator_approval_checksum",
]
