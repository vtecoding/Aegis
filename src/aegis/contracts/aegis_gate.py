"""Gate contracts for deterministic audited-plan decisions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class GateDecisionStatus(StrEnum):
    """Final gate-v1 decision status values."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


class GateBlockReason(StrEnum):
    """Stable gate-v1 block reason codes."""

    CHECKSUM_MISMATCH = "checksum_mismatch"
    AUDIT_ID_MISMATCH = "audit_id_mismatch"
    MALFORMED_AUDITED_PLAN = "malformed_audited_plan"


@dataclass(frozen=True, slots=True, init=False)
class GateDecision:
    """Immutable gate-v1 approval boundary decision.

    Args:
        status: Whether the audited plan is allowed or blocked.
        audit_id: The audited receipt identifier when available.
        plan_id: The command plan identifier when available.
        reasons: Deterministically ordered block reasons. Empty only when allowed.
        checksum_verified: Whether the stored checksum matched recomputation.
        audit_id_verified: Whether the stored audit ID matched recomputation.

    Raises:
        ValueError: If the decision violates gate-v1 status invariants.
    """

    status: GateDecisionStatus
    audit_id: str | None
    plan_id: str | None
    reasons: tuple[GateBlockReason, ...]
    checksum_verified: bool
    audit_id_verified: bool

    def __init__(
        self,
        status: object,
        audit_id: str | None,
        plan_id: str | None,
        reasons: Iterable[GateBlockReason],
        checksum_verified: object,
        audit_id_verified: object,
    ) -> None:
        if not isinstance(status, GateDecisionStatus):
            raise ValueError("status must be a GateDecisionStatus")
        if not isinstance(checksum_verified, bool):
            raise ValueError("checksum_verified must be a bool")
        if not isinstance(audit_id_verified, bool):
            raise ValueError("audit_id_verified must be a bool")

        normalized_reasons = _normalize_reasons(reasons)
        normalized_audit_id = _normalize_optional_identifier(audit_id, "audit_id")
        normalized_plan_id = _normalize_optional_identifier(plan_id, "plan_id")

        if status is GateDecisionStatus.ALLOWED:
            if normalized_reasons != ():
                raise ValueError("allowed decisions must not include block reasons")
            if checksum_verified is not True:
                raise ValueError("allowed decisions must verify checksum")
            if audit_id_verified is not True:
                raise ValueError("allowed decisions must verify audit_id")
            if normalized_audit_id is None:
                raise ValueError("allowed decisions must include audit_id")
            if normalized_plan_id is None:
                raise ValueError("allowed decisions must include plan_id")

        if status is GateDecisionStatus.BLOCKED and normalized_reasons == ():
            raise ValueError("blocked decisions must include at least one reason")

        object.__setattr__(self, "status", status)
        object.__setattr__(self, "audit_id", normalized_audit_id)
        object.__setattr__(self, "plan_id", normalized_plan_id)
        object.__setattr__(self, "reasons", normalized_reasons)
        object.__setattr__(self, "checksum_verified", checksum_verified)
        object.__setattr__(self, "audit_id_verified", audit_id_verified)


def _normalize_reasons(reasons: Iterable[object]) -> tuple[GateBlockReason, ...]:
    normalized: list[GateBlockReason] = []
    for reason in reasons:
        if not isinstance(reason, GateBlockReason):
            raise ValueError("reasons must contain GateBlockReason values")
        normalized.append(reason)
    return tuple(normalized)


def _normalize_optional_identifier(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    stripped_value = value.strip()
    if stripped_value == "":
        raise ValueError(f"{field_name} must be non-empty when provided")
    return stripped_value
