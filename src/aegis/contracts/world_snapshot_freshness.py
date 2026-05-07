"""Deterministic World Snapshot Freshness contracts (Phase 2 Part 5).

This module provides the deterministic freshness gate that runs before policy
admission. It evaluates whether a caller-supplied :class:`WorldSnapshotStub`
is fresh enough to back an approval, using a caller-supplied evaluation
timestamp. No wall-clock time, environment reads, or randomness are used.

Part 5 proves only deterministic freshness against caller-supplied evaluation
time. It does not prove the snapshot corresponds to physical reality. Evidence
trust, attestation, source identity signatures, and live sensing remain
future work.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from aegis.contracts.policy import WorldSnapshotStub
from aegis.errors import AegisError


class WorldSnapshotFreshnessError(AegisError):
    """Raised when freshness integrity checks fail catastrophically."""


class WorldSnapshotFreshnessStatus(StrEnum):
    """Phase 2 Part 5 freshness status values."""

    FRESH = "FRESH"
    STALE = "STALE"
    MISSING_SNAPSHOT = "MISSING_SNAPSHOT"
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"
    MISSING_EVALUATION_TIME = "MISSING_EVALUATION_TIME"
    FUTURE_DATED = "FUTURE_DATED"
    INVALID_MAX_AGE = "INVALID_MAX_AGE"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    SNAPSHOT_ID_MISSING = "SNAPSHOT_ID_MISSING"
    CONTRADICTORY_METADATA = "CONTRADICTORY_METADATA"
    NOT_CHECKED = "NOT_CHECKED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True, init=False)
class FreshnessPolicy:
    """Deterministic freshness policy bounding the maximum acceptable snapshot age.

    Args:
        max_snapshot_age_ms: Maximum acceptable age in milliseconds. Must be > 0.
        allow_future_observed_at: Whether observed_at_ms strictly greater than
            evaluation_time_ms is permitted (still bounded by max_future_skew_ms).
        max_future_skew_ms: Maximum permitted future skew in milliseconds when
            ``allow_future_observed_at`` is True. Must be >= 0.

    Raises:
        ValueError: If thresholds are non-int, negative, or otherwise invalid.
    """

    max_snapshot_age_ms: int
    allow_future_observed_at: bool
    max_future_skew_ms: int

    def __init__(
        self,
        max_snapshot_age_ms: object,
        allow_future_observed_at: object = False,
        max_future_skew_ms: object = 0,
    ) -> None:
        if isinstance(max_snapshot_age_ms, bool) or not isinstance(max_snapshot_age_ms, int):
            raise ValueError("max_snapshot_age_ms must be an integer")
        if max_snapshot_age_ms <= 0:
            raise ValueError("max_snapshot_age_ms must be greater than 0")
        if not isinstance(allow_future_observed_at, bool):
            raise ValueError("allow_future_observed_at must be a bool")
        if isinstance(max_future_skew_ms, bool) or not isinstance(max_future_skew_ms, int):
            raise ValueError("max_future_skew_ms must be an integer")
        if max_future_skew_ms < 0:
            raise ValueError("max_future_skew_ms must be >= 0")
        if not allow_future_observed_at and max_future_skew_ms != 0:
            raise ValueError("max_future_skew_ms must be 0 when allow_future_observed_at is False")

        object.__setattr__(self, "max_snapshot_age_ms", max_snapshot_age_ms)
        object.__setattr__(self, "allow_future_observed_at", allow_future_observed_at)
        object.__setattr__(self, "max_future_skew_ms", max_future_skew_ms)


DEFAULT_MAX_SNAPSHOT_AGE_MS = 1000
"""Default maximum acceptable snapshot age (Part 5)."""

DEFAULT_FRESHNESS_POLICY = FreshnessPolicy(DEFAULT_MAX_SNAPSHOT_AGE_MS)
"""Strict default freshness policy: future timestamps rejected, 1s max age."""


def _runtime_attribute(instance: object, name: str) -> object:
    return object.__getattribute__(instance, name)


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotFreshnessResult:
    """Deterministic result of evaluating a world snapshot's freshness.

    Args:
        snapshot_id: Snapshot identity bound by this result. Empty string only
            when the snapshot itself was missing.
        observed_at_ms: Snapshot observation time used for the check. ``-1``
            sentinel only when the snapshot or its timestamp was missing.
        evaluation_time_ms: Caller-supplied evaluation time. ``-1`` sentinel
            only when evaluation_time was missing.
        age_ms: Computed age. ``-1`` sentinel when age could not be computed.
        max_allowed_age_ms: Effective maximum age threshold from policy.
        status: Reason status. ``FRESH`` only when all checks passed.
        is_fresh: Convenience flag — True only when ``status == FRESH``.
        reason: Stable machine-readable reason code.
        checksum: Deterministic SHA-256 over the canonical content.

    Raises:
        ValueError: If is_fresh contradicts status, checksum is invalid, or
            FRESH state contradicts age/timestamp invariants.
    """

    snapshot_id: str
    observed_at_ms: int
    evaluation_time_ms: int
    age_ms: int
    max_allowed_age_ms: int
    status: WorldSnapshotFreshnessStatus
    is_fresh: bool
    reason: str
    checksum: str

    def __init__(
        self,
        *,
        snapshot_id: str,
        observed_at_ms: int,
        evaluation_time_ms: int,
        age_ms: int,
        max_allowed_age_ms: int,
        status: WorldSnapshotFreshnessStatus,
        is_fresh: bool,
        reason: str,
        checksum: str,
    ) -> None:
        if not isinstance(status, WorldSnapshotFreshnessStatus):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError("status must be a WorldSnapshotFreshnessStatus")
        if not isinstance(is_fresh, bool):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError("is_fresh must be a bool")
        if status is WorldSnapshotFreshnessStatus.FRESH:
            if not is_fresh:
                raise ValueError("FRESH status requires is_fresh=True")
            if snapshot_id == "":
                raise ValueError("FRESH status requires non-empty snapshot_id")
            if observed_at_ms < 0 or evaluation_time_ms < 0:
                raise ValueError("FRESH status requires valid timestamps")
            if max_allowed_age_ms <= 0:
                raise ValueError("FRESH status requires positive max_allowed_age_ms")
            if age_ms < 0 or age_ms > max_allowed_age_ms:
                raise ValueError("FRESH status requires age_ms within bounds")
        elif is_fresh:
            raise ValueError("is_fresh=True requires status=FRESH")
        if reason.strip() == "":
            raise ValueError("reason must be non-empty")
        if len(checksum) != 64 or not all(c in "0123456789abcdef" for c in checksum):
            raise ValueError("checksum must be a 64-char lowercase hex SHA-256")

        object.__setattr__(self, "snapshot_id", snapshot_id)
        object.__setattr__(self, "observed_at_ms", observed_at_ms)
        object.__setattr__(self, "evaluation_time_ms", evaluation_time_ms)
        object.__setattr__(self, "age_ms", age_ms)
        object.__setattr__(self, "max_allowed_age_ms", max_allowed_age_ms)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "is_fresh", is_fresh)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "checksum", checksum)


def world_snapshot_freshness_checksum(
    *,
    snapshot_id: str,
    observed_at_ms: int,
    evaluation_time_ms: int,
    age_ms: int,
    max_allowed_age_ms: int,
    status: WorldSnapshotFreshnessStatus,
    is_fresh: bool,
    reason: str,
) -> str:
    """Compute a deterministic SHA-256 checksum over canonical freshness fields."""
    payload = {
        "snapshot_id": snapshot_id,
        "observed_at_ms": observed_at_ms,
        "evaluation_time_ms": evaluation_time_ms,
        "age_ms": age_ms,
        "max_allowed_age_ms": max_allowed_age_ms,
        "status": status.value,
        "is_fresh": is_fresh,
        "reason": reason,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_result(
    *,
    snapshot_id: str,
    observed_at_ms: int,
    evaluation_time_ms: int,
    age_ms: int,
    max_allowed_age_ms: int,
    status: WorldSnapshotFreshnessStatus,
    reason: str,
) -> WorldSnapshotFreshnessResult:
    is_fresh = status is WorldSnapshotFreshnessStatus.FRESH
    checksum = world_snapshot_freshness_checksum(
        snapshot_id=snapshot_id,
        observed_at_ms=observed_at_ms,
        evaluation_time_ms=evaluation_time_ms,
        age_ms=age_ms,
        max_allowed_age_ms=max_allowed_age_ms,
        status=status,
        is_fresh=is_fresh,
        reason=reason,
    )
    return WorldSnapshotFreshnessResult(
        snapshot_id=snapshot_id,
        observed_at_ms=observed_at_ms,
        evaluation_time_ms=evaluation_time_ms,
        age_ms=age_ms,
        max_allowed_age_ms=max_allowed_age_ms,
        status=status,
        is_fresh=is_fresh,
        reason=reason,
        checksum=checksum,
    )


def validate_world_snapshot_freshness(
    snapshot: WorldSnapshotStub | None,
    *,
    evaluation_time_ms: object,
    freshness_policy: object,
) -> WorldSnapshotFreshnessResult:
    """Deterministically validate a world snapshot's freshness.

    Args:
        snapshot: The world snapshot stub to evaluate, or ``None``.
        evaluation_time_ms: Caller-supplied evaluation time in milliseconds. Must
            be a non-negative ``int`` (rejecting ``bool`` and ``float``).
        freshness_policy: Caller-supplied freshness threshold contract.

    Returns:
        A ``WorldSnapshotFreshnessResult`` with status ``FRESH`` only when all
        checks pass; otherwise a structured non-fresh result with a stable
        reason code.
    """
    if not isinstance(freshness_policy, FreshnessPolicy):
        return _build_result(
            snapshot_id="",
            observed_at_ms=-1,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=-1,
            status=WorldSnapshotFreshnessStatus.INVALID_MAX_AGE,
            reason="FRESHNESS_POLICY_INVALID",
        )

    max_age_value = _runtime_attribute(freshness_policy, "max_snapshot_age_ms")
    if isinstance(max_age_value, bool) or not isinstance(max_age_value, int) or max_age_value <= 0:
        return _build_result(
            snapshot_id="",
            observed_at_ms=-1,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=-1,
            status=WorldSnapshotFreshnessStatus.INVALID_MAX_AGE,
            reason="FRESHNESS_POLICY_INVALID",
        )
    max_age = max_age_value

    allow_future_value = _runtime_attribute(freshness_policy, "allow_future_observed_at")
    max_future_skew_value = _runtime_attribute(freshness_policy, "max_future_skew_ms")
    if not isinstance(allow_future_value, bool):
        return _build_result(
            snapshot_id="",
            observed_at_ms=-1,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=-1,
            status=WorldSnapshotFreshnessStatus.INVALID_MAX_AGE,
            reason="FRESHNESS_POLICY_INVALID",
        )
    if (
        isinstance(max_future_skew_value, bool)
        or not isinstance(max_future_skew_value, int)
        or max_future_skew_value < 0
    ):
        return _build_result(
            snapshot_id="",
            observed_at_ms=-1,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=-1,
            status=WorldSnapshotFreshnessStatus.INVALID_MAX_AGE,
            reason="FRESHNESS_POLICY_INVALID",
        )

    if snapshot is None:
        return _build_result(
            snapshot_id="",
            observed_at_ms=-1,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.MISSING_SNAPSHOT,
            reason="WORLD_SNAPSHOT_MISSING",
        )

    snapshot_id_value = _runtime_attribute(snapshot, "snapshot_id")
    snapshot_id = snapshot_id_value if isinstance(snapshot_id_value, str) else ""
    observed_at_value = _runtime_attribute(snapshot, "captured_at_ms")
    observed_at_for_error = (
        observed_at_value
        if isinstance(observed_at_value, int) and not isinstance(observed_at_value, bool)
        else -1
    )

    if isinstance(evaluation_time_ms, bool) or not isinstance(evaluation_time_ms, int):
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_for_error,
            evaluation_time_ms=-1,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.MISSING_EVALUATION_TIME,
            reason="EVALUATION_TIME_REQUIRED",
        )
    if evaluation_time_ms < 0:
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_for_error,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP,
            reason="EVALUATION_TIME_NEGATIVE",
        )

    if snapshot_id == "":
        return _build_result(
            snapshot_id="",
            observed_at_ms=observed_at_for_error,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.SNAPSHOT_ID_MISSING,
            reason="SNAPSHOT_ID_MISSING",
        )

    if observed_at_value is None:
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=-1,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.MISSING_TIMESTAMP,
            reason="OBSERVED_AT_REQUIRED",
        )
    if isinstance(observed_at_value, bool) or not isinstance(observed_at_value, int):
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=-1,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP,
            reason="OBSERVED_AT_INVALID",
        )

    observed_at_ms = observed_at_value
    if observed_at_ms < 0:
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP,
            reason="OBSERVED_AT_NEGATIVE",
        )

    expires_at_value = _runtime_attribute(snapshot, "expires_at_ms")
    if isinstance(expires_at_value, bool) or not isinstance(expires_at_value, int):
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP,
            reason="EXPIRES_AT_INVALID",
        )
    if expires_at_value < observed_at_ms:
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=-1,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.CONTRADICTORY_METADATA,
            reason="EXPIRES_BEFORE_CAPTURED",
        )

    if observed_at_ms > evaluation_time_ms:
        skew = observed_at_ms - evaluation_time_ms
        if not allow_future_value or skew > max_future_skew_value:
            return _build_result(
                snapshot_id=snapshot_id,
                observed_at_ms=observed_at_ms,
                evaluation_time_ms=evaluation_time_ms,
                age_ms=-1,
                max_allowed_age_ms=max_age,
                status=WorldSnapshotFreshnessStatus.FUTURE_DATED,
                reason="OBSERVED_AT_IN_FUTURE",
            )
        # Within future skew: treat age as 0 for evaluation purposes.
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=0,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.FRESH,
            reason="WORLD_SNAPSHOT_FRESH",
        )

    age_ms = evaluation_time_ms - observed_at_ms
    if age_ms > max_age:
        return _build_result(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=age_ms,
            max_allowed_age_ms=max_age,
            status=WorldSnapshotFreshnessStatus.STALE,
            reason="WORLD_SNAPSHOT_STALE",
        )

    return _build_result(
        snapshot_id=snapshot_id,
        observed_at_ms=observed_at_ms,
        evaluation_time_ms=evaluation_time_ms,
        age_ms=age_ms,
        max_allowed_age_ms=max_age,
        status=WorldSnapshotFreshnessStatus.FRESH,
        reason="WORLD_SNAPSHOT_FRESH",
    )


def assert_world_snapshot_freshness_integrity(
    *,
    snapshot: WorldSnapshotStub,
    freshness_result: WorldSnapshotFreshnessResult,
    evaluation_time_ms: int,
    freshness_policy: FreshnessPolicy,
) -> WorldSnapshotFreshnessResult:
    """Verify that a freshness result is bound to the exact snapshot/policy/time.

    Args:
        snapshot: The world snapshot freshness was evaluated for.
        freshness_result: The freshness result to verify.
        evaluation_time_ms: Caller-supplied evaluation time used for the check.
        freshness_policy: The freshness policy used for the check.

    Returns:
        The same ``freshness_result`` when integrity passes.

    Raises:
        WorldSnapshotFreshnessError: If any binding mismatches, the result is
            forged, or status is not ``FRESH``.
    """
    violations: list[str] = []
    if freshness_result.snapshot_id != snapshot.snapshot_id:
        violations.append("SNAPSHOT_ID_MISMATCH")
    if freshness_result.observed_at_ms != snapshot.captured_at_ms:
        violations.append("OBSERVED_AT_MISMATCH")
    if freshness_result.evaluation_time_ms != evaluation_time_ms:
        violations.append("EVALUATION_TIME_MISMATCH")
    if freshness_result.max_allowed_age_ms != freshness_policy.max_snapshot_age_ms:
        violations.append("MAX_ALLOWED_AGE_MISMATCH")
    expected_checksum = world_snapshot_freshness_checksum(
        snapshot_id=freshness_result.snapshot_id,
        observed_at_ms=freshness_result.observed_at_ms,
        evaluation_time_ms=freshness_result.evaluation_time_ms,
        age_ms=freshness_result.age_ms,
        max_allowed_age_ms=freshness_result.max_allowed_age_ms,
        status=freshness_result.status,
        is_fresh=freshness_result.is_fresh,
        reason=freshness_result.reason,
    )
    if freshness_result.checksum != expected_checksum:
        violations.append("CHECKSUM_MISMATCH")
    if freshness_result.status is not WorldSnapshotFreshnessStatus.FRESH:
        violations.append("STATUS_NOT_FRESH")
    if not freshness_result.is_fresh:
        violations.append("IS_FRESH_FALSE")
    if violations:
        raise WorldSnapshotFreshnessError(
            message="World snapshot freshness integrity check failed",
            layer="policy",
            context={
                "snapshot_id": snapshot.snapshot_id,
                "reasons": list(violations),
            },
        )
    return freshness_result


def is_freshness_backed_admission(
    *,
    freshness_result: WorldSnapshotFreshnessResult | None,
    expected_snapshot_id: str | None,
    expected_observed_at_ms: int | None,
    expected_freshness_checksum: str | None,
) -> bool:
    """Return True only when admission carries a fully-bound FRESH result."""
    if freshness_result is None:
        return False
    if freshness_result.status is not WorldSnapshotFreshnessStatus.FRESH:
        return False
    if not freshness_result.is_fresh:
        return False
    if expected_snapshot_id is None or freshness_result.snapshot_id != expected_snapshot_id:
        return False
    if (
        expected_observed_at_ms is None
        or freshness_result.observed_at_ms != expected_observed_at_ms
    ):
        return False
    return (
        expected_freshness_checksum is not None
        and freshness_result.checksum == expected_freshness_checksum
    )


__all__ = [
    "DEFAULT_FRESHNESS_POLICY",
    "DEFAULT_MAX_SNAPSHOT_AGE_MS",
    "FreshnessPolicy",
    "WorldSnapshotFreshnessError",
    "WorldSnapshotFreshnessResult",
    "WorldSnapshotFreshnessStatus",
    "assert_world_snapshot_freshness_integrity",
    "is_freshness_backed_admission",
    "validate_world_snapshot_freshness",
    "world_snapshot_freshness_checksum",
]
