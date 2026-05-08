"""Contract tests for deterministic world snapshot freshness validation."""

from __future__ import annotations

from typing import cast

import pytest
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    FRESH_OBSERVED_AT_MS,
    fresh_world_snapshot,
)

from aegis.contracts.world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    FreshnessPolicy,
    WorldSnapshotFreshnessError,
    WorldSnapshotFreshnessResult,
    WorldSnapshotFreshnessStatus,
    assert_world_snapshot_freshness_integrity,
    is_freshness_backed_admission,
    validate_world_snapshot_freshness,
    world_snapshot_freshness_checksum,
)


def _checksum(
    *,
    snapshot_id: str = "snapshot-1",
    observed_at_ms: int = 10,
    evaluation_time_ms: int = 10,
    age_ms: int = 0,
    max_allowed_age_ms: int = 1000,
    status: WorldSnapshotFreshnessStatus = WorldSnapshotFreshnessStatus.FRESH,
    is_fresh: bool = True,
    reason: str = "WORLD_SNAPSHOT_FRESH",
) -> str:
    return world_snapshot_freshness_checksum(
        snapshot_id=snapshot_id,
        observed_at_ms=observed_at_ms,
        evaluation_time_ms=evaluation_time_ms,
        age_ms=age_ms,
        max_allowed_age_ms=max_allowed_age_ms,
        status=status,
        is_fresh=is_fresh,
        reason=reason,
    )


def _freshness_result(
    *,
    snapshot_id: str = "snapshot-1",
    observed_at_ms: int = 10,
    evaluation_time_ms: int = 10,
    age_ms: int = 0,
    max_allowed_age_ms: int = 1000,
    status: WorldSnapshotFreshnessStatus = WorldSnapshotFreshnessStatus.FRESH,
    is_fresh: bool = True,
    reason: str = "WORLD_SNAPSHOT_FRESH",
    checksum: str | None = None,
) -> WorldSnapshotFreshnessResult:
    return WorldSnapshotFreshnessResult(
        snapshot_id=snapshot_id,
        observed_at_ms=observed_at_ms,
        evaluation_time_ms=evaluation_time_ms,
        age_ms=age_ms,
        max_allowed_age_ms=max_allowed_age_ms,
        status=status,
        is_fresh=is_fresh,
        reason=reason,
        checksum=checksum
        or _checksum(
            snapshot_id=snapshot_id,
            observed_at_ms=observed_at_ms,
            evaluation_time_ms=evaluation_time_ms,
            age_ms=age_ms,
            max_allowed_age_ms=max_allowed_age_ms,
            status=status,
            is_fresh=is_fresh,
            reason=reason,
        ),
    )


def test_fresh_snapshot_passes() -> None:
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.FRESH
    assert result.is_fresh is True
    assert result.age_ms == FRESH_EVALUATION_TIME_MS - FRESH_OBSERVED_AT_MS


@pytest.mark.parametrize(
    ("max_snapshot_age_ms", "allow_future_observed_at", "max_future_skew_ms"),
    [
        (True, False, 0),
        (0, False, 0),
        (1000, "yes", 0),
        (1000, False, True),
        (1000, True, -1),
        (1000, False, 1),
    ],
)
def test_freshness_policy_rejects_invalid_thresholds(
    max_snapshot_age_ms: object,
    allow_future_observed_at: object,
    max_future_skew_ms: object,
) -> None:
    with pytest.raises(ValueError):
        FreshnessPolicy(max_snapshot_age_ms, allow_future_observed_at, max_future_skew_ms)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": cast(WorldSnapshotFreshnessStatus, "FRESH"), "checksum": "0" * 64},
        {"is_fresh": cast(bool, "yes")},
        {"is_fresh": False},
        {"snapshot_id": ""},
        {"observed_at_ms": -1},
        {"max_allowed_age_ms": 0},
        {"age_ms": 1001},
        {"status": WorldSnapshotFreshnessStatus.STALE, "is_fresh": True},
        {"reason": " "},
        {"checksum": "bad"},
    ],
)
def test_freshness_result_rejects_contradictions(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _freshness_result(**kwargs)


def test_age_exactly_max_passes() -> None:
    policy = FreshnessPolicy(500)
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_OBSERVED_AT_MS + 500,
        freshness_policy=policy,
    )

    assert result.status is WorldSnapshotFreshnessStatus.FRESH
    assert result.age_ms == 500


def test_age_max_plus_one_fails_stale() -> None:
    policy = FreshnessPolicy(500)
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_OBSERVED_AT_MS + 501,
        freshness_policy=policy,
    )

    assert result.status is WorldSnapshotFreshnessStatus.STALE
    assert result.is_fresh is False


def test_missing_snapshot_fails() -> None:
    result = validate_world_snapshot_freshness(
        None,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.MISSING_SNAPSHOT
    assert result.is_fresh is False


def test_missing_observed_at_ms_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "captured_at_ms", None)

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.MISSING_TIMESTAMP


def test_missing_evaluation_time_ms_fails() -> None:
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=None,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.MISSING_EVALUATION_TIME


def test_future_dated_snapshot_fails() -> None:
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_OBSERVED_AT_MS - 1,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.FUTURE_DATED


def test_negative_timestamp_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "captured_at_ms", -1)

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP


def test_non_integer_timestamp_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "captured_at_ms", "not-an-int")

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP


def test_invalid_max_age_fails() -> None:
    forged_policy = object.__new__(FreshnessPolicy)
    object.__setattr__(forged_policy, "max_snapshot_age_ms", 0)
    object.__setattr__(forged_policy, "allow_future_observed_at", False)
    object.__setattr__(forged_policy, "max_future_skew_ms", 0)

    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=forged_policy,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_MAX_AGE


def test_invalid_policy_object_fails() -> None:
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=object(),
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_MAX_AGE


@pytest.mark.parametrize(
    ("allow_future_observed_at", "max_future_skew_ms"),
    [("yes", 0), (True, True), (True, -1)],
)
def test_forged_future_policy_fields_fail(
    allow_future_observed_at: object,
    max_future_skew_ms: object,
) -> None:
    forged_policy = object.__new__(FreshnessPolicy)
    object.__setattr__(forged_policy, "max_snapshot_age_ms", 1000)
    object.__setattr__(forged_policy, "allow_future_observed_at", allow_future_observed_at)
    object.__setattr__(forged_policy, "max_future_skew_ms", max_future_skew_ms)

    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=forged_policy,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_MAX_AGE


def test_negative_evaluation_time_fails() -> None:
    result = validate_world_snapshot_freshness(
        fresh_world_snapshot(),
        evaluation_time_ms=-1,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP


def test_missing_snapshot_id_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "snapshot_id", "")

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.SNAPSHOT_ID_MISSING


def test_invalid_expires_at_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "expires_at_ms", "bad")

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.INVALID_TIMESTAMP


def test_contradictory_expiry_metadata_fails() -> None:
    snapshot = fresh_world_snapshot()
    object.__setattr__(snapshot, "expires_at_ms", snapshot.captured_at_ms - 1)

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert result.status is WorldSnapshotFreshnessStatus.CONTRADICTORY_METADATA


def test_explicit_future_skew_policy_can_accept_bounded_future_snapshot() -> None:
    snapshot = fresh_world_snapshot(observed_at_ms=FRESH_EVALUATION_TIME_MS + 3)
    policy = FreshnessPolicy(1000, allow_future_observed_at=True, max_future_skew_ms=3)

    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=policy,
    )

    assert result.status is WorldSnapshotFreshnessStatus.FRESH
    assert result.age_ms == 0


def test_checksum_is_deterministic() -> None:
    snapshot = fresh_world_snapshot()

    first = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    second = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert first == second
    assert first.checksum == second.checksum


def test_forged_freshness_result_is_rejected_by_integrity_helper() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    object.__setattr__(result, "checksum", "0" * 64)

    with pytest.raises(WorldSnapshotFreshnessError):
        assert_world_snapshot_freshness_integrity(
            snapshot=snapshot,
            freshness_result=result,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            freshness_policy=DEFAULT_FRESHNESS_POLICY,
        )


def test_integrity_helper_returns_matching_freshness_result() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    returned = assert_world_snapshot_freshness_integrity(
        snapshot=snapshot,
        freshness_result=result,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert returned is result


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("snapshot_id", "other-snapshot"),
        ("observed_at_ms", FRESH_OBSERVED_AT_MS + 1),
        ("evaluation_time_ms", FRESH_EVALUATION_TIME_MS + 1),
        ("max_allowed_age_ms", DEFAULT_FRESHNESS_POLICY.max_snapshot_age_ms + 1),
    ],
)
def test_integrity_helper_rejects_binding_mismatches(field: str, value: object) -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    object.__setattr__(result, field, value)

    with pytest.raises(WorldSnapshotFreshnessError):
        assert_world_snapshot_freshness_integrity(
            snapshot=snapshot,
            freshness_result=result,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            freshness_policy=DEFAULT_FRESHNESS_POLICY,
        )


def test_integrity_helper_rejects_non_fresh_result() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS + 2_000,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    with pytest.raises(WorldSnapshotFreshnessError):
        assert_world_snapshot_freshness_integrity(
            snapshot=snapshot,
            freshness_result=result,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS + 2_000,
            freshness_policy=DEFAULT_FRESHNESS_POLICY,
        )


def test_freshness_backed_admission_predicate_accepts_matching_fresh_result() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert is_freshness_backed_admission(
        freshness_result=result,
        expected_snapshot_id=snapshot.snapshot_id,
        expected_observed_at_ms=snapshot.captured_at_ms,
        expected_freshness_checksum=result.checksum,
    )


def test_freshness_backed_admission_predicate_rejects_stale_result() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS + 2_000,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )

    assert not is_freshness_backed_admission(
        freshness_result=result,
        expected_snapshot_id=snapshot.snapshot_id,
        expected_observed_at_ms=snapshot.captured_at_ms,
        expected_freshness_checksum=result.checksum,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"freshness_result": None},
        {"expected_snapshot_id": None},
        {"expected_snapshot_id": "other"},
        {"expected_observed_at_ms": None},
        {"expected_observed_at_ms": FRESH_OBSERVED_AT_MS + 1},
        {"expected_freshness_checksum": None},
        {"expected_freshness_checksum": "0" * 64},
    ],
)
def test_freshness_backed_admission_predicate_rejects_mismatches(
    kwargs: dict[str, object],
) -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    call_kwargs = {
        "freshness_result": result,
        "expected_snapshot_id": snapshot.snapshot_id,
        "expected_observed_at_ms": snapshot.captured_at_ms,
        "expected_freshness_checksum": result.checksum,
    }
    call_kwargs.update(kwargs)

    assert not is_freshness_backed_admission(**call_kwargs)


def test_freshness_backed_admission_predicate_rejects_forged_is_fresh_flag() -> None:
    snapshot = fresh_world_snapshot()
    result = validate_world_snapshot_freshness(
        snapshot,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
    )
    object.__setattr__(result, "is_fresh", False)

    assert not is_freshness_backed_admission(
        freshness_result=result,
        expected_snapshot_id=snapshot.snapshot_id,
        expected_observed_at_ms=snapshot.captured_at_ms,
        expected_freshness_checksum=result.checksum,
    )
