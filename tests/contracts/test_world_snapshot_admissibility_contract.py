"""Contract tests for deterministic world snapshot admissibility validation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import cast

import pytest

from aegis.contracts.policy import WorldSnapshotStub
from aegis.contracts.world_snapshot_admissibility import (
    SnapshotFactReadStatus,
    WorldSnapshotAdmissibilityError,
    WorldSnapshotAdmissibilityResult,
    WorldSnapshotAdmissibilityStatus,
    assert_world_snapshot_admissibility_integrity,
    is_admissibility_backed_admission,
    require_snapshot_fact,
    validate_world_snapshot_admissibility,
    world_snapshot_admissibility_result_checksum,
)

CAPABILITY = "locomotion.translation"
OTHER_CAPABILITY = "inspection.observe"
SNAPSHOT_CHECKSUM = "snapshot-checksum-admissible"


def _snapshot(
    *,
    facts: Mapping[str, object] | None = None,
    checksum: str | None = SNAPSHOT_CHECKSUM,
    declared_capability_scope: Iterable[str] | None = (CAPABILITY,),
    declared_fact_keys: Iterable[str] | None = None,
) -> WorldSnapshotStub:
    return WorldSnapshotStub(
        "admissibility-snapshot",
        1_000,
        2_000,
        "fixture",
        1.0,
        facts or {},
        checksum=checksum,
        declared_capability_scope=declared_capability_scope,
        declared_fact_keys=declared_fact_keys,
    )


class _SnapshotWithoutScope:
    checksum = SNAPSHOT_CHECKSUM
    facts = {"present": True}
    declared_fact_keys = frozenset({"present"})


class _SnapshotWithoutFacts:
    checksum = SNAPSHOT_CHECKSUM
    declared_capability_scope = frozenset({CAPABILITY})
    declared_fact_keys = frozenset({"present"})


class _SnapshotWithoutDeclaredFactKeys:
    checksum = SNAPSHOT_CHECKSUM
    declared_capability_scope = frozenset({CAPABILITY})
    facts = {"present": True}


def test_validate_world_snapshot_admissibility_accepts_matching_scope_and_facts() -> None:
    snapshot = _snapshot(
        facts={"distance_m": 1.5, "label": "crate"},
        declared_fact_keys=("distance_m", "label"),
    )

    result = validate_world_snapshot_admissibility(
        snapshot,
        requested_capability=CAPABILITY,
        required_fact_keys=("distance_m",),
    )

    assert result.status is WorldSnapshotAdmissibilityStatus.ADMISSIBLE
    assert result.reason_code == "ADMISSIBLE"
    assert result.world_snapshot_checksum == SNAPSHOT_CHECKSUM
    assert result.requested_capability == CAPABILITY
    assert result.declared_capability_scope == frozenset({CAPABILITY})
    assert result.declared_fact_keys == frozenset({"distance_m", "label"})
    assert result.missing_declared_fact_keys == frozenset()
    assert result.missing_required_fact_keys == frozenset()
    assert result.undeclared_required_fact_keys == frozenset()

    assert_world_snapshot_admissibility_integrity(
        snapshot=snapshot,
        admissibility_result=result,
        requested_capability=CAPABILITY,
        required_fact_keys=("distance_m",),
    )
    assert is_admissibility_backed_admission(
        admissibility_result=result,
        expected_snapshot_checksum=SNAPSHOT_CHECKSUM,
        expected_admissibility_checksum=result.checksum,
    )


@pytest.mark.parametrize(
    ("snapshot", "expected_status"),
    [
        (None, WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING),
        (_snapshot(checksum=None), WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_MISSING),
        (
            _snapshot(declared_capability_scope=None),
            WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISSING,
        ),
        (
            _snapshot(declared_capability_scope=()),
            WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_EMPTY,
        ),
        (
            _snapshot(declared_capability_scope=(OTHER_CAPABILITY,)),
            WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISMATCH,
        ),
        (
            _snapshot(facts={"present": True}, declared_fact_keys=("missing",)),
            WorldSnapshotAdmissibilityStatus.DECLARED_FACT_KEY_MISSING,
        ),
        (
            _snapshot(facts={}, declared_fact_keys=None),
            WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_MISSING,
        ),
        (
            _snapshot(facts={"required_key": 1}, declared_fact_keys=("other_key",)),
            WorldSnapshotAdmissibilityStatus.DECLARED_FACT_KEY_MISSING,
        ),
    ],
)
def test_validate_world_snapshot_admissibility_rejects_structural_failures(
    snapshot: WorldSnapshotStub | None,
    expected_status: WorldSnapshotAdmissibilityStatus,
) -> None:
    result = validate_world_snapshot_admissibility(
        snapshot,
        requested_capability=CAPABILITY,
        required_fact_keys=("required_key",),
    )

    assert result.status is expected_status


def test_validate_world_snapshot_admissibility_reports_checksum_empty_and_malformed_facts() -> None:
    empty_checksum_snapshot = _snapshot()
    object.__setattr__(empty_checksum_snapshot, "checksum", 42)
    empty_checksum = validate_world_snapshot_admissibility(
        empty_checksum_snapshot,
        requested_capability=CAPABILITY,
    )
    assert empty_checksum.status is WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_EMPTY

    malformed_facts_snapshot = _snapshot()
    object.__setattr__(malformed_facts_snapshot, "facts", "not-a-mapping")
    malformed_facts = validate_world_snapshot_admissibility(
        malformed_facts_snapshot,
        requested_capability=CAPABILITY,
    )
    assert malformed_facts.status is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED

    malformed_declared_keys_snapshot = _snapshot(facts={"present": True})
    object.__setattr__(malformed_declared_keys_snapshot, "declared_fact_keys", "present")
    malformed_declared_keys = validate_world_snapshot_admissibility(
        malformed_declared_keys_snapshot,
        requested_capability=CAPABILITY,
    )
    assert malformed_declared_keys.status is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED


def test_validate_world_snapshot_admissibility_reports_undeclared_required_fact() -> None:
    snapshot = _snapshot(
        facts={"required_key": 1, "other_key": 2},
        declared_fact_keys=("required_key",),
    )
    object.__setattr__(snapshot, "declared_fact_keys", frozenset({"other_key"}))

    result = validate_world_snapshot_admissibility(
        snapshot,
        requested_capability=CAPABILITY,
        required_fact_keys=("required_key",),
    )

    assert result.status is WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_UNDECLARED
    assert result.undeclared_required_fact_keys == frozenset({"required_key"})


def test_validate_world_snapshot_admissibility_handles_malformed_runtime_shapes() -> None:
    missing_scope = validate_world_snapshot_admissibility(
        cast(WorldSnapshotStub, _SnapshotWithoutScope()),
        requested_capability=CAPABILITY,
    )
    missing_facts = validate_world_snapshot_admissibility(
        cast(WorldSnapshotStub, _SnapshotWithoutFacts()),
        requested_capability=CAPABILITY,
    )
    missing_declared_fact_keys = validate_world_snapshot_admissibility(
        cast(WorldSnapshotStub, _SnapshotWithoutDeclaredFactKeys()),
        requested_capability=CAPABILITY,
    )
    invalid_scope = _snapshot()
    object.__setattr__(invalid_scope, "declared_capability_scope", ("BAD_CAPABILITY",))
    invalid_fact_key = _snapshot()
    object.__setattr__(invalid_fact_key, "facts", {1: "bad"})
    invalid_declared_fact_key = _snapshot(facts={"present": True})
    object.__setattr__(invalid_declared_fact_key, "declared_fact_keys", (1,))

    assert missing_scope.status is WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISSING
    assert missing_facts.status is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED
    assert missing_declared_fact_keys.status is WorldSnapshotAdmissibilityStatus.ADMISSIBLE
    assert (
        validate_world_snapshot_admissibility(invalid_scope, requested_capability=CAPABILITY).status
        is WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISSING
    )
    assert (
        validate_world_snapshot_admissibility(
            invalid_fact_key, requested_capability=CAPABILITY
        ).status
        is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED
    )
    assert (
        validate_world_snapshot_admissibility(
            invalid_declared_fact_key,
            requested_capability=CAPABILITY,
        ).status
        is WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED
    )


def test_admissibility_integrity_rejects_stale_or_untrusted_binding() -> None:
    snapshot = _snapshot()
    other_snapshot = _snapshot(checksum="other-snapshot-checksum")
    result = validate_world_snapshot_admissibility(snapshot, requested_capability=CAPABILITY)

    with pytest.raises(WorldSnapshotAdmissibilityError):
        assert_world_snapshot_admissibility_integrity(
            snapshot=other_snapshot,
            admissibility_result=result,
            requested_capability=CAPABILITY,
        )

    blocked = validate_world_snapshot_admissibility(None, requested_capability=CAPABILITY)
    with pytest.raises(WorldSnapshotAdmissibilityError):
        assert_world_snapshot_admissibility_integrity(
            snapshot=snapshot,
            admissibility_result=blocked,
            requested_capability=CAPABILITY,
        )
    assert not is_admissibility_backed_admission(
        admissibility_result=None,
        expected_snapshot_checksum=SNAPSHOT_CHECKSUM,
        expected_admissibility_checksum=result.checksum,
    )
    assert not is_admissibility_backed_admission(
        admissibility_result=blocked,
        expected_snapshot_checksum=SNAPSHOT_CHECKSUM,
        expected_admissibility_checksum=blocked.checksum,
    )
    assert not is_admissibility_backed_admission(
        admissibility_result=result,
        expected_snapshot_checksum=None,
        expected_admissibility_checksum=result.checksum,
    )
    assert not is_admissibility_backed_admission(
        admissibility_result=result,
        expected_snapshot_checksum="different-snapshot-checksum",
        expected_admissibility_checksum=result.checksum,
    )
    assert not is_admissibility_backed_admission(
        admissibility_result=result,
        expected_snapshot_checksum=SNAPSHOT_CHECKSUM,
        expected_admissibility_checksum=None,
    )


def test_require_snapshot_fact_returns_typed_statuses() -> None:
    snapshot = _snapshot(
        facts={"distance_m": 3, "label": "crate", "enabled": True},
        declared_fact_keys=("distance_m", "label", "enabled", "missing_key"),
    )

    present = require_snapshot_fact(snapshot, "distance_m", (int, float))
    missing = require_snapshot_fact(snapshot, "missing_key")
    type_mismatch = require_snapshot_fact(snapshot, "enabled", int)
    undeclared = require_snapshot_fact(snapshot, "not_declared")

    assert present.status is SnapshotFactReadStatus.PRESENT
    assert present.value == 3
    assert missing.status is SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_MISSING
    assert type_mismatch.status is SnapshotFactReadStatus.SNAPSHOT_FACT_TYPE_MISMATCH
    assert undeclared.status is SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_UNDECLARED

    object.__setattr__(snapshot, "declared_fact_keys", "malformed")
    malformed = require_snapshot_fact(snapshot, "distance_m")
    assert malformed.reason_code == "SNAPSHOT_FACTS_MALFORMED"


def test_world_snapshot_admissibility_result_rejects_invalid_manual_bindings() -> None:
    with pytest.raises(ValueError, match="status"):
        WorldSnapshotAdmissibilityResult(
            status=cast(WorldSnapshotAdmissibilityStatus, "ADMISSIBLE"),
            reason_code="ADMISSIBLE",
            world_snapshot_checksum=SNAPSHOT_CHECKSUM,
            requested_capability=CAPABILITY,
            declared_capability_scope=(CAPABILITY,),
        )
    with pytest.raises(ValueError, match="reason_code"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
            reason_code="not machine readable",
            world_snapshot_checksum=SNAPSHOT_CHECKSUM,
            requested_capability=CAPABILITY,
            declared_capability_scope=(CAPABILITY,),
        )
    with pytest.raises(ValueError, match="checksum"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
            reason_code="ADMISSIBLE",
            world_snapshot_checksum=SNAPSHOT_CHECKSUM,
            requested_capability=CAPABILITY,
            declared_capability_scope=(CAPABILITY,),
            checksum="0" * 64,
        )


@pytest.mark.parametrize(
    ("kwargs", "expected_message"),
    [
        ({"world_snapshot_checksum": None}, "world_snapshot_checksum"),
        ({"requested_capability": None}, "requested_capability"),
        ({"declared_capability_scope": ()}, "declared_capability_scope"),
        ({"declared_capability_scope": (OTHER_CAPABILITY,)}, "requested_capability"),
        ({"missing_declared_fact_keys": ("missing",)}, "missing declared"),
        ({"missing_required_fact_keys": ("required",)}, "missing required"),
        ({"undeclared_required_fact_keys": ("required",)}, "undeclared required"),
    ],
)
def test_admissible_status_requires_complete_positive_bindings(
    kwargs: Mapping[str, object],
    expected_message: str,
) -> None:
    fields: dict[str, object] = {
        "status": WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
        "reason_code": "ADMISSIBLE",
        "world_snapshot_checksum": SNAPSHOT_CHECKSUM,
        "requested_capability": CAPABILITY,
        "declared_capability_scope": (CAPABILITY,),
    }
    fields.update(kwargs)

    with pytest.raises(ValueError, match=expected_message):
        WorldSnapshotAdmissibilityResult(**fields)


def test_admissibility_checksum_is_deterministic_and_canonical() -> None:
    first = world_snapshot_admissibility_result_checksum(
        status=WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
        reason_code="ADMISSIBLE",
        world_snapshot_checksum=SNAPSHOT_CHECKSUM,
        requested_capability=CAPABILITY,
        declared_capability_scope=frozenset({CAPABILITY, OTHER_CAPABILITY}),
        declared_fact_keys=frozenset({"label", "distance_m"}),
        missing_declared_fact_keys=frozenset(),
        missing_required_fact_keys=frozenset(),
        undeclared_required_fact_keys=frozenset(),
    )
    second = world_snapshot_admissibility_result_checksum(
        status=WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
        reason_code="ADMISSIBLE",
        world_snapshot_checksum=SNAPSHOT_CHECKSUM,
        requested_capability=CAPABILITY,
        declared_capability_scope=frozenset({OTHER_CAPABILITY, CAPABILITY}),
        declared_fact_keys=frozenset({"distance_m", "label"}),
        missing_declared_fact_keys=frozenset(),
        missing_required_fact_keys=frozenset(),
        undeclared_required_fact_keys=frozenset(),
    )

    assert first == second


def test_world_snapshot_admissibility_result_rejects_malformed_text_and_iterables() -> None:
    with pytest.raises(ValueError, match="world_snapshot_checksum"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=cast(str | None, 42),
            requested_capability=None,
        )
    with pytest.raises(ValueError, match="reason_code"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code=" SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability=None,
        )
    with pytest.raises(ValueError, match="capability"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability="Locomotion.Translation",
        )
    with pytest.raises(ValueError, match="capability"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability=None,
            declared_capability_scope=cast(Iterable[str], CAPABILITY),
        )
    with pytest.raises(ValueError, match="capability"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability=None,
            declared_capability_scope=("BAD_CAPABILITY",),
        )
    with pytest.raises(ValueError, match="declared_fact_keys"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability=None,
            declared_fact_keys=cast(Iterable[str], "fact_key"),
        )
    with pytest.raises(ValueError, match="missing_declared_fact_keys"):
        WorldSnapshotAdmissibilityResult(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            reason_code="SNAPSHOT_MISSING",
            world_snapshot_checksum=None,
            requested_capability=None,
            missing_declared_fact_keys=("bad fact key",),
        )
