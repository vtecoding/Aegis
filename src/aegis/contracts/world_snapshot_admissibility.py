"""Deterministic world snapshot admissibility contracts.

This module implements the pre-freshness evidence boundary for world snapshots.
It performs only structural checks over explicit inputs and never reads clocks,
files, networks, process state, sensors, middleware, or hardware.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from types import MappingProxyType
from typing import cast

from aegis.contracts.policy import WorldSnapshotStub
from aegis.errors import AegisError

type CanonicalAdmissibilityValue = (
    str
    | int
    | float
    | bool
    | None
    | list[CanonicalAdmissibilityValue]
    | dict[str, CanonicalAdmissibilityValue]
)
type ExpectedFactType = type[object] | tuple[type[object], ...]


class WorldSnapshotAdmissibilityError(AegisError):
    """Raised when admissibility integrity checks fail catastrophically."""


class WorldSnapshotAdmissibilityStatus(StrEnum):
    """Structural admissibility status for world snapshot evidence."""

    ADMISSIBLE = "ADMISSIBLE"
    SNAPSHOT_MISSING = "SNAPSHOT_MISSING"
    SNAPSHOT_CHECKSUM_MISSING = "SNAPSHOT_CHECKSUM_MISSING"
    SNAPSHOT_CHECKSUM_EMPTY = "SNAPSHOT_CHECKSUM_EMPTY"
    CAPABILITY_SCOPE_MISSING = "CAPABILITY_SCOPE_MISSING"
    CAPABILITY_SCOPE_EMPTY = "CAPABILITY_SCOPE_EMPTY"
    CAPABILITY_SCOPE_MISMATCH = "CAPABILITY_SCOPE_MISMATCH"
    FACTS_MALFORMED = "FACTS_MALFORMED"
    DECLARED_FACT_KEY_MISSING = "DECLARED_FACT_KEY_MISSING"
    REQUIRED_FACT_KEY_MISSING = "REQUIRED_FACT_KEY_MISSING"
    REQUIRED_FACT_KEY_UNDECLARED = "REQUIRED_FACT_KEY_UNDECLARED"
    CONTRADICTORY_SNAPSHOT_EVIDENCE = "CONTRADICTORY_SNAPSHOT_EVIDENCE"


class SnapshotFactReadStatus(StrEnum):
    """Typed result status for policy fact reads."""

    PRESENT = "PRESENT"
    SNAPSHOT_FACT_KEY_MISSING = "SNAPSHOT_FACT_KEY_MISSING"
    SNAPSHOT_FACT_KEY_UNDECLARED = "SNAPSHOT_FACT_KEY_UNDECLARED"
    SNAPSHOT_FACT_TYPE_MISMATCH = "SNAPSHOT_FACT_TYPE_MISMATCH"


@dataclass(frozen=True, slots=True)
class SnapshotFactReadResult:
    """Typed policy fact read result."""

    key: str
    status: SnapshotFactReadStatus
    value: object | None
    reason_code: str


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotAdmissibilityResult:
    """Deterministic structural admissibility result for a world snapshot."""

    status: WorldSnapshotAdmissibilityStatus
    reason_code: str
    world_snapshot_checksum: str | None
    requested_capability: str | None
    declared_capability_scope: frozenset[str]
    declared_fact_keys: frozenset[str] | None
    missing_declared_fact_keys: frozenset[str]
    missing_required_fact_keys: frozenset[str]
    undeclared_required_fact_keys: frozenset[str]
    checksum: str

    def __init__(
        self,
        *,
        status: WorldSnapshotAdmissibilityStatus,
        reason_code: str,
        world_snapshot_checksum: str | None,
        requested_capability: str | None,
        declared_capability_scope: Iterable[str] = (),
        declared_fact_keys: Iterable[str] | None = None,
        missing_declared_fact_keys: Iterable[str] = (),
        missing_required_fact_keys: Iterable[str] = (),
        undeclared_required_fact_keys: Iterable[str] = (),
        checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason_code(reason_code, "reason_code")
        normalized_snapshot_checksum = _normalize_optional_result_checksum(
            world_snapshot_checksum,
            "world_snapshot_checksum",
            normalized_status,
        )
        normalized_requested_capability = (
            None
            if requested_capability is None
            else _normalize_capability_name(requested_capability)
        )
        normalized_scope = _normalize_capability_frozenset_allow_empty(
            declared_capability_scope, "declared_capability_scope"
        )
        normalized_declared_fact_keys = (
            None
            if declared_fact_keys is None
            else _normalize_fact_key_frozenset_allow_empty(declared_fact_keys, "declared_fact_keys")
        )
        normalized_missing_declared = _normalize_fact_key_frozenset_allow_empty(
            missing_declared_fact_keys, "missing_declared_fact_keys"
        )
        normalized_missing_required = _normalize_fact_key_frozenset_allow_empty(
            missing_required_fact_keys, "missing_required_fact_keys"
        )
        normalized_undeclared_required = _normalize_fact_key_frozenset_allow_empty(
            undeclared_required_fact_keys, "undeclared_required_fact_keys"
        )
        if normalized_status is WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
            _validate_admissible_fields(
                world_snapshot_checksum=normalized_snapshot_checksum,
                requested_capability=normalized_requested_capability,
                declared_capability_scope=normalized_scope,
                missing_declared_fact_keys=normalized_missing_declared,
                missing_required_fact_keys=normalized_missing_required,
                undeclared_required_fact_keys=normalized_undeclared_required,
            )
        computed_checksum = world_snapshot_admissibility_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            world_snapshot_checksum=normalized_snapshot_checksum,
            requested_capability=normalized_requested_capability,
            declared_capability_scope=normalized_scope,
            declared_fact_keys=normalized_declared_fact_keys,
            missing_declared_fact_keys=normalized_missing_declared,
            missing_required_fact_keys=normalized_missing_required,
            undeclared_required_fact_keys=normalized_undeclared_required,
        )
        normalized_checksum = _normalize_supplied_checksum(checksum, computed_checksum, "checksum")

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "world_snapshot_checksum", normalized_snapshot_checksum)
        object.__setattr__(self, "requested_capability", normalized_requested_capability)
        object.__setattr__(self, "declared_capability_scope", normalized_scope)
        object.__setattr__(self, "declared_fact_keys", normalized_declared_fact_keys)
        object.__setattr__(self, "missing_declared_fact_keys", normalized_missing_declared)
        object.__setattr__(self, "missing_required_fact_keys", normalized_missing_required)
        object.__setattr__(self, "undeclared_required_fact_keys", normalized_undeclared_required)
        object.__setattr__(self, "checksum", normalized_checksum)


def validate_world_snapshot_admissibility(
    snapshot: WorldSnapshotStub | None,
    *,
    requested_capability: str,
    required_fact_keys: Iterable[str] = (),
) -> WorldSnapshotAdmissibilityResult:
    """Deterministically validate snapshot evidence before freshness runs."""
    normalized_capability = _normalize_capability_name(requested_capability)
    normalized_required_fact_keys = _normalize_fact_key_frozenset_allow_empty(
        required_fact_keys, "required_fact_keys"
    )
    if snapshot is None:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_MISSING,
            requested_capability=normalized_capability,
        )

    checksum = _snapshot_checksum(snapshot)
    if checksum is None:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_MISSING,
            requested_capability=normalized_capability,
        )
    if checksum == "":
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.SNAPSHOT_CHECKSUM_EMPTY,
            world_snapshot_checksum="",
            requested_capability=normalized_capability,
        )

    declared_scope = _snapshot_declared_capability_scope(snapshot)
    if declared_scope is None:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISSING,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
        )
    if not declared_scope:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_EMPTY,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=(),
        )
    if normalized_capability not in declared_scope:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.CAPABILITY_SCOPE_MISMATCH,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
        )

    fact_keys = _snapshot_fact_keys(snapshot)
    if fact_keys is None:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
        )

    declared_fact_keys = _snapshot_declared_fact_keys(snapshot)
    if declared_fact_keys is _MALFORMED_FACT_KEYS:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.FACTS_MALFORMED,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
        )
    typed_declared_fact_keys = cast(frozenset[str] | None, declared_fact_keys)
    missing_declared = (
        frozenset[str]()
        if typed_declared_fact_keys is None
        else typed_declared_fact_keys.difference(fact_keys)
    )
    missing_required = normalized_required_fact_keys.difference(fact_keys)
    undeclared_required = (
        frozenset[str]()
        if typed_declared_fact_keys is None
        else normalized_required_fact_keys.difference(typed_declared_fact_keys)
    )
    if missing_declared:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.DECLARED_FACT_KEY_MISSING,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
            declared_fact_keys=typed_declared_fact_keys,
            missing_declared_fact_keys=missing_declared,
        )
    if missing_required:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_MISSING,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
            declared_fact_keys=typed_declared_fact_keys,
            missing_required_fact_keys=missing_required,
        )
    if undeclared_required:
        return _admissibility_result(
            status=WorldSnapshotAdmissibilityStatus.REQUIRED_FACT_KEY_UNDECLARED,
            world_snapshot_checksum=checksum,
            requested_capability=normalized_capability,
            declared_capability_scope=declared_scope,
            declared_fact_keys=typed_declared_fact_keys,
            undeclared_required_fact_keys=undeclared_required,
        )
    return _admissibility_result(
        status=WorldSnapshotAdmissibilityStatus.ADMISSIBLE,
        world_snapshot_checksum=checksum,
        requested_capability=normalized_capability,
        declared_capability_scope=declared_scope,
        declared_fact_keys=typed_declared_fact_keys,
    )


def assert_world_snapshot_admissibility_integrity(
    *,
    snapshot: WorldSnapshotStub,
    admissibility_result: WorldSnapshotAdmissibilityResult,
    requested_capability: str,
    required_fact_keys: Iterable[str] = (),
) -> WorldSnapshotAdmissibilityResult:
    """Verify that an ADMISSIBLE result binds to the exact snapshot and capability."""
    expected = validate_world_snapshot_admissibility(
        snapshot,
        requested_capability=requested_capability,
        required_fact_keys=required_fact_keys,
    )
    violations: list[str] = []
    if admissibility_result.status is not WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
        violations.append("ADMISSIBILITY_STATUS_NOT_ADMISSIBLE")
    if admissibility_result != expected:
        violations.append("ADMISSIBILITY_RESULT_MISMATCH")
    if admissibility_result.checksum != expected.checksum:
        violations.append("ADMISSIBILITY_RESULT_CHECKSUM_MISMATCH")
    if violations:
        raise WorldSnapshotAdmissibilityError(
            message="World snapshot admissibility integrity check failed",
            layer="policy",
            context={
                "reasons": list(violations),
                "snapshot_checksum": _snapshot_checksum(snapshot),
            },
        )
    return admissibility_result


def is_admissibility_backed_admission(
    *,
    admissibility_result: WorldSnapshotAdmissibilityResult | None,
    expected_snapshot_checksum: str | None,
    expected_admissibility_checksum: str | None,
) -> bool:
    """Return True only when admission carries a fully bound ADMISSIBLE result."""
    if admissibility_result is None:
        return False
    if admissibility_result.status is not WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
        return False
    if expected_snapshot_checksum is None:
        return False
    if admissibility_result.world_snapshot_checksum != expected_snapshot_checksum:
        return False
    return (
        expected_admissibility_checksum is not None
        and admissibility_result.checksum == expected_admissibility_checksum
    )


def require_snapshot_fact(
    snapshot: WorldSnapshotStub,
    key: str,
    expected_type: ExpectedFactType | None = None,
) -> SnapshotFactReadResult:
    """Read one declared snapshot fact with explicit missing/undeclared/type statuses."""
    normalized_key = _normalize_fact_key(key, "key")
    declared_fact_keys = _snapshot_declared_fact_keys(snapshot)
    if declared_fact_keys is _MALFORMED_FACT_KEYS:
        return SnapshotFactReadResult(
            key=normalized_key,
            status=SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_MISSING,
            value=None,
            reason_code="SNAPSHOT_FACTS_MALFORMED",
        )
    typed_declared_fact_keys = cast(frozenset[str] | None, declared_fact_keys)
    if typed_declared_fact_keys is not None and normalized_key not in typed_declared_fact_keys:
        return SnapshotFactReadResult(
            key=normalized_key,
            status=SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_UNDECLARED,
            value=None,
            reason_code=SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_UNDECLARED.value,
        )
    if normalized_key not in snapshot.facts:
        return SnapshotFactReadResult(
            key=normalized_key,
            status=SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_MISSING,
            value=None,
            reason_code=SnapshotFactReadStatus.SNAPSHOT_FACT_KEY_MISSING.value,
        )
    value = snapshot.facts[normalized_key]
    if expected_type is not None and not _matches_expected_type(value, expected_type):
        return SnapshotFactReadResult(
            key=normalized_key,
            status=SnapshotFactReadStatus.SNAPSHOT_FACT_TYPE_MISMATCH,
            value=value,
            reason_code=SnapshotFactReadStatus.SNAPSHOT_FACT_TYPE_MISMATCH.value,
        )
    return SnapshotFactReadResult(
        key=normalized_key,
        status=SnapshotFactReadStatus.PRESENT,
        value=value,
        reason_code=SnapshotFactReadStatus.PRESENT.value,
    )


def world_snapshot_admissibility_result_checksum(
    *,
    status: WorldSnapshotAdmissibilityStatus,
    reason_code: str,
    world_snapshot_checksum: str | None,
    requested_capability: str | None,
    declared_capability_scope: frozenset[str],
    declared_fact_keys: frozenset[str] | None,
    missing_declared_fact_keys: frozenset[str],
    missing_required_fact_keys: frozenset[str],
    undeclared_required_fact_keys: frozenset[str],
) -> str:
    """Return a deterministic checksum for a snapshot admissibility result."""
    return _sha256(
        {
            "status": status.value,
            "reason_code": reason_code,
            "world_snapshot_checksum": world_snapshot_checksum,
            "requested_capability": requested_capability,
            "declared_capability_scope": sorted(declared_capability_scope),
            "declared_fact_keys": (
                None if declared_fact_keys is None else sorted(declared_fact_keys)
            ),
            "missing_declared_fact_keys": sorted(missing_declared_fact_keys),
            "missing_required_fact_keys": sorted(missing_required_fact_keys),
            "undeclared_required_fact_keys": sorted(undeclared_required_fact_keys),
        }
    )


_MALFORMED_FACT_KEYS = object()


def _admissibility_result(
    *,
    status: WorldSnapshotAdmissibilityStatus,
    world_snapshot_checksum: str | None = None,
    requested_capability: str | None = None,
    declared_capability_scope: Iterable[str] = (),
    declared_fact_keys: Iterable[str] | None = None,
    missing_declared_fact_keys: Iterable[str] = (),
    missing_required_fact_keys: Iterable[str] = (),
    undeclared_required_fact_keys: Iterable[str] = (),
) -> WorldSnapshotAdmissibilityResult:
    return WorldSnapshotAdmissibilityResult(
        status=status,
        reason_code=status.value,
        world_snapshot_checksum=world_snapshot_checksum,
        requested_capability=requested_capability,
        declared_capability_scope=declared_capability_scope,
        declared_fact_keys=declared_fact_keys,
        missing_declared_fact_keys=missing_declared_fact_keys,
        missing_required_fact_keys=missing_required_fact_keys,
        undeclared_required_fact_keys=undeclared_required_fact_keys,
    )


def _snapshot_checksum(snapshot: object) -> str | None:
    value = object.__getattribute__(snapshot, "checksum")
    if value is None:
        return None
    if not isinstance(value, str):
        return ""
    return value.strip()


def _snapshot_declared_capability_scope(snapshot: object) -> frozenset[str] | None:
    try:
        value = object.__getattribute__(snapshot, "declared_capability_scope")
    except AttributeError:
        return None
    if value is None or isinstance(value, str):
        return None
    try:
        return _normalize_capability_frozenset_allow_empty(value, "declared_capability_scope")
    except (TypeError, ValueError):
        return None


def _snapshot_fact_keys(snapshot: object) -> frozenset[str] | None:
    try:
        facts = object.__getattribute__(snapshot, "facts")
    except AttributeError:
        return None
    if not isinstance(facts, Mapping):
        return None
    fact_keys: set[str] = set()
    typed_facts = cast(Mapping[object, object], facts)
    for key in typed_facts:
        if not isinstance(key, str) or key.strip() == "" or key != key.strip():
            return None
        fact_keys.add(key)
    return frozenset(fact_keys)


def _snapshot_declared_fact_keys(snapshot: object) -> frozenset[str] | None | object:
    try:
        value = object.__getattribute__(snapshot, "declared_fact_keys")
    except AttributeError:
        return None
    if value is None:
        return None
    if isinstance(value, str):
        return _MALFORMED_FACT_KEYS
    try:
        return _normalize_fact_key_frozenset_allow_empty(value, "declared_fact_keys")
    except (TypeError, ValueError):
        return _MALFORMED_FACT_KEYS


def _validate_admissible_fields(
    *,
    world_snapshot_checksum: str | None,
    requested_capability: str | None,
    declared_capability_scope: frozenset[str],
    missing_declared_fact_keys: frozenset[str],
    missing_required_fact_keys: frozenset[str],
    undeclared_required_fact_keys: frozenset[str],
) -> None:
    if world_snapshot_checksum is None or world_snapshot_checksum == "":
        raise ValueError("ADMISSIBLE requires world_snapshot_checksum")
    if requested_capability is None:
        raise ValueError("ADMISSIBLE requires requested_capability")
    if not declared_capability_scope:
        raise ValueError("ADMISSIBLE requires declared_capability_scope")
    if requested_capability not in declared_capability_scope:
        raise ValueError("ADMISSIBLE requires scope to include requested_capability")
    if missing_declared_fact_keys:
        raise ValueError("ADMISSIBLE requires no missing declared fact keys")
    if missing_required_fact_keys:
        raise ValueError("ADMISSIBLE requires no missing required fact keys")
    if undeclared_required_fact_keys:
        raise ValueError("ADMISSIBLE requires no undeclared required fact keys")


def _normalize_status(
    value: WorldSnapshotAdmissibilityStatus,
) -> WorldSnapshotAdmissibilityStatus:
    if not isinstance(value, WorldSnapshotAdmissibilityStatus):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("status must be a WorldSnapshotAdmissibilityStatus")
    return value


def _normalize_required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(f"{field_name} must be a string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    if value == "":
        raise ValueError(f"{field_name} must be non-empty")
    return value


def _normalize_optional_result_checksum(
    value: str | None,
    field_name: str,
    status: WorldSnapshotAdmissibilityStatus,
) -> str | None:
    if value is None:
        return None
    if status is WorldSnapshotAdmissibilityStatus.ADMISSIBLE:
        return _normalize_required_text(value, field_name)
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(f"{field_name} must be a string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return value


def _normalize_reason_code(value: str, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a machine-readable uppercase reason code")
    return normalized


def _normalize_capability_name(value: str) -> str:
    normalized = _normalize_required_text(value, "capability")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_fact_key(value: str, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical fact key")
    return normalized


def _normalize_capability_frozenset_allow_empty(
    values: Iterable[str],
    field_name: str,
) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of capability names")
    return frozenset(_normalize_capability_name(value) for value in values)


def _normalize_fact_key_frozenset_allow_empty(
    values: Iterable[str],
    field_name: str,
) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of fact keys")
    return frozenset(_normalize_fact_key(value, field_name) for value in values)


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    if supplied_checksum is None:
        return computed_checksum
    normalized = _normalize_required_text(supplied_checksum, field_name)
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match deterministic checksum")
    return normalized


def _matches_expected_type(value: object, expected_type: ExpectedFactType) -> bool:
    if _expects_numeric_type(expected_type) and isinstance(value, bool):
        return False
    return isinstance(value, expected_type)


def _expects_numeric_type(expected_type: ExpectedFactType) -> bool:
    if isinstance(expected_type, tuple):
        return int in expected_type or float in expected_type
    return expected_type in {int, float}


def _canonicalise(value: object) -> CanonicalAdmissibilityValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, MappingProxyType):
        return _canonical_mapping(cast(Mapping[object, object], value))
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[object, object], value))
    if isinstance(value, tuple):
        return [_canonicalise(item) for item in cast(tuple[object, ...], value)]
    if isinstance(value, list):
        return [_canonicalise(item) for item in cast(list[object], value)]
    if isinstance(value, frozenset):
        items = cast(frozenset[object], value)
        return sorted((_canonicalise(item) for item in items), key=_canonical_sort_key)
    raise ValueError("admissibility values must be JSON-compatible frozen values")


def _canonical_mapping(
    values: Mapping[object, object],
) -> dict[str, CanonicalAdmissibilityValue]:
    canonical: dict[str, CanonicalAdmissibilityValue] = {}
    for key, value in values.items():
        if not isinstance(key, str):
            raise ValueError("admissibility mapping keys must be strings")
        canonical[key] = _canonicalise(value)
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sort_key(value: CanonicalAdmissibilityValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha256(value: Mapping[str, object]) -> str:
    canonical = json.dumps(
        _canonical_mapping(cast(Mapping[object, object], value)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "SnapshotFactReadResult",
    "SnapshotFactReadStatus",
    "WorldSnapshotAdmissibilityError",
    "WorldSnapshotAdmissibilityResult",
    "WorldSnapshotAdmissibilityStatus",
    "assert_world_snapshot_admissibility_integrity",
    "is_admissibility_backed_admission",
    "require_snapshot_fact",
    "validate_world_snapshot_admissibility",
    "world_snapshot_admissibility_result_checksum",
]
