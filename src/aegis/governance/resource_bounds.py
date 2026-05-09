"""Deterministic resource bounds for canonical input structures."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from typing import cast

type CanonicalBoundedValue = (
    str | int | float | bool | None | list[CanonicalBoundedValue] | dict[str, CanonicalBoundedValue]
)


@dataclass(frozen=True, slots=True)
class ResourceBounds:
    """Limits applied before canonical hashing or policy evaluation."""

    max_string_length: int
    max_metadata_depth: int
    max_mapping_width: int
    max_sequence_length: int
    max_total_nodes: int
    max_canonical_json_bytes: int
    max_trace_stage_count: int
    max_scenario_count: int

    def __post_init__(self) -> None:
        for field_name in (
            "max_string_length",
            "max_metadata_depth",
            "max_mapping_width",
            "max_sequence_length",
            "max_total_nodes",
            "max_canonical_json_bytes",
            "max_trace_stage_count",
            "max_scenario_count",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be greater than 0")


DEFAULT_RESOURCE_BOUNDS = ResourceBounds(
    max_string_length=100_000,
    max_metadata_depth=64,
    max_mapping_width=1_024,
    max_sequence_length=2_048,
    max_total_nodes=65_536,
    max_canonical_json_bytes=1_048_576,
    max_trace_stage_count=32,
    max_scenario_count=256,
)
"""Default ADR-0014 deterministic input bounds."""


def validate_resource_bounds(
    value: object,
    *,
    bounds: ResourceBounds = DEFAULT_RESOURCE_BOUNDS,
    label: str = "value",
) -> None:
    """Fail closed when a canonical input exceeds deterministic resource bounds.

    Args:
        value: Candidate canonical structure or boundary value.
        bounds: Explicit resource bounds to enforce.
        label: Human-readable field label for diagnostics.

    Raises:
        ValueError: If the value contains unsupported objects, non-finite
            numbers, excessive depth/width/length, or too many canonical bytes.
    """
    counter = _NodeCounter()
    canonical = _canonical_bounded_value(
        value, bounds=bounds, label=label, depth=0, counter=counter
    )
    canonical_json = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    if len(canonical_json.encode("utf-8")) > bounds.max_canonical_json_bytes:
        raise ValueError(f"{label} exceeds max_canonical_json_bytes")


def validate_trace_stage_count(
    stage_count: object,
    *,
    bounds: ResourceBounds = DEFAULT_RESOURCE_BOUNDS,
) -> None:
    """Validate a decision trace stage count against ADR-0014 bounds."""
    count = _normalize_non_negative_count(stage_count, "stage_count")
    if count > bounds.max_trace_stage_count:
        raise ValueError("decision trace exceeds max_trace_stage_count")


def validate_scenario_count(
    scenario_count: object,
    *,
    bounds: ResourceBounds = DEFAULT_RESOURCE_BOUNDS,
) -> None:
    """Validate a scenario suite size against ADR-0014 bounds."""
    count = _normalize_non_negative_count(scenario_count, "scenario_count")
    if count > bounds.max_scenario_count:
        raise ValueError("scenario suite exceeds max_scenario_count")


@dataclass(slots=True)
class _NodeCounter:
    total: int = 0


def _canonical_bounded_value(
    value: object,
    *,
    bounds: ResourceBounds,
    label: str,
    depth: int,
    counter: _NodeCounter,
) -> CanonicalBoundedValue:
    if depth > bounds.max_metadata_depth:
        raise ValueError(f"{label} exceeds max_metadata_depth")
    counter.total += 1
    if counter.total > bounds.max_total_nodes:
        raise ValueError(f"{label} exceeds max_total_nodes")

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value) > bounds.max_string_length:
            raise ValueError(f"{label} exceeds max_string_length")
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError(f"{label} numeric values must be finite")
        return value
    if callable(value):
        raise ValueError(f"{label} must not contain callables")
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _canonical_mapping(mapping, bounds=bounds, label=label, depth=depth, counter=counter)
    if isinstance(value, list | tuple):
        sequence = cast(list[object] | tuple[object, ...], value)
        return _canonical_sequence(
            sequence, bounds=bounds, label=label, depth=depth, counter=counter
        )
    if isinstance(value, set | frozenset):
        set_values = cast(set[object] | frozenset[object], value)
        canonical_items = _canonical_sequence(
            tuple(set_values), bounds=bounds, label=label, depth=depth, counter=counter
        )
        return sorted(canonical_items, key=_canonical_sort_key)
    raise ValueError(f"{label} contains unsupported object values")


def _canonical_mapping(
    value: Mapping[object, object],
    *,
    bounds: ResourceBounds,
    label: str,
    depth: int,
    counter: _NodeCounter,
) -> dict[str, CanonicalBoundedValue]:
    if len(value) > bounds.max_mapping_width:
        raise ValueError(f"{label} exceeds max_mapping_width")
    canonical: dict[str, CanonicalBoundedValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{label} mapping keys must be strings")
        if len(key) > bounds.max_string_length:
            raise ValueError(f"{label} mapping key exceeds max_string_length")
        canonical[key] = _canonical_bounded_value(
            item, bounds=bounds, label=label, depth=depth + 1, counter=counter
        )
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sequence(
    value: list[object] | tuple[object, ...],
    *,
    bounds: ResourceBounds,
    label: str,
    depth: int,
    counter: _NodeCounter,
) -> list[CanonicalBoundedValue]:
    if len(value) > bounds.max_sequence_length:
        raise ValueError(f"{label} exceeds max_sequence_length")
    return [
        _canonical_bounded_value(item, bounds=bounds, label=label, depth=depth + 1, counter=counter)
        for item in value
    ]


def _canonical_sort_key(value: CanonicalBoundedValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalize_non_negative_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


__all__ = [
    "DEFAULT_RESOURCE_BOUNDS",
    "ResourceBounds",
    "validate_resource_bounds",
    "validate_scenario_count",
    "validate_trace_stage_count",
]
