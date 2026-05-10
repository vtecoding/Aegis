"""Tests for deterministic resource bounds."""

from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.governance.aegis_resource_bounds import (
    DEFAULT_RESOURCE_BOUNDS,
    ResourceBounds,
    validate_resource_bounds,
)


def _bounds(**overrides: int) -> ResourceBounds:
    return replace(DEFAULT_RESOURCE_BOUNDS, **overrides)


def test_resource_bounds_accepts_bounded_canonical_values() -> None:
    validate_resource_bounds(
        {"goal": "move", "path": [{"x": 1, "y": 2}], "enabled": True},
        bounds=_bounds(max_canonical_json_bytes=512),
    )


def test_resource_bounds_rejects_oversized_string() -> None:
    with pytest.raises(ValueError, match="max_string_length"):
        validate_resource_bounds(
            {"payload": "x" * 6},
            bounds=_bounds(max_string_length=5),
        )


def test_resource_bounds_rejects_excessive_depth() -> None:
    with pytest.raises(ValueError, match="max_metadata_depth"):
        validate_resource_bounds(
            {"a": {"b": {"c": 1}}},
            bounds=_bounds(max_metadata_depth=2),
        )


def test_resource_bounds_rejects_excessive_width() -> None:
    with pytest.raises(ValueError, match="max_mapping_width"):
        validate_resource_bounds(
            {"a": 1, "b": 2},
            bounds=_bounds(max_mapping_width=1),
        )


def test_resource_bounds_rejects_large_canonical_json() -> None:
    with pytest.raises(ValueError, match="max_canonical_json_bytes"):
        validate_resource_bounds(
            {"payload": "abcdef"},
            bounds=_bounds(max_canonical_json_bytes=4),
        )
