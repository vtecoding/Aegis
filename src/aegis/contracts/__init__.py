"""Shared typed contracts between Aegis pipeline layers."""

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import (
    FrozenJsonValue,
    JsonScalar,
    JsonValue,
    freeze_json_mapping,
    freeze_json_value,
    is_json_value,
)
from aegis.contracts.validation import ValidationResult, Violation

__all__ = [
    "ExecutionContext",
    "FrozenJsonValue",
    "JsonScalar",
    "JsonValue",
    "RawIntent",
    "ValidationResult",
    "Violation",
    "freeze_json_mapping",
    "freeze_json_value",
    "is_json_value",
]
