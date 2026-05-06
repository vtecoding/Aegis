"""Typed Aegis exception hierarchy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aegis.contracts.json_types import FrozenJsonValue, JsonValue, freeze_json_mapping


@dataclass(frozen=True, slots=True, init=False)
class AegisError(Exception):
    """Base exception for explicit, inspectable Aegis failures.

    Args:
        message: Human-readable failure message.
        layer: Pipeline layer associated with the failure.
        context: JSON-compatible failure metadata.

    Raises:
        ValueError: If message or layer are empty, or context is not a JSON
            object mapping.
    """

    message: str
    layer: str
    context: Mapping[str, FrozenJsonValue]

    def __init__(self, message: str, layer: str, context: Mapping[str, JsonValue]) -> None:
        message = message.strip()
        if message == "":
            raise ValueError("message must be non-empty")

        layer = layer.strip()
        if layer == "":
            raise ValueError("layer must be non-empty")

        object.__setattr__(self, "message", message)
        object.__setattr__(self, "layer", layer)
        object.__setattr__(self, "context", freeze_json_mapping(context))
        Exception.__init__(self, str(self))

    def __str__(self) -> str:
        """Return a stable layer-qualified message."""
        return f"[{self.layer}] {self.message}"


class ValidationError(AegisError):
    """Validation layer failure."""


class PlanningError(AegisError):
    """Planning layer failure."""


class AuditError(AegisError):
    """Audit layer failure."""


class GateError(AegisError):
    """Execution gate failure."""


class PolicyAdmissionIntegrityError(AegisError):
    """Policy admission integrity failure."""


class ConfigurationError(AegisError):
    """Configuration failure."""
