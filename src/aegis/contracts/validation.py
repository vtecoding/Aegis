"""Validation result contracts for Aegis."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from aegis.contracts.intent import RawIntent


@dataclass(frozen=True, slots=True)
class Violation:
    """Stable validation failure metadata.

    Args:
        field: Contract field associated with the failure.
        reason: Human-readable failure reason.
        code: Stable machine-readable failure code.
        layer: Pipeline layer reporting the failure.

    Raises:
        ValueError: If any field is empty after stripping whitespace.
    """

    field: str
    reason: str
    code: str
    layer: str

    def __post_init__(self) -> None:
        field = self.field.strip()
        if field == "":
            raise ValueError("field must be non-empty")

        reason = self.reason.strip()
        if reason == "":
            raise ValueError("reason must be non-empty")

        code = self.code.strip()
        if code == "":
            raise ValueError("code must be non-empty")

        layer = self.layer.strip()
        if layer == "":
            raise ValueError("layer must be non-empty")

        object.__setattr__(self, "field", field)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "layer", layer)


@dataclass(frozen=True, slots=True, init=False)
class ValidationResult:
    """Outcome of validating a raw intent contract.

    Args:
        is_valid: Whether validation passed.
        intent: Intent that was validated.
        violations: Validation failures. Must be empty when valid and
            non-empty when invalid.

    Raises:
        ValueError: If validity and violation state contradict each other.
    """

    is_valid: bool
    intent: RawIntent
    violations: tuple[Violation, ...]

    def __init__(
        self,
        is_valid: bool,
        intent: RawIntent,
        violations: Iterable[Violation],
    ) -> None:
        violations_tuple = tuple(violations)
        if is_valid and violations_tuple:
            raise ValueError("valid results must not contain violations")
        if not is_valid and not violations_tuple:
            raise ValueError("invalid results must contain at least one violation")

        object.__setattr__(self, "is_valid", is_valid)
        object.__setattr__(self, "intent", intent)
        object.__setattr__(self, "violations", violations_tuple)
