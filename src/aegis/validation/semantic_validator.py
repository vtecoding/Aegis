"""Semantic validation for supported Aegis v1 commands."""

from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
from typing import cast

from aegis.constants import ALLOWED_COMMANDS, MAX_WAIT_DURATION_MS
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import FrozenJsonValue
from aegis.contracts.validation import ValidationResult, Violation
from aegis.validation.schema_validator import validate_schema

_LAYER = "validation"


def validate_semantics(intent: RawIntent) -> ValidationResult:
    """Validate supported command vocabulary and command-specific parameters.

    Args:
        intent: Raw intent contract to validate.

    Returns:
        A deterministic validation result containing semantic violations only.
    """
    violations: list[Violation] = []

    if intent.command not in ALLOWED_COMMANDS:
        violations.append(
            _violation(
                "command",
                f"unsupported command {intent.command!r}",
                "unsupported_command",
            )
        )
        return _result(intent, violations)

    if intent.command == "stop":
        violations.extend(_validate_stop(intent))
    elif intent.command == "wait":
        violations.extend(_validate_wait(intent))
    elif intent.command == "inspect":
        violations.extend(_validate_inspect(intent))
    elif intent.command == "move":
        violations.extend(_validate_move(intent))
    else:
        # CONTRACT-CORRUPTION DEFENSE: unreachable via normal API.
        # If ALLOWED_COMMANDS is changed without updating this branch, the
        # AssertionError surfaces immediately rather than silently falling through.
        raise AssertionError(f"unhandled allowed command {intent.command!r}")

    return _result(intent, violations)


def validate_intent(intent: RawIntent) -> ValidationResult:
    """Validate a raw intent with schema checks before semantic checks.

    Args:
        intent: Raw intent contract to validate.

    Returns:
        A deterministic validation result containing all validation violations.
    """
    schema_result = validate_schema(intent)
    semantic_result = validate_semantics(intent)
    violations = [*schema_result.violations, *semantic_result.violations]

    return _result(intent, violations)


def _validate_stop(intent: RawIntent) -> list[Violation]:
    return _unexpected_parameter_violations(intent.parameters, frozenset())


def _validate_wait(intent: RawIntent) -> list[Violation]:
    violations = _unexpected_parameter_violations(intent.parameters, frozenset({"duration_ms"}))
    if "duration_ms" not in intent.parameters:
        violations.append(
            _violation(
                "parameters.duration_ms",
                "wait command requires duration_ms",
                "missing_parameter",
            )
        )
        return violations

    duration = intent.parameters["duration_ms"]

    if isinstance(duration, bool):
        violations.append(
            _violation(
                "parameters.duration_ms",
                "duration_ms must be an integer and bool is not allowed",
                "bool_not_allowed_for_integer",
            )
        )
    elif not isinstance(duration, int):
        violations.append(
            _violation(
                "parameters.duration_ms",
                "duration_ms must be an integer",
                "invalid_parameter_type",
            )
        )
    elif duration <= 0:
        violations.append(
            _violation(
                "parameters.duration_ms",
                "duration_ms must be greater than 0",
                "invalid_parameter_value",
            )
        )
    elif duration > MAX_WAIT_DURATION_MS:
        violations.append(
            _violation(
                "parameters.duration_ms",
                f"duration_ms must be at most {MAX_WAIT_DURATION_MS}",
                "invalid_parameter_value",
            )
        )

    return violations


def _validate_inspect(intent: RawIntent) -> list[Violation]:
    violations = _unexpected_parameter_violations(intent.parameters, frozenset({"target"}))
    if "target" not in intent.parameters:
        violations.append(
            _violation(
                "parameters.target",
                "inspect command requires target",
                "missing_parameter",
            )
        )
        return violations

    target = intent.parameters["target"]
    if not isinstance(target, str):
        violations.append(
            _violation(
                "parameters.target",
                "target must be a string",
                "invalid_parameter_type",
            )
        )
        return violations
    if target.strip() == "":
        violations.append(
            _violation(
                "parameters.target",
                "target must be non-empty",
                "invalid_parameter_value",
            )
        )
    return violations


def _validate_move(intent: RawIntent) -> list[Violation]:
    violations = _unexpected_parameter_violations(intent.parameters, frozenset({"target"}))
    if "target" not in intent.parameters:
        violations.append(
            _violation(
                "parameters.target",
                "move command requires target",
                "missing_parameter",
            )
        )
        return violations

    target = intent.parameters["target"]
    if not isinstance(target, Mapping):
        violations.append(
            _violation(
                "parameters.target",
                "target must be an object with x and y",
                "invalid_parameter_type",
            )
        )
        return violations

    target_mapping = cast(Mapping[str, FrozenJsonValue], target)
    for axis in ("x", "y"):
        if axis not in target_mapping:
            violations.append(
                _violation(
                    f"parameters.target.{axis}",
                    f"move target requires {axis}",
                    "missing_parameter",
                )
            )
        else:
            violations.extend(_validate_coordinate(axis, target_mapping[axis]))

    return violations


def _unexpected_parameter_violations(
    parameters: Mapping[str, FrozenJsonValue],
    allowed_fields: frozenset[str],
) -> list[Violation]:
    if all(key in allowed_fields for key in parameters):
        return []
    return [
        _violation(
            "parameters",
            "command contains unsupported parameter names",
            "unexpected_parameters",
        )
    ]


def _validate_coordinate(axis: str, coordinate: FrozenJsonValue) -> list[Violation]:
    field = f"parameters.target.{axis}"
    if isinstance(coordinate, bool):
        return [
            _violation(
                field,
                f"{axis} must be a finite number and bool is not allowed",
                "bool_not_allowed_for_number",
            )
        ]
    if not isinstance(coordinate, (int, float)):
        return [_violation(field, f"{axis} must be a finite number", "invalid_parameter_type")]
    # CONTRACT-CORRUPTION DEFENSE: RawIntent.freeze_json_mapping already rejects
    # non-finite floats via is_json_value, so this branch is unreachable via the
    # normal public API.  It remains as a defense-in-depth guard.
    if isinstance(coordinate, float) and not isfinite(coordinate):
        return [_violation(field, f"{axis} must be finite", "invalid_parameter_value")]
    return []


def _result(intent: RawIntent, violations: list[Violation]) -> ValidationResult:
    return ValidationResult(is_valid=not violations, intent=intent, violations=violations)


def _violation(field: str, reason: str, code: str) -> Violation:
    return Violation(field=field, reason=reason, code=code, layer=_LAYER)
