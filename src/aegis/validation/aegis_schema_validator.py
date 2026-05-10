"""Schema-level validation for raw Aegis intents."""

from __future__ import annotations

from collections.abc import Mapping

from aegis.aegis_constants import (
    MAX_PARAMETER_DEPTH,
    MAX_PARAMETER_KEYS,
    MAX_PRIORITY,
    MAX_STRING_LENGTH,
    MIN_PRIORITY,
)
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import FrozenJsonValue
from aegis.contracts.aegis_validation import ValidationResult, Violation

_LAYER = "validation"

type _ParameterNode = FrozenJsonValue | Mapping[str, FrozenJsonValue]


def validate_schema(intent: RawIntent) -> ValidationResult:
    """Validate raw intent schema limits and boundary-level structure.

    Args:
        intent: Raw intent contract to validate.

    Returns:
        A deterministic validation result containing schema violations only.
    """
    violations: list[Violation] = []

    if intent.command == "":
        violations.append(_violation("command", "command must be non-empty", "missing_command"))
    if len(intent.command) > MAX_STRING_LENGTH:
        violations.append(
            _violation(
                "command",
                f"command exceeds maximum string length of {MAX_STRING_LENGTH}",
                "string_length_exceeded",
            )
        )

    if intent.source_id == "":
        violations.append(_violation("source_id", "source_id must be non-empty", "missing_source"))
    if len(intent.source_id) > MAX_STRING_LENGTH:
        violations.append(
            _violation(
                "source_id",
                f"source_id exceeds maximum string length of {MAX_STRING_LENGTH}",
                "string_length_exceeded",
            )
        )

    if isinstance(intent.priority, bool):
        violations.append(
            _violation(
                "priority",
                "priority must be an integer and bool is not allowed",
                "bool_not_allowed_for_integer",
            )
        )
    elif intent.priority < MIN_PRIORITY or intent.priority > MAX_PRIORITY:
        violations.append(
            _violation(
                "priority",
                f"priority must be between {MIN_PRIORITY} and {MAX_PRIORITY}",
                "priority_out_of_range",
            )
        )

    if len(intent.context.request_id) > MAX_STRING_LENGTH:
        violations.append(
            _violation(
                "context.request_id",
                f"request_id exceeds maximum string length of {MAX_STRING_LENGTH}",
                "string_length_exceeded",
            )
        )
    if len(intent.context.policy_version) > MAX_STRING_LENGTH:
        violations.append(
            _violation(
                "context.policy_version",
                f"policy_version exceeds maximum string length of {MAX_STRING_LENGTH}",
                "string_length_exceeded",
            )
        )
    if intent.context.run_id is not None and len(intent.context.run_id) > MAX_STRING_LENGTH:
        violations.append(
            _violation(
                "context.run_id",
                f"run_id exceeds maximum string length of {MAX_STRING_LENGTH}",
                "string_length_exceeded",
            )
        )

    violations.extend(_collect_parameter_limit_violations(intent.parameters))

    return _result(intent, violations)


def _collect_parameter_limit_violations(
    parameters: Mapping[str, FrozenJsonValue],
) -> list[Violation]:
    violations: list[Violation] = []
    nodes: list[tuple[str, _ParameterNode, int]] = [("parameters", parameters, 1)]
    next_node_index = 0
    total_keys = 0
    depth_reported = False
    key_limit_reported = False

    while next_node_index < len(nodes):
        field, value, depth = nodes[next_node_index]
        next_node_index += 1

        if depth > MAX_PARAMETER_DEPTH:
            if not depth_reported:
                violations.append(
                    _violation(
                        field,
                        f"parameters exceed maximum depth of {MAX_PARAMETER_DEPTH}",
                        "parameter_depth_exceeded",
                    )
                )
                depth_reported = True
            continue

        if isinstance(value, str):
            if len(value) > MAX_STRING_LENGTH:
                violations.append(
                    _violation(
                        field,
                        f"string exceeds maximum length of {MAX_STRING_LENGTH}",
                        "string_length_exceeded",
                    )
                )
            continue

        if isinstance(value, tuple):
            for index, item in enumerate(value):
                nodes.append((f"{field}[{index}]", item, depth + 1))
            continue

        if isinstance(value, Mapping):
            for key, item in sorted(value.items(), key=lambda entry: entry[0]):
                total_keys += 1
                child_field = f"{field}.{key}"
                if len(key) > MAX_STRING_LENGTH:
                    violations.append(
                        _violation(
                            child_field,
                            f"object key exceeds maximum string length of {MAX_STRING_LENGTH}",
                            "string_length_exceeded",
                        )
                    )
                if total_keys > MAX_PARAMETER_KEYS and not key_limit_reported:
                    violations.append(
                        _violation(
                            child_field,
                            f"parameters exceed maximum key count of {MAX_PARAMETER_KEYS}",
                            "parameter_key_limit_exceeded",
                        )
                    )
                    key_limit_reported = True
                nodes.append((child_field, item, depth + 1))

    return violations


def _result(intent: RawIntent, violations: list[Violation]) -> ValidationResult:
    return ValidationResult(is_valid=not violations, intent=intent, violations=violations)


def _violation(field: str, reason: str, code: str) -> Violation:
    return Violation(field=field, reason=reason, code=code, layer=_LAYER)
