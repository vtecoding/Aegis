"""Planning-v1 command plan construction."""

from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
from typing import cast

from aegis.aegis_errors import PlanningError
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import FrozenJsonValue, JsonValue
from aegis.contracts.aegis_planning import CommandPlan, CommandStep, CommandStepType
from aegis.contracts.aegis_validation import ValidationResult
from aegis.planning.aegis_plan_hasher import stable_plan_id

_LAYER = "planning"


def plan_validated_intent(validation: ValidationResult) -> CommandPlan:
    """Create a deterministic command plan from an already-valid intent.

    Args:
        validation: Successful validation result produced by the validation layer.

    Returns:
        A command plan containing one planning-v1 command step.

    Raises:
        PlanningError: If validation failed, contains violations, or the intent
            cannot be translated into a planning-v1 command step.
    """
    if not validation.is_valid:
        raise _planning_error(
            "cannot plan an invalid validation result",
            {
                "reason": "validation_result_invalid",
                "violation_codes": [violation.code for violation in validation.violations],
                "violation_count": len(validation.violations),
            },
        )
    if validation.violations:
        raise _planning_error(
            "cannot plan a validation result with violations",
            {
                "reason": "validation_result_contains_violations",
                "violation_codes": [violation.code for violation in validation.violations],
                "violation_count": len(validation.violations),
            },
        )

    step = _step_for_intent(validation.intent)
    steps = (step,)
    return CommandPlan(stable_plan_id(validation.intent, steps), validation.intent, steps)


def _step_for_intent(intent: RawIntent) -> CommandStep:
    if intent.command == "stop":
        return _plan_stop(intent)
    if intent.command == "wait":
        return _plan_wait(intent)
    if intent.command == "inspect":
        return _plan_inspect(intent)
    if intent.command == "move":
        return _plan_move(intent)
    raise _planning_error(
        "unsupported command cannot be planned",
        {"reason": "unsupported_command", "command": intent.command},
    )


def _plan_stop(intent: RawIntent) -> CommandStep:
    if intent.parameters:
        raise _malformed_parameters(intent.command, "parameters", "stop does not accept parameters")
    return CommandStep(CommandStepType.STOP, {}, 0)


def _plan_wait(intent: RawIntent) -> CommandStep:
    duration = intent.parameters.get("duration_ms")
    if isinstance(duration, bool) or not isinstance(duration, int):
        raise _malformed_parameters(
            intent.command,
            "parameters.duration_ms",
            "wait requires integer duration_ms",
        )
    return CommandStep(CommandStepType.WAIT, {"duration_ms": duration}, 0)


def _plan_inspect(intent: RawIntent) -> CommandStep:
    target = intent.parameters.get("target")
    if not isinstance(target, str) or target.strip() == "":
        raise _malformed_parameters(
            intent.command,
            "parameters.target",
            "inspect requires non-empty string target",
        )
    return CommandStep(CommandStepType.INSPECT, {"target": target}, 0)


def _plan_move(intent: RawIntent) -> CommandStep:
    target = intent.parameters.get("target")
    if not isinstance(target, Mapping):
        raise _malformed_parameters(
            intent.command,
            "parameters.target",
            "move requires target object",
        )

    target_mapping = cast(Mapping[str, FrozenJsonValue], target)
    x = _required_coordinate(intent.command, target_mapping, "x")
    y = _required_coordinate(intent.command, target_mapping, "y")
    return CommandStep(CommandStepType.MOVE, {"target": {"x": x, "y": y}}, 0)


def _required_coordinate(
    command: str,
    target: Mapping[str, FrozenJsonValue],
    axis: str,
) -> int | float:
    if axis not in target:
        raise _malformed_parameters(command, f"parameters.target.{axis}", f"move requires {axis}")

    value = target[axis]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _malformed_parameters(
            command,
            f"parameters.target.{axis}",
            f"move {axis} must be a finite number",
        )
    if isinstance(value, float) and not isfinite(value):
        raise _malformed_parameters(
            command,
            f"parameters.target.{axis}",
            f"move {axis} must be finite",
        )
    return value


def _malformed_parameters(command: str, field: str, reason: str) -> PlanningError:
    return _planning_error(
        "malformed valid-looking command parameters",
        {"reason": reason, "command": command, "field": field},
    )


def _planning_error(message: str, context: Mapping[str, JsonValue]) -> PlanningError:
    return PlanningError(message, _LAYER, context)
