"""Planning contracts for deterministic command plans."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_json_types import FrozenJsonValue, JsonValue, freeze_json_mapping


class CommandStepType(StrEnum):
    """Supported abstract command step types emitted by planning-v1."""

    MOVE = "move"
    STOP = "stop"
    INSPECT = "inspect"
    WAIT = "wait"


@dataclass(frozen=True, slots=True, init=False)
class CommandStep:
    """A deterministic abstract command step.

    Args:
        step_type: Supported command step type.
        parameters: JSON-compatible step parameters.
        sequence: Zero-based command sequence index.

    Raises:
        ValueError: If the step type is unsupported, sequence is negative, or
            parameters are not JSON-compatible.
    """

    step_type: CommandStepType
    parameters: Mapping[str, FrozenJsonValue]
    sequence: int

    def __init__(
        self,
        step_type: object,
        parameters: Mapping[str, JsonValue],
        sequence: object,
    ) -> None:
        if not isinstance(step_type, CommandStepType):
            raise ValueError("step_type must be a CommandStepType")
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise ValueError("sequence must be an integer")
        if sequence < 0:
            raise ValueError("sequence must be greater than or equal to 0")

        object.__setattr__(self, "step_type", step_type)
        object.__setattr__(self, "parameters", freeze_json_mapping(parameters))
        object.__setattr__(self, "sequence", sequence)


@dataclass(frozen=True, slots=True, init=False)
class CommandPlan:
    """Deterministic immutable command plan emitted by planning-v1.

    Args:
        plan_id: Deterministic plan identifier.
        intent: Original raw intent preserved for audit and replay.
        steps: Ordered non-empty command steps.

    Raises:
        ValueError: If plan_id is empty, steps are empty, or step sequences are
            not exactly contiguous from zero.
    """

    plan_id: str
    intent: RawIntent
    steps: tuple[CommandStep, ...]

    def __init__(
        self,
        plan_id: str,
        intent: RawIntent,
        steps: Iterable[CommandStep],
    ) -> None:
        plan_id = plan_id.strip()
        if plan_id == "":
            raise ValueError("plan_id must be non-empty")

        steps_tuple = tuple(steps)
        if not steps_tuple:
            raise ValueError("steps must be non-empty")

        for expected_sequence, step in enumerate(steps_tuple):
            if step.sequence != expected_sequence:
                raise ValueError("step sequence values must be contiguous from 0")

        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "intent", intent)
        object.__setattr__(self, "steps", steps_tuple)
