"""Raw intent boundary contract for Aegis."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aegis.contracts.context import ExecutionContext
from aegis.contracts.json_types import FrozenJsonValue, JsonValue, freeze_json_mapping


@dataclass(frozen=True, slots=True, init=False)
class RawIntent:
    """Boundary-level intent submitted to the deterministic core.

    Args:
        command: Non-empty command string.
        parameters: JSON-compatible parameter object.
        source_id: Non-empty caller/source identifier.
        priority: Integer priority from 1 through 10 inclusive.
        context: Caller-injected execution context.

    Raises:
        ValueError: If text fields are empty, priority is out of range, or
            parameters are not JSON-compatible.
    """

    command: str
    parameters: Mapping[str, FrozenJsonValue]
    source_id: str
    priority: int
    context: ExecutionContext

    def __init__(
        self,
        command: str,
        parameters: Mapping[str, JsonValue],
        source_id: str,
        priority: int,
        context: ExecutionContext,
    ) -> None:
        command = command.strip()
        if command == "":
            raise ValueError("command must be non-empty")

        source_id = source_id.strip()
        if source_id == "":
            raise ValueError("source_id must be non-empty")

        if priority < 1 or priority > 10:
            raise ValueError("priority must be between 1 and 10 inclusive")

        object.__setattr__(self, "command", command)
        object.__setattr__(self, "parameters", freeze_json_mapping(parameters))
        object.__setattr__(self, "source_id", source_id)
        object.__setattr__(self, "priority", priority)
        object.__setattr__(self, "context", context)
