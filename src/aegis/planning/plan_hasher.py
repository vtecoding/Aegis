"""Deterministic plan identifier hashing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime

from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import FrozenJsonValue
from aegis.contracts.planning import CommandStep

type CanonicalJsonValue = (
    str | int | float | bool | None | list[CanonicalJsonValue] | dict[str, CanonicalJsonValue]
)


def stable_plan_id(intent: RawIntent, steps: tuple[CommandStep, ...]) -> str:
    """Return a deterministic SHA-256 plan identifier.

    Args:
        intent: Original validated intent used to construct the plan.
        steps: Ordered command steps emitted for the intent.

    Returns:
        A lowercase 64-character SHA-256 hexadecimal digest.
    """
    payload: dict[str, CanonicalJsonValue] = {
        "intent": {
            "command": intent.command,
            "parameters": _canonical_json_mapping(intent.parameters),
            "source_id": intent.source_id,
            "priority": intent.priority,
            "context": {
                "request_id": intent.context.request_id,
                "submitted_at": _iso_utc(intent.context.submitted_at),
                "policy_version": intent.context.policy_version,
                "run_id": intent.context.run_id,
            },
        },
        "steps": [_canonical_step(step) for step in steps],
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _canonical_step(step: CommandStep) -> dict[str, CanonicalJsonValue]:
    return {
        "step_type": step.step_type.value,
        "parameters": _canonical_json_mapping(step.parameters),
        "sequence": step.sequence,
    }


def _canonical_json_mapping(values: Mapping[str, FrozenJsonValue]) -> dict[str, CanonicalJsonValue]:
    return {key: _canonical_json_value(values[key]) for key in sorted(values)}


def _canonical_json_value(value: FrozenJsonValue) -> CanonicalJsonValue:
    if isinstance(value, Mapping):
        return _canonical_json_mapping(value)
    if isinstance(value, tuple):
        return [_canonical_json_value(item) for item in value]
    return value


def _iso_utc(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")
