"""Deterministic SHA-256 checksums for command plan audit receipts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime

from aegis.contracts.json_types import FrozenJsonValue
from aegis.contracts.planning import CommandPlan, CommandStep

type _CanonicalJsonValue = (
    str | int | float | bool | None | list[_CanonicalJsonValue] | dict[str, _CanonicalJsonValue]
)


def plan_checksum(plan: CommandPlan) -> str:
    """Compute a deterministic SHA-256 checksum of the executable plan payload.

    Covers the plan_id (an opaque reference that already encodes the full planning
    event) and the concrete command steps (step_type, parameters, sequence).  Caller
    context fields (request_id, submitted_at, policy_version, run_id) are intentionally
    excluded — they are bound into audit_id instead.

    Design invariant::

        same plan_id + same steps  →  same checksum
        different context only     →  same checksum, different audit_id

    Args:
        plan: The command plan to checksum.

    Returns:
        A lowercase 64-character SHA-256 hexadecimal digest.
    """
    payload: dict[str, _CanonicalJsonValue] = {
        "plan_id": plan.plan_id,
        "steps": [_canonical_step(step) for step in plan.steps],
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def plan_audit_id(plan: CommandPlan, checksum: str) -> str:
    """Compute a deterministic SHA-256 audit event identifier.

    The audit_id incorporates the plan checksum and the execution context
    (request_id, submitted_at, policy_version, run_id), producing a unique
    identifier for this specific plan-plus-context audit event.

    Args:
        plan: The command plan being audited.
        checksum: The plan checksum already computed by ``plan_checksum``.

    Returns:
        A lowercase 64-character SHA-256 hexadecimal digest.
    """
    payload: dict[str, _CanonicalJsonValue] = {
        "checksum": checksum,
        "plan_id": plan.plan_id,
        "context": {
            "request_id": plan.intent.context.request_id,
            "submitted_at": _iso_utc(plan.intent.context.submitted_at),
            "policy_version": plan.intent.context.policy_version,
            "run_id": plan.intent.context.run_id,
        },
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _canonical_step(step: CommandStep) -> dict[str, _CanonicalJsonValue]:
    return {
        "parameters": _canonical_json_mapping(step.parameters),
        "sequence": step.sequence,
        "step_type": step.step_type.value,
    }


def _canonical_json_mapping(
    values: Mapping[str, FrozenJsonValue],
) -> dict[str, _CanonicalJsonValue]:
    return {key: _canonical_json_value(values[key]) for key in sorted(values)}


def _canonical_json_value(value: FrozenJsonValue) -> _CanonicalJsonValue:
    if isinstance(value, Mapping):
        return _canonical_json_mapping(value)
    if isinstance(value, tuple):
        return [_canonical_json_value(item) for item in value]
    return value


def _iso_utc(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")
