"""Policy admission contracts for pipeline enforcement wiring."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import cast

from aegis.contracts.policy import (
    Capability,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    SafetyCase,
    WorldSnapshotStub,
)


class PolicyAdmissionMode(StrEnum):
    """Pipeline policy admission modes."""

    DISABLED = "DISABLED"
    ENFORCE = "ENFORCE"


@dataclass(frozen=True, slots=True, init=False)
class PolicyAdmissionInput:
    """Explicit policy admission inputs supplied by the pipeline caller.

    Args:
        mode: Whether policy admission is disabled or enforced.
        policy: Policy-v1 bundle to evaluate in ``ENFORCE`` mode.
        capability: Explicit requested capability to evaluate in ``ENFORCE`` mode.
        world_snapshot: Optional caller-supplied world evidence stub.
        context: Deterministic evaluator context. Values are recursively frozen.
        evidence: Inert SafetyCase evidence. Values are recursively frozen.

    Raises:
        ValueError: If mode is invalid, disabled mode includes policy inputs, or
            context/evidence contain unsupported values.
    """

    mode: PolicyAdmissionMode
    policy: Policy | None
    capability: Capability | None
    world_snapshot: WorldSnapshotStub | None
    context: Mapping[str, FrozenPolicyValue]
    evidence: Mapping[str, FrozenPolicyValue]

    def __init__(
        self,
        mode: str | PolicyAdmissionMode,
        policy: Policy | None = None,
        capability: Capability | None = None,
        world_snapshot: WorldSnapshotStub | None = None,
        context: Mapping[str, object] | None = None,
        evidence: Mapping[str, object] | None = None,
    ) -> None:
        normalized_mode = _normalize_mode(mode)
        frozen_context = _freeze_admission_mapping(context or {})
        frozen_evidence = _freeze_admission_mapping(evidence or {})

        if normalized_mode is PolicyAdmissionMode.DISABLED and (
            policy is not None
            or capability is not None
            or world_snapshot is not None
            or frozen_context
            or frozen_evidence
        ):
            raise ValueError("DISABLED policy admission must not include policy inputs")

        object.__setattr__(self, "mode", normalized_mode)
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "world_snapshot", world_snapshot)
        object.__setattr__(self, "context", frozen_context)
        object.__setattr__(self, "evidence", frozen_evidence)


@dataclass(frozen=True, slots=True, init=False)
class PolicyAdmissionRecord:
    """Observable result of pipeline policy admission.

    Args:
        mode: Admission mode used for the pipeline run.
        policy_result: Policy-v1 evaluator result when evaluation ran.
        safety_case: SafetyCase bound to the audited plan when available.
        enforced: Whether policy enforcement was requested.
        admission_allowed: Whether policy admission permits proceeding to gate.
        reasons: Deterministic admission reason codes.

    Raises:
        ValueError: If the field combination contradicts admission semantics.
    """

    mode: PolicyAdmissionMode
    policy_result: PolicyEvaluationResult | None
    safety_case: SafetyCase | None
    enforced: bool
    admission_allowed: bool
    reasons: tuple[str, ...]

    def __init__(
        self,
        mode: str | PolicyAdmissionMode,
        policy_result: PolicyEvaluationResult | None,
        safety_case: SafetyCase | None,
        enforced: object,
        admission_allowed: object,
        reasons: Iterable[str],
    ) -> None:
        normalized_mode = _normalize_mode(mode)
        if not isinstance(enforced, bool):
            raise ValueError("enforced must be a bool")
        if not isinstance(admission_allowed, bool):
            raise ValueError("admission_allowed must be a bool")

        normalized_reasons = _normalize_text_tuple(reasons, "reasons")

        if normalized_mode is PolicyAdmissionMode.DISABLED:
            _validate_disabled_record(policy_result, safety_case, enforced, admission_allowed)

        if normalized_mode is PolicyAdmissionMode.ENFORCE:
            _validate_enforced_record(
                policy_result=policy_result,
                safety_case=safety_case,
                enforced=enforced,
                admission_allowed=admission_allowed,
                reasons=normalized_reasons,
            )

        object.__setattr__(self, "mode", normalized_mode)
        object.__setattr__(self, "policy_result", policy_result)
        object.__setattr__(self, "safety_case", safety_case)
        object.__setattr__(self, "enforced", enforced)
        object.__setattr__(self, "admission_allowed", admission_allowed)
        object.__setattr__(self, "reasons", normalized_reasons)


def disabled_policy_admission_record() -> PolicyAdmissionRecord:
    """Return the canonical disabled-mode policy admission record."""
    return PolicyAdmissionRecord(
        mode=PolicyAdmissionMode.DISABLED,
        policy_result=None,
        safety_case=None,
        enforced=False,
        admission_allowed=True,
        reasons=("POLICY_ADMISSION_DISABLED",),
    )


def _validate_disabled_record(
    policy_result: PolicyEvaluationResult | None,
    safety_case: SafetyCase | None,
    enforced: bool,
    admission_allowed: bool,
) -> None:
    if enforced:
        raise ValueError("DISABLED admission records must not be enforced")
    if not admission_allowed:
        raise ValueError("DISABLED admission records must preserve legacy admission")
    if policy_result is not None:
        raise ValueError("DISABLED admission records must not contain policy_result")
    if safety_case is not None:
        raise ValueError("DISABLED admission records must not contain safety_case")


def _validate_enforced_record(
    *,
    policy_result: PolicyEvaluationResult | None,
    safety_case: SafetyCase | None,
    enforced: bool,
    admission_allowed: bool,
    reasons: tuple[str, ...],
) -> None:
    if not enforced:
        raise ValueError("ENFORCE admission records must be enforced")
    if safety_case is not None and policy_result is None:
        raise ValueError("safety_case requires policy_result")
    if safety_case is not None and safety_case.policy_result != policy_result:
        raise ValueError("safety_case must explain policy_result")
    if admission_allowed:
        if policy_result is None:
            raise ValueError("allowed ENFORCE admission requires policy_result")
        if policy_result.decision is not PolicyDecision.ALLOW:
            raise ValueError("admission_allowed=True requires policy decision ALLOW")
        if safety_case is None:
            raise ValueError("allowed ENFORCE admission requires safety_case")
    elif reasons == ():
        raise ValueError("denied ENFORCE admission requires reasons")


def _normalize_mode(value: str | PolicyAdmissionMode) -> PolicyAdmissionMode:
    if isinstance(value, PolicyAdmissionMode):
        return value
    try:
        return PolicyAdmissionMode(value.strip())
    except ValueError:
        raise ValueError("mode must be DISABLED or ENFORCE") from None


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must contain non-empty strings")
    return normalized


def _normalize_text_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of strings")

    normalized_values: list[str] = []
    for value in values:
        normalized_values.append(_normalize_required_text(value, field_name))
    return tuple(normalized_values)


def _freeze_admission_mapping(values: Mapping[str, object]) -> Mapping[str, FrozenPolicyValue]:
    return _freeze_admission_items(values.items())


def _freeze_admission_items(
    items: Iterable[tuple[object, object]],
) -> Mapping[str, FrozenPolicyValue]:
    frozen_values: dict[str, FrozenPolicyValue] = {}
    for key, value in items:
        if not isinstance(key, str):
            raise ValueError("policy admission mapping keys must be strings")
        frozen_values[key] = _freeze_admission_value(value)
    return MappingProxyType({key: frozen_values[key] for key in sorted(frozen_values)})


def _freeze_admission_value(value: object) -> FrozenPolicyValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("policy admission numeric values must be finite")
        return value
    if isinstance(value, list):
        items = cast(list[object], value)
        return tuple(_freeze_admission_value(item) for item in items)
    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(_freeze_admission_value(item) for item in items)
    if isinstance(value, set):
        items = cast(set[object], value)
        return frozenset(_freeze_admission_value(item) for item in items)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _freeze_admission_items(mapping.items())
    raise ValueError("policy admission values must be primitive values or nested containers")


__all__ = [
    "PolicyAdmissionInput",
    "PolicyAdmissionMode",
    "PolicyAdmissionRecord",
    "disabled_policy_admission_record",
]
