"""Pure deterministic Policy-v1 evaluator."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from math import isfinite
from types import MappingProxyType
from typing import TypeGuard, cast

from aegis.contracts.policy import (
    Capability,
    Constraint,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyDefaultDecision,
    PolicyEvaluationResult,
    PolicyRule,
    SafetyCase,
    WorldSnapshotStub,
)
from aegis.policy.safety_case import build_safety_case
from aegis.policy.validation import validate_policy

_EMERGENCY_STOP_CAPABILITY = "system.emergency_stop"


@dataclass(frozen=True, slots=True)
class ConstraintEvaluation:
    """Structured result for one deterministic constraint evaluation."""

    constraint_id: str
    constraint_type: str
    passed: bool
    required: bool
    reason: str
    evidence: Mapping[str, FrozenPolicyValue]


def evaluate_policy(
    *,
    policy: Policy,
    capability: Capability,
    world_snapshot: WorldSnapshotStub | None = None,
    context: Mapping[str, object] | None = None,
) -> PolicyEvaluationResult:
    """Evaluate a Capability against a Policy-v1 bundle and optional evidence.

    Args:
        policy: Immutable Policy-v1 rule bundle.
        capability: Capability requested by the caller.
        world_snapshot: Optional immutable caller-supplied world evidence.
        context: Optional deterministic caller-supplied evaluation context.

    Returns:
        A PolicyEvaluationResult explaining ALLOW, BLOCK, REQUIRE_REVIEW, or
        INVALID. The evaluator performs no I/O and reads no live state.

    Raises:
        ValueError: If the policy object violates Policy-v1 structural invariants.
    """
    result, _evaluations = _evaluate_policy_details(
        policy=policy,
        capability=capability,
        world_snapshot=world_snapshot,
        context=context,
    )
    return result


def evaluate_policy_with_safety_case(
    *,
    policy: Policy,
    capability: Capability,
    audited_plan_id: str,
    world_snapshot: WorldSnapshotStub | None = None,
    context: Mapping[str, object] | None = None,
    evidence: Mapping[str, object] | None = None,
) -> tuple[PolicyEvaluationResult, SafetyCase]:
    """Evaluate policy and build a deterministic SafetyCase explanation.

    Args:
        policy: Immutable Policy-v1 rule bundle.
        capability: Capability requested by the caller.
        audited_plan_id: Caller-supplied audited plan ID to bind in evidence.
        world_snapshot: Optional immutable caller-supplied world evidence.
        context: Optional deterministic caller-supplied evaluation context.
        evidence: Optional extra deterministic evidence to include.

    Returns:
        A tuple of policy evaluation result and SafetyCase.

    Raises:
        ValueError: If policy validation or SafetyCase construction fails.
    """
    result, evaluations = _evaluate_policy_details(
        policy=policy,
        capability=capability,
        world_snapshot=world_snapshot,
        context=context,
    )
    safety_evidence: dict[str, object] = dict(evidence or {})
    safety_evidence["capability_name"] = capability.name
    safety_evidence["capability_version"] = capability.version
    safety_evidence["constraint_evaluations"] = tuple(
        _constraint_evaluation_evidence(evaluation) for evaluation in evaluations
    )
    safety_case = build_safety_case(
        policy_result=result,
        audited_plan_id=audited_plan_id,
        world_snapshot=world_snapshot,
        evidence=safety_evidence,
    )
    return result, safety_case


def _evaluate_policy_details(
    *,
    policy: Policy,
    capability: Capability,
    world_snapshot: WorldSnapshotStub | None,
    context: Mapping[str, object] | None,
) -> tuple[PolicyEvaluationResult, tuple[ConstraintEvaluation, ...]]:
    validate_policy(policy)
    try:
        frozen_context = _freeze_context(context)
    except ValueError:
        return (
            PolicyEvaluationResult(
                PolicyDecision.INVALID,
                policy.policy_id,
                (),
                (),
                (),
                ("POLICY_EVALUATION_CONTEXT_INVALID",),
            ),
            (),
        )

    matched_rules = tuple(
        rule for rule in policy.rules if rule.enabled and rule.capability == capability.name
    )
    if not matched_rules:
        return _no_matching_rule_result(policy), ()

    evaluations: list[ConstraintEvaluation] = []
    for rule in matched_rules:
        for index, constraint in enumerate(rule.constraints):
            evaluations.append(
                _evaluate_constraint(
                    rule_id=rule.rule_id,
                    constraint_index=index,
                    constraint=constraint,
                    capability=capability,
                    world_snapshot=world_snapshot,
                    context=frozen_context,
                )
            )

    result = _aggregate_evaluations(policy.policy_id, matched_rules, tuple(evaluations))
    return result, tuple(evaluations)


def _no_matching_rule_result(policy: Policy) -> PolicyEvaluationResult:
    if policy.default_decision is PolicyDefaultDecision.REQUIRE_REVIEW:
        return PolicyEvaluationResult(
            PolicyDecision.REQUIRE_REVIEW,
            policy.policy_id,
            (),
            (),
            (),
            ("POLICY_NO_MATCHING_RULE", "POLICY_DEFAULT_REQUIRE_REVIEW"),
        )
    return PolicyEvaluationResult(
        PolicyDecision.BLOCK,
        policy.policy_id,
        (),
        (),
        (),
        ("POLICY_NO_MATCHING_RULE", "POLICY_DEFAULT_BLOCK"),
    )


def _aggregate_evaluations(
    policy_id: str,
    matched_rules: Iterable[PolicyRule],
    evaluations: tuple[ConstraintEvaluation, ...],
) -> PolicyEvaluationResult:
    matched_rule_ids = tuple(rule.rule_id for rule in matched_rules)
    passed_constraints = tuple(
        evaluation.constraint_id for evaluation in evaluations if evaluation.passed
    )
    failed_constraints = tuple(
        evaluation.constraint_id for evaluation in evaluations if not evaluation.passed
    )
    reasons = tuple(evaluation.reason for evaluation in evaluations)
    required_failures = tuple(
        evaluation for evaluation in evaluations if not evaluation.passed and evaluation.required
    )
    optional_failures = tuple(
        evaluation
        for evaluation in evaluations
        if not evaluation.passed and not evaluation.required
    )

    if required_failures:
        decision = PolicyDecision.BLOCK
        result_reasons = (*reasons, "POLICY_REQUIRED_CONSTRAINT_FAILED")
    elif optional_failures:
        decision = PolicyDecision.REQUIRE_REVIEW
        result_reasons = (*reasons, "POLICY_OPTIONAL_CONSTRAINT_FAILED")
    else:
        decision = PolicyDecision.ALLOW
        result_reasons = (*reasons, "POLICY_ALLOWED")

    return PolicyEvaluationResult(
        decision,
        policy_id,
        matched_rule_ids,
        passed_constraints,
        failed_constraints,
        result_reasons,
    )


def _evaluate_constraint(
    *,
    rule_id: str,
    constraint_index: int,
    constraint: Constraint,
    capability: Capability,
    world_snapshot: WorldSnapshotStub | None,
    context: Mapping[str, FrozenPolicyValue],
) -> ConstraintEvaluation:
    constraint_id = f"{rule_id}:{constraint_index}:{constraint.constraint_type}"
    match constraint.constraint_type:
        case "requires_world_snapshot":
            return _evaluate_requires_world_snapshot(constraint_id, constraint, world_snapshot)
        case "snapshot_freshness":
            return _evaluate_snapshot_freshness(constraint_id, constraint, world_snapshot, context)
        case "min_sensor_confidence":
            return _evaluate_min_sensor_confidence(constraint_id, constraint, world_snapshot)
        case "max_velocity":
            return _evaluate_max_velocity(constraint_id, constraint, capability)
        case "deny_zone":
            return _evaluate_deny_zone(constraint_id, constraint, world_snapshot)
        case "human_proximity_limit":
            return _evaluate_human_proximity_limit(constraint_id, constraint, world_snapshot)
        case "requires_authorisation":
            return _evaluate_requires_authorisation(constraint_id, constraint, context)
        case "requires_dual_authorisation":
            return _evaluate_requires_dual_authorisation(constraint_id, constraint, context)
        case "emergency_stop_override":
            return _evaluate_emergency_stop_override(constraint_id, constraint, capability)
        case _:
            return _constraint_result(
                constraint_id,
                constraint,
                False,
                "POLICY_UNKNOWN_CONSTRAINT_TYPE",
                {"constraint_type": constraint.constraint_type},
            )


def _evaluate_requires_world_snapshot(
    constraint_id: str,
    constraint: Constraint,
    world_snapshot: WorldSnapshotStub | None,
) -> ConstraintEvaluation:
    if world_snapshot is None:
        return _constraint_result(constraint_id, constraint, False, "WORLD_SNAPSHOT_REQUIRED", {})
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "WORLD_SNAPSHOT_PRESENT",
        _world_snapshot_evidence(world_snapshot),
    )


def _evaluate_snapshot_freshness(
    constraint_id: str,
    constraint: Constraint,
    world_snapshot: WorldSnapshotStub | None,
    context: Mapping[str, FrozenPolicyValue],
) -> ConstraintEvaluation:
    if world_snapshot is None:
        return _constraint_result(constraint_id, constraint, False, "WORLD_SNAPSHOT_REQUIRED", {})

    requested_at_ms = constraint.parameters.get("requested_at_ms", context.get("requested_at_ms"))
    if not _is_int_value(requested_at_ms):
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "REQUEST_TIME_REQUIRED",
            _world_snapshot_evidence(world_snapshot),
        )
    if requested_at_ms < world_snapshot.captured_at_ms:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "WORLD_SNAPSHOT_NOT_YET_VALID",
            {**_world_snapshot_evidence(world_snapshot), "requested_at_ms": requested_at_ms},
        )
    if requested_at_ms > world_snapshot.expires_at_ms:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "WORLD_SNAPSHOT_EXPIRED",
            {**_world_snapshot_evidence(world_snapshot), "requested_at_ms": requested_at_ms},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "WORLD_SNAPSHOT_FRESH",
        {**_world_snapshot_evidence(world_snapshot), "requested_at_ms": requested_at_ms},
    )


def _evaluate_min_sensor_confidence(
    constraint_id: str,
    constraint: Constraint,
    world_snapshot: WorldSnapshotStub | None,
) -> ConstraintEvaluation:
    if world_snapshot is None:
        return _constraint_result(constraint_id, constraint, False, "WORLD_SNAPSHOT_REQUIRED", {})

    threshold_value = constraint.parameters.get("min_confidence")
    if threshold_value is None:
        return _constraint_result(constraint_id, constraint, False, "MIN_CONFIDENCE_REQUIRED", {})
    min_confidence = _finite_number(threshold_value)
    if min_confidence is None or min_confidence < 0.0 or min_confidence > 1.0:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "MIN_CONFIDENCE_INVALID",
            {"min_confidence": threshold_value},
        )
    if world_snapshot.confidence < min_confidence:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "WORLD_SNAPSHOT_CONFIDENCE_TOO_LOW",
            {"snapshot_confidence": world_snapshot.confidence, "min_confidence": min_confidence},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "WORLD_SNAPSHOT_CONFIDENCE_ACCEPTED",
        {"snapshot_confidence": world_snapshot.confidence, "min_confidence": min_confidence},
    )


def _evaluate_max_velocity(
    constraint_id: str,
    constraint: Constraint,
    capability: Capability,
) -> ConstraintEvaluation:
    velocity_value = capability.parameters.get("velocity_mps")
    if velocity_value is None:
        return _constraint_result(constraint_id, constraint, False, "VELOCITY_REQUIRED", {})
    velocity_mps = _finite_number(velocity_value)
    if velocity_mps is None or velocity_mps < 0.0:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "VELOCITY_INVALID",
            {"observed_velocity_mps": velocity_value},
        )

    max_value = constraint.parameters.get("max_mps")
    if max_value is None:
        return _constraint_result(constraint_id, constraint, False, "MAX_VELOCITY_REQUIRED", {})
    max_mps = _finite_number(max_value)
    if max_mps is None or max_mps < 0.0:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "MAX_VELOCITY_INVALID",
            {"max_mps": max_value},
        )
    if velocity_mps > max_mps:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "VELOCITY_LIMIT_EXCEEDED",
            {"observed_velocity_mps": velocity_mps, "max_mps": max_mps},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "VELOCITY_WITHIN_LIMIT",
        {"observed_velocity_mps": velocity_mps, "max_mps": max_mps},
    )


def _evaluate_deny_zone(
    constraint_id: str,
    constraint: Constraint,
    world_snapshot: WorldSnapshotStub | None,
) -> ConstraintEvaluation:
    if world_snapshot is None:
        return _constraint_result(constraint_id, constraint, False, "WORLD_SNAPSHOT_REQUIRED", {})

    denied_zones = _string_sequence(constraint.parameters.get("zone_ids"), allow_empty=False)
    if denied_zones is None:
        return _constraint_result(constraint_id, constraint, False, "DENIED_ZONES_REQUIRED", {})

    target_zones = _target_zones(world_snapshot)
    if target_zones is None:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "TARGET_ZONE_EVIDENCE_REQUIRED",
            {"denied_zones": denied_zones},
        )
    for target_zone in target_zones:
        if target_zone in denied_zones:
            return _constraint_result(
                constraint_id,
                constraint,
                False,
                "TARGET_ZONE_DENIED",
                {"target_zone_id": target_zone, "denied_zones": denied_zones},
            )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "TARGET_ZONE_ALLOWED",
        {"target_zones": target_zones, "denied_zones": denied_zones},
    )


def _evaluate_human_proximity_limit(
    constraint_id: str,
    constraint: Constraint,
    world_snapshot: WorldSnapshotStub | None,
) -> ConstraintEvaluation:
    if world_snapshot is None:
        return _constraint_result(constraint_id, constraint, False, "WORLD_SNAPSHOT_REQUIRED", {})

    distance_value = world_snapshot.facts.get("nearest_human_distance_m")
    if distance_value is None:
        return _constraint_result(constraint_id, constraint, False, "HUMAN_DISTANCE_REQUIRED", {})
    nearest_human_distance_m = _finite_number(distance_value)
    if nearest_human_distance_m is None or nearest_human_distance_m < 0.0:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "HUMAN_DISTANCE_INVALID",
            {"nearest_human_distance_m": distance_value},
        )

    minimum_value = constraint.parameters.get("min_distance_m")
    if minimum_value is None:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "MIN_HUMAN_DISTANCE_REQUIRED",
            {},
        )
    min_distance_m = _finite_number(minimum_value)
    if min_distance_m is None or min_distance_m < 0.0:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "MIN_HUMAN_DISTANCE_INVALID",
            {"min_distance_m": minimum_value},
        )
    if nearest_human_distance_m < min_distance_m:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "HUMAN_TOO_CLOSE",
            {
                "nearest_human_distance_m": nearest_human_distance_m,
                "min_distance_m": min_distance_m,
            },
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "HUMAN_DISTANCE_ACCEPTED",
        {"nearest_human_distance_m": nearest_human_distance_m, "min_distance_m": min_distance_m},
    )


def _evaluate_requires_authorisation(
    constraint_id: str,
    constraint: Constraint,
    context: Mapping[str, FrozenPolicyValue],
) -> ConstraintEvaluation:
    required_authorisation = constraint.parameters.get("authorisation")
    if required_authorisation is None or required_authorisation == "":
        return _constraint_result(constraint_id, constraint, False, "AUTHORISATION_REQUIRED", {})
    if not isinstance(required_authorisation, str):
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "AUTHORISATION_INVALID",
            {"authorisation": required_authorisation},
        )

    if "authorisations" not in context:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "AUTHORISATIONS_CONTEXT_REQUIRED",
            {"required_authorisation": required_authorisation},
        )

    authorisations = _string_sequence(context["authorisations"], allow_empty=True)
    if authorisations is None:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "AUTHORISATION_INVALID",
            {"required_authorisation": required_authorisation},
        )
    if required_authorisation not in authorisations:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "AUTHORISATION_MISSING",
            {"required_authorisation": required_authorisation, "authorisations": authorisations},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "AUTHORISATION_PRESENT",
        {"required_authorisation": required_authorisation, "authorisations": authorisations},
    )


def _evaluate_requires_dual_authorisation(
    constraint_id: str,
    constraint: Constraint,
    context: Mapping[str, FrozenPolicyValue],
) -> ConstraintEvaluation:
    if constraint.parameters.get("required") is not True:
        return _constraint_result(
            constraint_id, constraint, False, "DUAL_AUTHORISATION_REQUIRED", {}
        )

    dual_authorised = context.get("dual_authorised")
    if dual_authorised is None or dual_authorised is False:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "DUAL_AUTHORISATION_MISSING",
            {},
        )
    if dual_authorised is not True:
        return _constraint_result(
            constraint_id,
            constraint,
            False,
            "DUAL_AUTHORISATION_INVALID",
            {"dual_authorised": dual_authorised},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        True,
        "DUAL_AUTHORISATION_PRESENT",
        {"dual_authorised": True},
    )


def _evaluate_emergency_stop_override(
    constraint_id: str,
    constraint: Constraint,
    capability: Capability,
) -> ConstraintEvaluation:
    if capability.name == _EMERGENCY_STOP_CAPABILITY:
        return _constraint_result(
            constraint_id,
            constraint,
            True,
            "EMERGENCY_STOP_ALLOWED",
            {"capability_name": capability.name},
        )
    return _constraint_result(
        constraint_id,
        constraint,
        False,
        "EMERGENCY_STOP_CONSTRAINT_MISMATCH",
        {"capability_name": capability.name},
    )


def _constraint_result(
    constraint_id: str,
    constraint: Constraint,
    passed: bool,
    reason: str,
    evidence: Mapping[str, object],
) -> ConstraintEvaluation:
    return ConstraintEvaluation(
        constraint_id=constraint_id,
        constraint_type=constraint.constraint_type,
        passed=passed,
        required=constraint.required,
        reason=reason,
        evidence=_freeze_mapping(evidence),
    )


def _constraint_evaluation_evidence(evaluation: ConstraintEvaluation) -> Mapping[str, object]:
    return {
        "constraint_id": evaluation.constraint_id,
        "constraint_type": evaluation.constraint_type,
        "passed": evaluation.passed,
        "required": evaluation.required,
        "reason": evaluation.reason,
        "evidence": evaluation.evidence,
    }


def _world_snapshot_evidence(world_snapshot: WorldSnapshotStub) -> dict[str, object]:
    return {
        "world_snapshot_id": world_snapshot.snapshot_id,
        "captured_at_ms": world_snapshot.captured_at_ms,
        "expires_at_ms": world_snapshot.expires_at_ms,
        "confidence": world_snapshot.confidence,
    }


def _target_zones(world_snapshot: WorldSnapshotStub) -> tuple[str, ...] | None:
    target_zone_id = world_snapshot.facts.get("target_zone_id")
    if isinstance(target_zone_id, str) and target_zone_id != "":
        return (target_zone_id,)
    if "zones_containing_target" in world_snapshot.facts:
        return _string_sequence(world_snapshot.facts["zones_containing_target"], allow_empty=True)
    return None


def _string_sequence(value: object, *, allow_empty: bool) -> tuple[str, ...] | None:
    if isinstance(value, str) or value is None:
        return None
    if isinstance(value, tuple):
        values = cast(tuple[object, ...], value)
    elif isinstance(value, list):
        values = tuple(cast(list[object], value))
    elif isinstance(value, frozenset):
        values = tuple(cast(frozenset[object], value))
    elif isinstance(value, set):
        values = tuple(cast(set[object], value))
    else:
        return None
    if not allow_empty and not values:
        return None
    strings: list[str] = []
    for item in values:
        if not isinstance(item, str) or item == "":
            return None
        strings.append(item)
    return tuple(strings)


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    normalized = float(value)
    if not isfinite(normalized):
        return None
    return normalized


def _is_int_value(value: object) -> TypeGuard[int]:
    return not isinstance(value, bool) and isinstance(value, int)


def _freeze_context(context: Mapping[str, object] | None) -> Mapping[str, FrozenPolicyValue]:
    if context is None:
        return MappingProxyType({})
    return _freeze_mapping(context)


def _freeze_mapping(values: Mapping[str, object]) -> Mapping[str, FrozenPolicyValue]:
    return _freeze_mapping_items(values.items())


def _freeze_mapping_items(
    items: Iterable[tuple[object, object]],
) -> Mapping[str, FrozenPolicyValue]:
    frozen_values: dict[str, FrozenPolicyValue] = {}
    for key, value in items:
        if not isinstance(key, str):
            raise ValueError("policy evidence keys must be strings")
        frozen_values[key] = _freeze_value(value)
    return MappingProxyType({key: frozen_values[key] for key in sorted(frozen_values)})


def _freeze_value(value: object) -> FrozenPolicyValue:
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
            raise ValueError("policy evidence numeric values must be finite")
        return value
    if isinstance(value, list):
        items = cast(list[object], value)
        return tuple(_freeze_value(item) for item in items)
    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(_freeze_value(item) for item in items)
    if isinstance(value, frozenset):
        items = cast(frozenset[object], value)
        return frozenset(_freeze_value(item) for item in items)
    if isinstance(value, set):
        items = cast(set[object], value)
        return frozenset(_freeze_value(item) for item in items)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _freeze_mapping_items(mapping.items())
    raise ValueError("policy evidence values must be primitive values or nested containers")


__all__ = ["evaluate_policy", "evaluate_policy_with_safety_case"]
