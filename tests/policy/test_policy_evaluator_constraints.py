"""Policy-v1 built-in constraint evaluator tests."""

import pytest

from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.policy.aegis_evaluator import evaluate_policy


def snapshot(
    *,
    captured_at_ms: int = 100,
    expires_at_ms: int = 200,
    confidence: float = 0.9,
    facts: dict[str, object] | None = None,
) -> WorldSnapshotStub:
    """Return a deterministic WorldSnapshotStub for constraint tests."""
    return WorldSnapshotStub(
        "snapshot-1",
        captured_at_ms,
        expires_at_ms,
        "fixture",
        confidence,
        facts or {},
    )


def move_capability(parameters: dict[str, object] | None = None) -> Capability:
    """Return a locomotion capability for constraint tests."""
    return Capability(
        "locomotion.translation",
        parameters=parameters if parameters is not None else {"velocity_mps": 0.2},
    )


def evaluate_constraint(
    constraint: Constraint,
    *,
    capability: Capability | None = None,
    world_snapshot: WorldSnapshotStub | None = None,
    context: dict[str, object] | None = None,
) -> tuple[PolicyDecision, tuple[str, ...], tuple[str, ...]]:
    """Evaluate a single constraint and return decision plus trace fields."""
    result = evaluate_policy(
        policy=Policy(
            "policy-1",
            "v1",
            [PolicyRule("rule-1", "locomotion.translation", [constraint])],
        ),
        capability=capability or move_capability(),
        world_snapshot=world_snapshot,
        context=context,
    )
    return result.decision, result.failed_constraints, result.reasons


def test_requires_world_snapshot_passes_when_snapshot_exists() -> None:
    """requires_world_snapshot passes with supplied immutable snapshot evidence."""
    decision, failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_world_snapshot"),
        world_snapshot=snapshot(),
    )

    assert decision is PolicyDecision.ALLOW
    assert failed_constraints == ()
    assert "WORLD_SNAPSHOT_PRESENT" in reasons


def test_requires_world_snapshot_fails_when_snapshot_missing() -> None:
    """requires_world_snapshot blocks missing world evidence."""
    decision, failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_world_snapshot")
    )

    assert decision is PolicyDecision.BLOCK
    assert failed_constraints == ("rule-1:0:requires_world_snapshot",)
    assert "WORLD_SNAPSHOT_REQUIRED" in reasons


@pytest.mark.parametrize(
    ("requested_at_ms", "expected_decision", "expected_reason"),
    [
        (100, PolicyDecision.ALLOW, "WORLD_SNAPSHOT_FRESH"),
        (150, PolicyDecision.ALLOW, "WORLD_SNAPSHOT_FRESH"),
        (200, PolicyDecision.ALLOW, "WORLD_SNAPSHOT_FRESH"),
        (99, PolicyDecision.BLOCK, "WORLD_SNAPSHOT_NOT_YET_VALID"),
        (201, PolicyDecision.BLOCK, "WORLD_SNAPSHOT_EXPIRED"),
    ],
)
def test_snapshot_freshness_time_boundaries(
    requested_at_ms: int,
    expected_decision: PolicyDecision,
    expected_reason: str,
) -> None:
    """Snapshot freshness uses caller-supplied request time only."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("snapshot_freshness", {"requested_at_ms": requested_at_ms}),
        world_snapshot=snapshot(),
    )

    assert decision is expected_decision
    assert expected_reason in reasons


def test_snapshot_freshness_can_read_request_time_from_context() -> None:
    """Context request time is deterministic caller-supplied data."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("snapshot_freshness"),
        world_snapshot=snapshot(),
        context={"requested_at_ms": 150},
    )

    assert decision is PolicyDecision.ALLOW
    assert "WORLD_SNAPSHOT_FRESH" in reasons


def test_snapshot_freshness_fails_when_time_or_snapshot_missing() -> None:
    """Missing snapshot or request time fails closed."""
    missing_time = evaluate_constraint(Constraint("snapshot_freshness"), world_snapshot=snapshot())
    missing_snapshot = evaluate_constraint(Constraint("snapshot_freshness"))

    assert missing_time[0] is PolicyDecision.BLOCK
    assert "REQUEST_TIME_REQUIRED" in missing_time[2]
    assert missing_snapshot[0] is PolicyDecision.BLOCK
    assert "WORLD_SNAPSHOT_REQUIRED" in missing_snapshot[2]


@pytest.mark.parametrize(
    ("confidence", "threshold", "expected_decision"),
    [
        (0.8, 0.8, PolicyDecision.ALLOW),
        (0.9, 0.8, PolicyDecision.ALLOW),
        (0.7, 0.8, PolicyDecision.BLOCK),
    ],
)
def test_min_sensor_confidence_boundaries(
    confidence: float,
    threshold: float,
    expected_decision: PolicyDecision,
) -> None:
    """min_sensor_confidence passes at or above threshold only."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("min_sensor_confidence", {"min_confidence": threshold}),
        world_snapshot=snapshot(confidence=confidence),
    )

    assert decision is expected_decision
    if expected_decision is PolicyDecision.BLOCK:
        assert "WORLD_SNAPSHOT_CONFIDENCE_TOO_LOW" in reasons


def test_min_sensor_confidence_fails_missing_or_invalid_threshold() -> None:
    """Missing and malformed confidence thresholds fail closed."""
    missing = evaluate_constraint(Constraint("min_sensor_confidence"), world_snapshot=snapshot())
    invalid = evaluate_constraint(
        Constraint("min_sensor_confidence", {"min_confidence": 1.1}),
        world_snapshot=snapshot(),
    )

    assert missing[0] is PolicyDecision.BLOCK
    assert "MIN_CONFIDENCE_REQUIRED" in missing[2]
    assert invalid[0] is PolicyDecision.BLOCK
    assert "MIN_CONFIDENCE_INVALID" in invalid[2]


def test_min_sensor_confidence_fails_when_snapshot_missing() -> None:
    """min_sensor_confidence requires supplied snapshot evidence."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("min_sensor_confidence", {"min_confidence": 0.8})
    )

    assert decision is PolicyDecision.BLOCK
    assert "WORLD_SNAPSHOT_REQUIRED" in reasons


@pytest.mark.parametrize(
    ("velocity_mps", "max_mps", "expected_decision", "expected_reason"),
    [
        (0.2, 0.5, PolicyDecision.ALLOW, "VELOCITY_WITHIN_LIMIT"),
        (0.5, 0.5, PolicyDecision.ALLOW, "VELOCITY_WITHIN_LIMIT"),
        (0.6, 0.5, PolicyDecision.BLOCK, "VELOCITY_LIMIT_EXCEEDED"),
        (-0.1, 0.5, PolicyDecision.BLOCK, "VELOCITY_INVALID"),
        ("fast", 0.5, PolicyDecision.BLOCK, "VELOCITY_INVALID"),
        (0.2, "fast", PolicyDecision.BLOCK, "MAX_VELOCITY_INVALID"),
    ],
)
def test_max_velocity_boundaries(
    velocity_mps: object,
    max_mps: object,
    expected_decision: PolicyDecision,
    expected_reason: str,
) -> None:
    """max_velocity evaluates finite non-negative numeric values only."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("max_velocity", {"max_mps": max_mps}),
        capability=move_capability({"velocity_mps": velocity_mps}),
    )

    assert decision is expected_decision
    assert expected_reason in reasons


def test_max_velocity_fails_when_velocity_or_threshold_missing() -> None:
    """Missing velocity or threshold evidence fails closed."""
    missing_velocity = evaluate_constraint(
        Constraint("max_velocity", {"max_mps": 0.5}),
        capability=move_capability({}),
    )
    missing_threshold = evaluate_constraint(Constraint("max_velocity"))

    assert missing_velocity[0] is PolicyDecision.BLOCK
    assert "VELOCITY_REQUIRED" in missing_velocity[2]
    assert missing_threshold[0] is PolicyDecision.BLOCK
    assert "MAX_VELOCITY_REQUIRED" in missing_threshold[2]


def test_deny_zone_passes_when_target_zone_not_denied() -> None:
    """deny_zone passes when target evidence excludes all denied zones."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("deny_zone", {"zone_ids": ("restricted_lab",)}),
        world_snapshot=snapshot(facts={"target_zone_id": "open_lab"}),
    )

    assert decision is PolicyDecision.ALLOW
    assert "TARGET_ZONE_ALLOWED" in reasons


def test_deny_zone_blocks_denied_target_or_missing_evidence() -> None:
    """deny_zone fails closed for denied, missing, or malformed evidence."""
    denied = evaluate_constraint(
        Constraint("deny_zone", {"zone_ids": ("restricted_lab",)}),
        world_snapshot=snapshot(facts={"target_zone_id": "restricted_lab"}),
    )
    missing_zones = evaluate_constraint(Constraint("deny_zone"), world_snapshot=snapshot())
    missing_target = evaluate_constraint(
        Constraint("deny_zone", {"zone_ids": ("restricted_lab",)}),
        world_snapshot=snapshot(),
    )
    missing_snapshot = evaluate_constraint(Constraint("deny_zone", {"zone_ids": ("a",)}))

    assert denied[0] is PolicyDecision.BLOCK
    assert "TARGET_ZONE_DENIED" in denied[2]
    assert "DENIED_ZONES_REQUIRED" in missing_zones[2]
    assert "TARGET_ZONE_EVIDENCE_REQUIRED" in missing_target[2]
    assert "WORLD_SNAPSHOT_REQUIRED" in missing_snapshot[2]


def test_deny_zone_reads_zones_containing_target() -> None:
    """deny_zone can evaluate tuple-valued target-zone membership evidence."""
    result = evaluate_constraint(
        Constraint("deny_zone", {"zone_ids": ("restricted_lab",)}),
        world_snapshot=snapshot(facts={"zones_containing_target": ("open_lab",)}),
    )

    assert result[0] is PolicyDecision.ALLOW


@pytest.mark.parametrize(
    ("distance_m", "minimum_m", "expected_decision", "expected_reason"),
    [
        (2.0, 1.5, PolicyDecision.ALLOW, "HUMAN_DISTANCE_ACCEPTED"),
        (1.5, 1.5, PolicyDecision.ALLOW, "HUMAN_DISTANCE_ACCEPTED"),
        (1.4, 1.5, PolicyDecision.BLOCK, "HUMAN_TOO_CLOSE"),
        (-1.0, 1.5, PolicyDecision.BLOCK, "HUMAN_DISTANCE_INVALID"),
        ("near", 1.5, PolicyDecision.BLOCK, "HUMAN_DISTANCE_INVALID"),
        (2.0, -1.0, PolicyDecision.BLOCK, "MIN_HUMAN_DISTANCE_INVALID"),
    ],
)
def test_human_proximity_limit_boundaries(
    distance_m: object,
    minimum_m: object,
    expected_decision: PolicyDecision,
    expected_reason: str,
) -> None:
    """human_proximity_limit requires finite distances above the minimum."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("human_proximity_limit", {"min_distance_m": minimum_m}),
        world_snapshot=snapshot(facts={"nearest_human_distance_m": distance_m}),
    )

    assert decision is expected_decision
    assert expected_reason in reasons


def test_human_proximity_limit_fails_when_distance_or_threshold_missing() -> None:
    """Missing human distance or minimum threshold fails closed."""
    missing_distance = evaluate_constraint(
        Constraint("human_proximity_limit", {"min_distance_m": 1.5}),
        world_snapshot=snapshot(),
    )
    missing_threshold = evaluate_constraint(
        Constraint("human_proximity_limit"),
        world_snapshot=snapshot(facts={"nearest_human_distance_m": 2.0}),
    )

    assert "HUMAN_DISTANCE_REQUIRED" in missing_distance[2]
    assert "MIN_HUMAN_DISTANCE_REQUIRED" in missing_threshold[2]


def test_human_proximity_limit_fails_when_snapshot_missing() -> None:
    """human_proximity_limit requires supplied snapshot evidence."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("human_proximity_limit", {"min_distance_m": 1.5})
    )

    assert decision is PolicyDecision.BLOCK
    assert "WORLD_SNAPSHOT_REQUIRED" in reasons


def test_requires_authorisation_passes_on_exact_authorisation() -> None:
    """requires_authorisation uses exact string membership only."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": "operator"}),
        context={"authorisations": ("operator",)},
    )

    assert decision is PolicyDecision.ALLOW
    assert "AUTHORISATION_PRESENT" in reasons


def test_requires_authorisation_fails_missing_required_or_context() -> None:
    """Missing required authorisation or context authorisations fails closed."""
    missing_required = evaluate_constraint(Constraint("requires_authorisation"))
    missing_context = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": "operator"})
    )

    assert "AUTHORISATION_REQUIRED" in missing_required[2]
    assert "AUTHORISATIONS_CONTEXT_REQUIRED" in missing_context[2]


def test_requires_authorisation_rejects_substring_and_non_string_values() -> None:
    """Substring matches and non-string authorisation values do not pass."""
    substring = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": "admin"}),
        context={"authorisations": ("superadmin-user",)},
    )
    invalid_value = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": "admin"}),
        context={"authorisations": (1,)},
    )

    assert substring[0] is PolicyDecision.BLOCK
    assert "AUTHORISATION_MISSING" in substring[2]
    assert invalid_value[0] is PolicyDecision.BLOCK
    assert "AUTHORISATION_INVALID" in invalid_value[2]


def test_requires_authorisation_rejects_non_string_required_authorisation() -> None:
    """The required authorisation parameter itself must be a string."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": 1}),
        context={"authorisations": ("operator",)},
    )

    assert decision is PolicyDecision.BLOCK
    assert "AUTHORISATION_INVALID" in reasons


def test_requires_authorisation_accepts_frozenset_context_values() -> None:
    """Frozen context authorisation collections are deterministic inputs."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_authorisation", {"authorisation": "operator"}),
        context={"authorisations": frozenset({"operator"})},
    )

    assert decision is PolicyDecision.ALLOW
    assert "AUTHORISATION_PRESENT" in reasons


@pytest.mark.parametrize(
    ("dual_authorised", "expected_reason"),
    [
        (False, "DUAL_AUTHORISATION_MISSING"),
        ("true", "DUAL_AUTHORISATION_INVALID"),
        (1, "DUAL_AUTHORISATION_INVALID"),
    ],
)
def test_requires_dual_authorisation_rejects_falsey_or_truthy_non_bool(
    dual_authorised: object,
    expected_reason: str,
) -> None:
    """Only boolean True passes requires_dual_authorisation."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_dual_authorisation", {"required": True}),
        context={"dual_authorised": dual_authorised},
    )

    assert decision is PolicyDecision.BLOCK
    assert expected_reason in reasons


def test_requires_dual_authorisation_passes_only_boolean_true_and_fails_missing() -> None:
    """Dual authorisation requires exact bool True in context."""
    passed = evaluate_constraint(
        Constraint("requires_dual_authorisation", {"required": True}),
        context={"dual_authorised": True},
    )
    missing = evaluate_constraint(Constraint("requires_dual_authorisation", {"required": True}))

    assert passed[0] is PolicyDecision.ALLOW
    assert "DUAL_AUTHORISATION_PRESENT" in passed[2]
    assert missing[0] is PolicyDecision.BLOCK
    assert "DUAL_AUTHORISATION_MISSING" in missing[2]


def test_requires_dual_authorisation_fails_when_constraint_parameter_missing() -> None:
    """The dual-authorisation constraint must explicitly require dual approval."""
    decision, _failed_constraints, reasons = evaluate_constraint(
        Constraint("requires_dual_authorisation"),
        context={"dual_authorised": True},
    )

    assert decision is PolicyDecision.BLOCK
    assert "DUAL_AUTHORISATION_REQUIRED" in reasons
