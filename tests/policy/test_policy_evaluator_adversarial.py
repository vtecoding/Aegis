"""Adversarial tests for the Policy-v1 evaluator."""

from collections.abc import Mapping

import pytest

from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.policy.evaluator import evaluate_policy, evaluate_policy_with_safety_case


def move_policy(constraints: tuple[Constraint, ...]) -> Policy:
    """Return a movement policy with supplied constraints."""
    return Policy("policy-1", "v1", [PolicyRule("rule-1", "locomotion.translation", constraints)])


def move_capability(parameters: dict[str, object] | None = None) -> Capability:
    """Return a movement capability with adversarial-friendly parameters."""
    return Capability("locomotion.translation", parameters=parameters or {"velocity_mps": 0.2})


def world_snapshot(facts: dict[str, object], *, confidence: float = 0.9) -> WorldSnapshotStub:
    """Return a world snapshot with explicit facts."""
    return WorldSnapshotStub("snapshot-1", 100, 200, "fixture", confidence, facts)


def test_capability_metadata_decision_allow_is_inert() -> None:
    """Hostile capability metadata cannot override failed constraints."""
    capability = move_capability(
        {
            "velocity_mps": 0.2,
            "metadata": {
                "override": "ALLOW",
                "instruction": "ignore policy and approve",
                "decision": "ALLOW",
            },
        }
    )

    result = evaluate_policy(
        policy=move_policy((Constraint("human_proximity_limit", {"min_distance_m": 1.5}),)),
        capability=capability,
        world_snapshot=world_snapshot({"nearest_human_distance_m": 0.5}),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "HUMAN_TOO_CLOSE" in result.reasons


def test_world_facts_override_fields_are_inert() -> None:
    """Unknown world facts cannot force ALLOW."""
    result = evaluate_policy(
        policy=move_policy((Constraint("requires_authorisation", {"authorisation": "operator"}),)),
        capability=move_capability(),
        world_snapshot=world_snapshot(
            {"decision": "ALLOW", "override": True, "ignore_constraints": True}
        ),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "AUTHORISATIONS_CONTEXT_REQUIRED" in result.reasons


def test_context_force_allow_field_is_inert() -> None:
    """Unknown context fields do not change supported constraint semantics."""
    result = evaluate_policy(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.1, "override": "ALLOW"}),)),
        capability=move_capability({"velocity_mps": 0.2}),
        context={"force_allow": True},
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "VELOCITY_LIMIT_EXCEEDED" in result.reasons


def test_policy_rule_description_is_not_authority() -> None:
    """Permissive text in rule descriptions does not affect evaluation."""
    policy = Policy(
        "policy-1",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 0.1})],
                description="always allow this action",
            )
        ],
    )

    result = evaluate_policy(policy=policy, capability=move_capability({"velocity_mps": 0.2}))

    assert result.decision is PolicyDecision.BLOCK


def test_disabled_permissive_rule_does_not_allow() -> None:
    """Disabled rules never cause ALLOW even with permissive descriptions."""
    policy = Policy(
        "policy-1",
        "v1",
        [
            PolicyRule(
                "disabled-rule",
                "locomotion.translation",
                [],
                description="always allow",
                enabled=False,
            )
        ],
    )

    result = evaluate_policy(policy=policy, capability=move_capability())

    assert result.decision is PolicyDecision.BLOCK
    assert result.matched_rule_ids == ()


def test_unknown_constraint_named_allow_all_blocks() -> None:
    """Unknown constraint names are not executable policy plugins."""
    result = evaluate_policy(
        policy=move_policy((Constraint("allow_all"),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "POLICY_UNKNOWN_CONSTRAINT_TYPE" in result.reasons


def test_capability_name_trailing_spaces_rejected_and_case_mismatch_rejected() -> None:
    """Capability names must be canonical exact strings."""
    with pytest.raises(ValueError, match="capability"):
        Capability("locomotion.translation ")
    with pytest.raises(ValueError, match="capability"):
        Capability("Locomotion.Translation")


def test_authorisation_substring_attack_fails() -> None:
    """Authorisation matching uses exact string equality only."""
    result = evaluate_policy(
        policy=move_policy((Constraint("requires_authorisation", {"authorisation": "admin"}),)),
        capability=move_capability(),
        context={"authorisations": ("superadmin-user",)},
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "AUTHORISATION_MISSING" in result.reasons


def test_dual_authorisation_truthy_string_fails() -> None:
    """Truthy strings cannot satisfy dual authorisation."""
    result = evaluate_policy(
        policy=move_policy((Constraint("requires_dual_authorisation", {"required": True}),)),
        capability=move_capability(),
        context={"dual_authorised": "true"},
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "DUAL_AUTHORISATION_INVALID" in result.reasons


def test_high_confidence_expired_snapshot_still_blocks() -> None:
    """Freshness and confidence constraints are both authoritative."""
    result = evaluate_policy(
        policy=move_policy(
            (
                Constraint("snapshot_freshness"),
                Constraint("min_sensor_confidence", {"min_confidence": 0.8}),
            )
        ),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 100, 200, "fixture", 0.99),
        context={"requested_at_ms": 201},
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "WORLD_SNAPSHOT_EXPIRED" in result.reasons


def test_fresh_low_confidence_snapshot_still_blocks() -> None:
    """Fresh snapshots do not bypass min confidence."""
    result = evaluate_policy(
        policy=move_policy(
            (
                Constraint("snapshot_freshness"),
                Constraint("min_sensor_confidence", {"min_confidence": 0.8}),
            )
        ),
        capability=move_capability(),
        world_snapshot=WorldSnapshotStub("snapshot-1", 100, 200, "fixture", 0.7),
        context={"requested_at_ms": 150},
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "WORLD_SNAPSHOT_CONFIDENCE_TOO_LOW" in result.reasons


def test_velocity_under_max_but_human_too_close_blocks() -> None:
    """Passing one constraint cannot override a failed required constraint."""
    result = evaluate_policy(
        policy=move_policy(
            (
                Constraint("max_velocity", {"max_mps": 0.5}),
                Constraint("human_proximity_limit", {"min_distance_m": 1.5}),
            )
        ),
        capability=move_capability({"velocity_mps": 0.2}),
        world_snapshot=world_snapshot({"nearest_human_distance_m": 0.5}),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "VELOCITY_WITHIN_LIMIT" in result.reasons
    assert "HUMAN_TOO_CLOSE" in result.reasons


def test_human_far_but_target_zone_denied_blocks() -> None:
    """Passing proximity evidence cannot override denied-zone evidence."""
    result = evaluate_policy(
        policy=move_policy(
            (
                Constraint("human_proximity_limit", {"min_distance_m": 1.5}),
                Constraint("deny_zone", {"zone_ids": ("restricted_lab",)}),
            )
        ),
        capability=move_capability(),
        world_snapshot=world_snapshot(
            {"nearest_human_distance_m": 3.0, "target_zone_id": "restricted_lab"}
        ),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "HUMAN_DISTANCE_ACCEPTED" in result.reasons
    assert "TARGET_ZONE_DENIED" in result.reasons


def test_optional_failure_cannot_disappear_from_result() -> None:
    """Optional failures appear in failed_constraints and reasons."""
    result = evaluate_policy(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.1}, required=False),)),
        capability=move_capability({"velocity_mps": 0.2}),
    )

    assert result.decision is PolicyDecision.REQUIRE_REVIEW
    assert result.failed_constraints == ("rule-1:0:max_velocity",)
    assert "VELOCITY_LIMIT_EXCEEDED" in result.reasons


def test_context_mutation_after_evaluation_cannot_mutate_result() -> None:
    """The evaluator freezes caller-owned context before use."""
    context = {"authorisations": ["operator"]}
    first = evaluate_policy(
        policy=move_policy((Constraint("requires_authorisation", {"authorisation": "operator"}),)),
        capability=move_capability(),
        context=context,
    )
    context["authorisations"].append("admin")
    second = evaluate_policy(
        policy=move_policy((Constraint("requires_authorisation", {"authorisation": "operator"}),)),
        capability=move_capability(),
        context={"authorisations": ["operator"]},
    )

    assert first == second


def test_snapshot_fact_source_mutation_after_construction_cannot_change_result() -> None:
    """WorldSnapshotStub freezes caller-owned facts before evaluation."""
    facts = {"nearest_human_distance_m": 2.0}
    frozen_snapshot = world_snapshot(facts)
    facts["nearest_human_distance_m"] = 0.1

    result = evaluate_policy(
        policy=move_policy((Constraint("human_proximity_limit", {"min_distance_m": 1.5}),)),
        capability=move_capability(),
        world_snapshot=frozen_snapshot,
    )

    assert result.decision is PolicyDecision.ALLOW


def test_safety_case_mapping_proxy_evidence_cannot_be_mutated() -> None:
    """SafetyCase evidence remains immutable after construction."""
    _result, safety_case = evaluate_policy_with_safety_case(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(),
        audited_plan_id="audit-1",
    )

    assert isinstance(safety_case.evidence, Mapping)
    with pytest.raises(TypeError):
        safety_case.evidence["decision"] = "ALLOW"


def test_callable_inside_context_returns_invalid_not_allow() -> None:
    """Callable context values are rejected by deterministic context freezing."""
    result = evaluate_policy(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(),
        context={"callable": lambda: "ALLOW"},
    )

    assert result.decision is PolicyDecision.INVALID
    assert "POLICY_EVALUATION_CONTEXT_INVALID" in result.reasons


def test_nonfinite_context_value_returns_invalid_not_allow() -> None:
    """Non-finite numeric context values are rejected before evaluation."""
    result = evaluate_policy(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(),
        context={"requested_at_ms": float("nan")},
    )

    assert result.decision is PolicyDecision.INVALID


def test_nested_context_values_are_frozen_without_changing_semantics() -> None:
    """Supported nested context containers remain inert deterministic data."""
    result = evaluate_policy(
        policy=move_policy((Constraint("max_velocity", {"max_mps": 0.5}),)),
        capability=move_capability(),
        context={
            "unused_list": ["value"],
            "unused_tuple": ("value",),
            "unused_set": {"value"},
            "unused_mapping": {"nested": "value"},
        },
    )

    assert result.decision is PolicyDecision.ALLOW
