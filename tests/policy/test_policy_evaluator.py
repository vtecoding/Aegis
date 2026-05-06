"""Policy-v1 evaluator matching and decision aggregation tests."""

import pytest

from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyDefaultDecision,
    PolicyRule,
)
from aegis.policy.evaluator import evaluate_policy


def move_capability(velocity_mps: object = 0.2) -> Capability:
    """Return a locomotion capability with configurable velocity."""
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def max_velocity(max_mps: object = 0.5, *, required: bool = True) -> Constraint:
    """Return a max_velocity constraint."""
    return Constraint("max_velocity", {"max_mps": max_mps}, required=required)


def rule(
    rule_id: str,
    capability: str = "locomotion.translation",
    constraints: tuple[Constraint, ...] = (max_velocity(),),
    *,
    enabled: bool = True,
    description: str = "",
) -> PolicyRule:
    """Return a PolicyRule for evaluator tests."""
    return PolicyRule(rule_id, capability, constraints, description=description, enabled=enabled)


def policy(
    rules: tuple[PolicyRule, ...],
    default_decision: PolicyDefaultDecision = PolicyDefaultDecision.BLOCK,
) -> Policy:
    """Return a Policy-v1 bundle for evaluator tests."""
    return Policy("policy-1", "v1", rules, default_decision)


def test_exact_capability_match_allows_when_constraint_passes() -> None:
    """Exact string equality is enough for a matching rule to be evaluated."""
    result = evaluate_policy(policy=policy((rule("rule-1"),)), capability=move_capability())

    assert result.decision is PolicyDecision.ALLOW
    assert result.matched_rule_ids == ("rule-1",)
    assert result.passed_constraints == ("rule-1:0:max_velocity",)
    assert "POLICY_ALLOWED" in result.reasons


def test_prefix_match_does_not_match_specially() -> None:
    """Prefix-looking capability names are not wildcard matches."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", capability="locomotion.translation_fast"),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.matched_rule_ids == ()
    assert "POLICY_NO_MATCHING_RULE" in result.reasons


def test_wildcard_rule_text_is_rejected_at_contract_boundary() -> None:
    """Regex or wildcard capability matching is outside Policy-v1 Part 2."""
    with pytest.raises(ValueError, match="capability"):
        PolicyRule("rule-1", "locomotion.*", [max_velocity()])


def test_disabled_matching_rule_is_ignored() -> None:
    """Disabled rules do not participate in enforcement or allow decisions."""
    disabled_rule = rule(
        "disabled-allow-text",
        constraints=(),
        enabled=False,
        description="always allow this capability",
    )

    result = evaluate_policy(policy=policy((disabled_rule,)), capability=move_capability())

    assert result.decision is PolicyDecision.BLOCK
    assert result.matched_rule_ids == ()


def test_no_matching_enabled_rule_uses_default_block() -> None:
    """No-rule matches never imply ALLOW."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", capability="inspection.observe"),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.reasons == ("POLICY_NO_MATCHING_RULE", "POLICY_DEFAULT_BLOCK")


def test_no_matching_enabled_rule_uses_default_require_review() -> None:
    """Default REQUIRE_REVIEW remains fail-closed for no-match paths."""
    result = evaluate_policy(
        policy=policy(
            (rule("rule-1", capability="inspection.observe"),),
            PolicyDefaultDecision.REQUIRE_REVIEW,
        ),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.REQUIRE_REVIEW
    assert result.reasons == ("POLICY_NO_MATCHING_RULE", "POLICY_DEFAULT_REQUIRE_REVIEW")


def test_multiple_matching_rules_all_evaluated_and_strictest_failure_blocks() -> None:
    """One passing matching rule cannot bypass another stricter matching rule."""
    result = evaluate_policy(
        policy=policy(
            (
                rule("rule-pass", constraints=(max_velocity(1.0),)),
                rule("rule-fail", constraints=(max_velocity(0.1),)),
            )
        ),
        capability=move_capability(0.2),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.matched_rule_ids == ("rule-pass", "rule-fail")
    assert result.passed_constraints == ("rule-pass:0:max_velocity",)
    assert result.failed_constraints == ("rule-fail:0:max_velocity",)
    assert "POLICY_REQUIRED_CONSTRAINT_FAILED" in result.reasons


def test_optional_failure_only_requires_review_and_remains_visible() -> None:
    """Optional failures are not silent; they produce REQUIRE_REVIEW."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", constraints=(max_velocity(0.1, required=False),)),)),
        capability=move_capability(0.2),
    )

    assert result.decision is PolicyDecision.REQUIRE_REVIEW
    assert result.failed_constraints == ("rule-1:0:max_velocity",)
    assert "POLICY_OPTIONAL_CONSTRAINT_FAILED" in result.reasons


def test_required_failure_dominates_optional_failure() -> None:
    """BLOCK takes precedence when required and optional constraints both fail."""
    result = evaluate_policy(
        policy=policy(
            (
                rule(
                    "rule-1",
                    constraints=(max_velocity(0.1), max_velocity(0.05, required=False)),
                ),
            )
        ),
        capability=move_capability(0.2),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.failed_constraints == ("rule-1:0:max_velocity", "rule-1:1:max_velocity")


def test_unknown_required_constraint_blocks() -> None:
    """Unknown constraint types fail closed as required constraints."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", constraints=(Constraint("allow_all"),)),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.failed_constraints == ("rule-1:0:allow_all",)
    assert "POLICY_UNKNOWN_CONSTRAINT_TYPE" in result.reasons


def test_unknown_optional_constraint_requires_review() -> None:
    """Unknown optional constraints do not allow and remain visible."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", constraints=(Constraint("allow_all", required=False),)),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.REQUIRE_REVIEW
    assert result.failed_constraints == ("rule-1:0:allow_all",)
    assert "POLICY_UNKNOWN_CONSTRAINT_TYPE" in result.reasons


def test_emergency_stop_override_allows_only_explicit_emergency_stop_capability() -> None:
    """The emergency override is exact capability admission, not a wildcard bypass."""
    result = evaluate_policy(
        policy=policy(
            (
                rule(
                    "emergency-stop",
                    capability="system.emergency_stop",
                    constraints=(Constraint("emergency_stop_override"),),
                ),
            )
        ),
        capability=Capability("system.emergency_stop"),
    )

    assert result.decision is PolicyDecision.ALLOW
    assert result.passed_constraints == ("emergency-stop:0:emergency_stop_override",)
    assert "EMERGENCY_STOP_ALLOWED" in result.reasons


def test_emergency_stop_override_does_not_allow_movement_capability() -> None:
    """Emergency override constraints fail closed for non-emergency capabilities."""
    result = evaluate_policy(
        policy=policy((rule("rule-1", constraints=(Constraint("emergency_stop_override"),)),)),
        capability=move_capability(),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert "EMERGENCY_STOP_CONSTRAINT_MISMATCH" in result.reasons


def test_emergency_stop_override_does_not_bypass_unrelated_required_failure() -> None:
    """An emergency stop pass cannot hide another required failure in the same rule."""
    result = evaluate_policy(
        policy=policy(
            (
                rule(
                    "emergency-stop",
                    capability="system.emergency_stop",
                    constraints=(Constraint("emergency_stop_override"), max_velocity()),
                ),
            )
        ),
        capability=Capability("system.emergency_stop"),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.passed_constraints == ("emergency-stop:0:emergency_stop_override",)
    assert result.failed_constraints == ("emergency-stop:1:max_velocity",)
