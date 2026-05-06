"""Pure Policy-v1 structural validation helpers."""

from __future__ import annotations

from aegis.contracts.policy import Policy, PolicyDefaultDecision


def validate_policy(policy: Policy) -> None:
    """Validate a constructed Policy-v1 bundle.

    Policy construction enforces the same invariants. This helper exists as a
    pure explicit validation entry point for future evaluator code that receives
    a policy object and wants a no-return structural check.

    Args:
        policy: Policy-v1 bundle to validate.

    Raises:
        ValueError: If the policy violates Policy-v1 fail-closed invariants.
    """
    if policy.policy_id == "":
        raise ValueError("policy_id must be non-empty")
    if policy.version == "":
        raise ValueError("version must be non-empty")
    if policy.default_decision not in {
        PolicyDefaultDecision.BLOCK,
        PolicyDefaultDecision.REQUIRE_REVIEW,
    }:
        raise ValueError("default_decision must be BLOCK or REQUIRE_REVIEW")

    seen_rule_ids: set[str] = set()
    for rule in policy.rules:
        if rule.rule_id in seen_rule_ids:
            raise ValueError("rules must not contain duplicate rule_id values")
        seen_rule_ids.add(rule.rule_id)
        if rule.enabled and not rule.constraints:
            raise ValueError("enabled rules must contain at least one constraint")
