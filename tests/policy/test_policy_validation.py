"""Validation helper and determinism tests for Policy-v1 contracts."""

import os

import pytest

from aegis.contracts.policy import (
    Constraint,
    Policy,
    PolicyDefaultDecision,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.policy.validation import validate_policy


def make_constraint() -> Constraint:
    """Return a valid constraint for policy validation tests."""
    return Constraint("max_velocity", {"meters_per_second": 0.5})


def make_rule(rule_id: str = "rule-1") -> PolicyRule:
    """Return a valid rule for policy validation tests."""
    return PolicyRule(rule_id, "locomotion.translation", [make_constraint()])


def make_policy() -> Policy:
    """Return a valid policy for validation helper tests."""
    return Policy("policy-1", "v1", [make_rule()])


def unchecked_policy(
    policy_id: str,
    version: str,
    rules: tuple[PolicyRule, ...],
    default_decision: object,
) -> Policy:
    """Build an invalid policy object to exercise validate_policy fail-closed checks."""
    policy = object.__new__(Policy)
    object.__setattr__(policy, "policy_id", policy_id)
    object.__setattr__(policy, "version", version)
    object.__setattr__(policy, "rules", rules)
    object.__setattr__(policy, "default_decision", default_decision)
    return policy


def unchecked_rule(rule_id: str, enabled: bool, constraints: tuple[Constraint, ...]) -> PolicyRule:
    """Build an invalid rule object to exercise validate_policy fail-closed checks."""
    rule = object.__new__(PolicyRule)
    object.__setattr__(rule, "rule_id", rule_id)
    object.__setattr__(rule, "capability", "locomotion.translation")
    object.__setattr__(rule, "constraints", constraints)
    object.__setattr__(rule, "description", "")
    object.__setattr__(rule, "enabled", enabled)
    return rule


def test_validate_policy_accepts_valid_policy() -> None:
    """validate_policy accepts a structurally valid Policy-v1 bundle."""
    assert validate_policy(make_policy()) is None


def test_validate_policy_rejects_empty_policy_id() -> None:
    """validate_policy fails closed on malformed policy IDs."""
    with pytest.raises(ValueError, match="policy_id"):
        validate_policy(unchecked_policy("", "v1", (make_rule(),), PolicyDefaultDecision.BLOCK))


def test_validate_policy_rejects_empty_version() -> None:
    """validate_policy fails closed on malformed policy versions."""
    with pytest.raises(ValueError, match="version"):
        validate_policy(
            unchecked_policy("policy-1", "", (make_rule(),), PolicyDefaultDecision.BLOCK)
        )


def test_validate_policy_rejects_invalid_default_decision() -> None:
    """validate_policy rejects impossible default allow states."""
    policy = unchecked_policy("policy-1", "v1", (make_rule(),), "ALLOW")

    with pytest.raises(ValueError, match="default_decision"):
        validate_policy(policy)


def test_validate_policy_rejects_duplicate_rule_ids() -> None:
    """validate_policy rejects duplicate rule IDs in unchecked policy objects."""
    rule = make_rule("rule-1")
    policy = unchecked_policy("policy-1", "v1", (rule, rule), PolicyDefaultDecision.BLOCK)

    with pytest.raises(ValueError, match="duplicate rule_id"):
        validate_policy(policy)


def test_validate_policy_rejects_enabled_rule_with_zero_constraints() -> None:
    """validate_policy rejects unchecked enabled metadata-only rules."""
    rule = unchecked_rule("rule-1", True, ())
    policy = unchecked_policy("policy-1", "v1", (rule,), PolicyDefaultDecision.BLOCK)

    with pytest.raises(ValueError, match="enabled rules"):
        validate_policy(policy)


def test_same_valid_input_produces_equal_policy_object() -> None:
    """Policy construction is deterministic for identical explicit inputs."""
    first = make_policy()
    second = make_policy()

    assert first == second


def test_same_invalid_input_raises_same_exception_type() -> None:
    """Invalid contract construction fails deterministically."""
    first_error_type: type[Exception]
    second_error_type: type[Exception]

    with pytest.raises(ValueError) as first_error:
        Policy("", "v1", [make_rule()])
    first_error_type = type(first_error.value)

    with pytest.raises(ValueError) as second_error:
        Policy("", "v1", [make_rule()])
    second_error_type = type(second_error.value)

    assert first_error_type is second_error_type


def test_world_snapshot_construction_uses_explicit_timestamps_only() -> None:
    """WorldSnapshotStub needs caller-supplied timestamps and generates none."""
    snapshot = WorldSnapshotStub("snapshot-1", 0, 1, "fixture", 1.0)

    assert snapshot.captured_at_ms == 0
    assert snapshot.expires_at_ms == 1


def test_policy_contracts_do_not_need_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment variables do not influence policy contract construction."""
    monkeypatch.setenv("AEGIS_POLICY_DEFAULT_DECISION", "ALLOW")

    policy = make_policy()

    assert os.environ["AEGIS_POLICY_DEFAULT_DECISION"] == "ALLOW"
    assert policy.default_decision is PolicyDefaultDecision.BLOCK
