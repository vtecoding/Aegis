"""Tests for ADR-0014 policy identity checksums."""

from __future__ import annotations

import pytest

from aegis.contracts.policy import (
    Constraint,
    Policy,
    PolicyDefaultDecision,
    PolicyRule,
    policy_identity_checksum,
)
from aegis.governance.policy_identity import policy_identity_errors, recompute_policy_checksum


def _rule(max_mps: float = 1.0) -> PolicyRule:
    return PolicyRule(
        "rule-max-velocity",
        "locomotion.translation",
        (Constraint("max_velocity", {"max_mps": max_mps}),),
    )


def test_policy_checksum_binds_identity_and_rule_material() -> None:
    policy = Policy(
        "policy-identity-test",
        "v1",
        (_rule(),),
        policy_schema_version="policy-v1",
        policy_authority="safety-board",
        effective_from_ms=1000,
        metadata={"domain": "simulation"},
    )

    expected = policy_identity_checksum(
        policy_id="policy-identity-test",
        policy_version="v1",
        policy_schema_version="policy-v1",
        policy_authority="safety-board",
        effective_from_ms=1000,
        supersedes_policy_checksum=None,
        rules=policy.rules,
        capabilities=policy.capabilities,
        default_decision=PolicyDefaultDecision.BLOCK,
        metadata=policy.metadata,
    )

    assert policy.policy_checksum == expected
    assert policy.version == "v1"
    assert recompute_policy_checksum(policy) == expected
    assert policy_identity_errors(policy) == ()


def test_policy_checksum_changes_when_version_changes() -> None:
    first_policy = Policy("versioned-policy", "v1", (_rule(),))
    second_policy = Policy("versioned-policy", "v2", (_rule(),))

    assert first_policy.policy_checksum != second_policy.policy_checksum


def test_policy_rejects_forged_checksum() -> None:
    with pytest.raises(ValueError, match="policy_checksum must match"):
        Policy("forged-policy", "v1", (_rule(),), policy_checksum="0" * 64)
