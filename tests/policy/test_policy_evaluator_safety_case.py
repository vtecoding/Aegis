"""Policy-v1 SafetyCase builder tests."""

from collections.abc import Mapping
from types import MappingProxyType

import pytest

from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.policy.aegis_evaluator import evaluate_policy, evaluate_policy_with_safety_case
from aegis.policy.aegis_safety_case import build_safety_case, canonicalise_for_hash


def policy() -> Policy:
    """Return a passing Policy-v1 bundle for SafetyCase tests."""
    return Policy(
        "policy-1",
        "v1",
        [
            PolicyRule(
                "rule-1", "locomotion.translation", [Constraint("max_velocity", {"max_mps": 0.5})]
            )
        ],
    )


def capability(velocity_mps: object = 0.2) -> Capability:
    """Return a test capability."""
    return Capability("locomotion.translation", parameters={"velocity_mps": velocity_mps})


def snapshot(snapshot_id: str = "snapshot-1") -> WorldSnapshotStub:
    """Return a test world snapshot."""
    return WorldSnapshotStub(snapshot_id, 100, 200, "fixture", 0.9)


def test_safety_case_created_for_allow_with_evaluator_evidence() -> None:
    """Combined helper builds explanatory evidence for ALLOW decisions."""
    result, safety_case = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
        world_snapshot=snapshot(),
    )

    assert result.decision is PolicyDecision.ALLOW
    assert safety_case.policy_result == result
    assert safety_case.audited_plan_id == "audit-1"
    assert safety_case.evidence["capability_name"] == "locomotion.translation"
    assert safety_case.evidence["world_snapshot_id"] == "snapshot-1"


def test_safety_case_created_for_block() -> None:
    """SafetyCase can explain fail-closed policy results."""
    result = evaluate_policy(policy=policy(), capability=capability(1.0))
    safety_case = build_safety_case(policy_result=result, audited_plan_id="audit-1")

    assert result.decision is PolicyDecision.BLOCK
    assert safety_case.policy_result == result
    assert safety_case.evidence["decision"] == "BLOCK"


def test_safety_case_evidence_is_immutable() -> None:
    """SafetyCase evidence is recursively frozen by the contract boundary."""
    _result, safety_case = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
    )

    with pytest.raises(TypeError):
        safety_case.evidence["decision"] = "BLOCK"

    constraint_evaluations = safety_case.evidence["constraint_evaluations"]
    assert isinstance(constraint_evaluations, tuple)
    first_evaluation = constraint_evaluations[0]
    assert isinstance(first_evaluation, Mapping)
    with pytest.raises(TypeError):
        first_evaluation["passed"] = False


def test_safety_case_id_is_deterministic_for_same_inputs() -> None:
    """SafetyCase IDs are stable for identical explicit inputs."""
    first = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
        world_snapshot=snapshot(),
    )[1]
    second = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
        world_snapshot=snapshot(),
    )[1]

    assert first.safety_case_id == second.safety_case_id


def test_safety_case_id_changes_when_policy_result_changes() -> None:
    """Changing the policy decision changes the deterministic SafetyCase ID."""
    allow_result = evaluate_policy(policy=policy(), capability=capability())
    block_result = evaluate_policy(policy=policy(), capability=capability(1.0))

    allow_case = build_safety_case(
        policy_result=allow_result,
        audited_plan_id="audit-1",
        evidence={"capability_name": "locomotion.translation"},
    )
    block_case = build_safety_case(policy_result=block_result, audited_plan_id="audit-1")

    assert allow_case.safety_case_id != block_case.safety_case_id


def test_safety_case_id_changes_when_audit_or_snapshot_changes() -> None:
    """Audited plan ID and world snapshot ID are bound into the case hash."""
    first = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
        world_snapshot=snapshot("ws-1"),
    )[1]
    different_audit = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-2",
        world_snapshot=snapshot("ws-1"),
    )[1]
    different_snapshot = evaluate_policy_with_safety_case(
        policy=policy(),
        capability=capability(),
        audited_plan_id="audit-1",
        world_snapshot=snapshot("ws-2"),
    )[1]

    assert first.safety_case_id != different_audit.safety_case_id
    assert first.safety_case_id != different_snapshot.safety_case_id


def test_safety_case_rejects_empty_audited_plan_id() -> None:
    """SafetyCase construction binds to a non-empty audited plan ID."""
    result = evaluate_policy(policy=policy(), capability=capability(1.0))

    with pytest.raises(ValueError, match="audited_plan_id"):
        build_safety_case(policy_result=result, audited_plan_id=" ")


def test_allow_safety_case_requires_meaningful_passed_constraint_evidence() -> None:
    """ALLOW safety cases reject results with no passed constraint evidence."""
    result = PolicyEvaluationResult(PolicyDecision.ALLOW, "policy-1", ["rule-1"], [], [], [])

    with pytest.raises(ValueError, match="passed constraint"):
        build_safety_case(
            policy_result=result,
            audited_plan_id="audit-1",
            evidence={"capability_name": "locomotion.translation"},
        )


def test_constraint_evaluations_appear_in_safety_case_evidence() -> None:
    """Combined helper includes per-constraint structured evidence."""
    _result, safety_case = evaluate_policy_with_safety_case(
        policy=policy(), capability=capability(), audited_plan_id="audit-1"
    )

    constraint_evaluations = safety_case.evidence["constraint_evaluations"]
    assert isinstance(constraint_evaluations, tuple)
    first_evaluation = constraint_evaluations[0]
    assert isinstance(first_evaluation, Mapping)
    assert first_evaluation["constraint_id"] == "rule-1:0:max_velocity"
    assert first_evaluation["reason"] == "VELOCITY_WITHIN_LIMIT"


def test_canonicalise_for_hash_is_key_order_stable() -> None:
    """Equivalent evidence with different dict insertion order hashes the same."""
    first = canonicalise_for_hash({"b": 2, "a": {"y": 2, "x": 1}})
    second = canonicalise_for_hash({"a": {"x": 1, "y": 2}, "b": 2})

    assert first == second


def test_canonicalise_for_hash_handles_mapping_proxy_and_rejects_unsupported_object() -> None:
    """Frozen mappings are canonical, but custom objects are rejected."""
    assert canonicalise_for_hash(MappingProxyType({"value": 1})) == {"value": 1}

    with pytest.raises(ValueError, match="hash evidence"):
        canonicalise_for_hash(object())


def test_canonicalise_for_hash_handles_policy_contract_objects() -> None:
    """Policy-v1 contract objects canonicalise through explicit fields."""
    capability_value = canonicalise_for_hash(Capability("locomotion.translation"))
    constraint_value = canonicalise_for_hash(Constraint("max_velocity", {"max_mps": 0.5}))
    snapshot_value = canonicalise_for_hash(WorldSnapshotStub("snapshot-1", 0, 1, "fixture", 1.0))

    assert capability_value == {"name": "locomotion.translation", "parameters": {}, "version": "v1"}
    assert constraint_value == {
        "constraint_type": "max_velocity",
        "parameters": {"max_mps": 0.5},
        "required": True,
    }
    assert isinstance(snapshot_value, dict)
    assert snapshot_value["snapshot_id"] == "snapshot-1"


def test_canonicalise_for_hash_handles_supported_containers() -> None:
    """Lists, tuples, sets, and frozensets canonicalise deterministically."""
    assert canonicalise_for_hash([1, (2, 3)]) == [1, [2, 3]]
    assert canonicalise_for_hash({"b", "a"}) == ["a", "b"]
    assert canonicalise_for_hash(frozenset({"b", "a"})) == ["a", "b"]


def test_canonicalise_for_hash_rejects_nonfinite_numbers_and_non_string_keys() -> None:
    """Unsupported hash evidence fails before SafetyCase IDs are produced."""
    with pytest.raises(ValueError, match="finite"):
        canonicalise_for_hash(float("nan"))
    with pytest.raises(ValueError, match="keys"):
        canonicalise_for_hash({1: "value"})
