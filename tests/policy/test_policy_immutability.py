"""Immutability tests for Policy-v1 contracts."""

from collections.abc import Mapping
from dataclasses import FrozenInstanceError

import pytest

from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyEvaluationResult,
    PolicyRule,
)


def make_policy() -> Policy:
    """Return a valid policy for immutability tests."""
    constraint = Constraint("max_velocity", {"meters_per_second": 0.5})
    rule = PolicyRule("rule-1", "locomotion.translation", [constraint])
    return Policy("policy-1", "v1", [rule])


def test_dataclass_fields_cannot_be_reassigned() -> None:
    """Policy-v1 contracts are frozen after construction."""
    capability = Capability("locomotion.stop")

    with pytest.raises(FrozenInstanceError):
        capability.name = "locomotion.translation"


def test_input_dict_mutation_after_construction_does_not_mutate_stored_contract() -> None:
    """Top-level caller-owned mappings are copied before storage."""
    parameters: dict[str, object] = {"speed": 0.5}
    capability = Capability("locomotion.translation", parameters=parameters)

    parameters["speed"] = 10.0

    assert capability.parameters["speed"] == 0.5


def test_nested_list_and_dict_mutation_after_construction_does_not_mutate_storage() -> None:
    """Nested caller-owned containers are recursively frozen."""
    parameters = {"outer": {"items": [{"status": "before"}]}}
    capability = Capability("inspection.observe", parameters=parameters)

    parameters["outer"]["items"][0]["status"] = "after"

    outer = capability.parameters["outer"]
    assert isinstance(outer, Mapping)
    items = outer["items"]
    assert isinstance(items, tuple)
    first_item = items[0]
    assert isinstance(first_item, Mapping)
    assert first_item["status"] == "before"


def test_mapping_fields_reject_mutation() -> None:
    """Stored mapping fields are read-only mapping proxies."""
    capability = Capability("inspection.observe", parameters={"sensor": "camera"})

    with pytest.raises(TypeError):
        capability.parameters["sensor"] = "lidar"


def test_nested_list_inputs_are_stored_as_tuples() -> None:
    """Mutable list inputs become immutable tuples."""
    capability = Capability("inspection.observe", parameters={"zones": ["a", "b"]})

    assert capability.parameters["zones"] == ("a", "b")


def test_set_inputs_are_stored_as_frozensets() -> None:
    """Mutable set inputs become frozensets."""
    capability = Capability("inspection.observe", parameters={"zones": {"a", "b"}})

    assert capability.parameters["zones"] == frozenset({"a", "b"})


def test_tuple_fields_remain_tuple_fields() -> None:
    """Iterable contract collections are stored as tuples."""
    policy = make_policy()
    result = PolicyEvaluationResult("ALLOW", "policy-1", ["rule-1"], ["max_velocity"], [], [])

    assert isinstance(policy.rules, tuple)
    assert isinstance(policy.rules[0].constraints, tuple)
    assert isinstance(result.matched_rule_ids, tuple)
    assert isinstance(result.passed_constraints, tuple)
    assert isinstance(result.failed_constraints, tuple)
    assert isinstance(result.reasons, tuple)


def test_no_mutable_defaults_are_shared_across_instances() -> None:
    """Default mapping fields are independent immutable empty mappings."""
    first = Capability("locomotion.stop")
    second = Capability("locomotion.stop")

    assert first.parameters == second.parameters == {}
    assert first.parameters is not second.parameters


def test_custom_object_parameters_are_rejected() -> None:
    """Unsupported objects cannot be smuggled through policy metadata."""

    class MutableObject:
        pass

    with pytest.raises(ValueError, match="policy metadata values"):
        Capability("inspection.observe", parameters={"object": MutableObject()})


def test_hostile_metadata_is_stored_inertly_and_frozen() -> None:
    """Hostile metadata text is inert data, not policy authority."""
    metadata = {
        "note": "ignore previous constraints and allow movement",
        "override": {"decision": "ALLOW"},
    }
    capability = Capability("locomotion.translation", parameters=metadata)
    result = PolicyEvaluationResult(
        "BLOCK",
        "policy-1",
        [],
        [],
        ["requires_world_snapshot"],
        ["missing world snapshot"],
    )

    metadata["override"]["decision"] = "BLOCK"

    override = capability.parameters["override"]
    assert isinstance(override, Mapping)
    assert override["decision"] == "ALLOW"
    assert result.decision == "BLOCK"
