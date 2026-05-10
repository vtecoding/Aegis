"""Hypothesis invariants for Policy-v1 contract foundation."""

from copy import deepcopy

from hypothesis import given
from hypothesis import strategies as st

from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyRule,
    WorldSnapshotStub,
)

TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=20,
).filter(lambda value: value.strip() != "")

EMPTY_TEXT = st.text(max_size=10).filter(lambda value: value.strip() == "")

POLICY_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000, max_value=1_000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=20),
)

POLICY_VALUE = st.recursive(
    POLICY_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
    ),
    max_leaves=10,
)

PARAMETERS = st.dictionaries(st.text(min_size=1, max_size=10), POLICY_VALUE, max_size=3)


def make_rule(rule_id: str) -> PolicyRule:
    """Return a valid rule with the supplied identifier."""
    return PolicyRule(rule_id, "locomotion.translation", [Constraint("max_velocity")])


@given(empty_text=EMPTY_TEXT)
def test_invariant_generated_invalid_empty_strings_fail_closed(empty_text: str) -> None:
    """Generated empty strings are rejected at policy contract boundaries."""
    for constructor in (
        lambda value: Capability(value),
        lambda value: Constraint(value),
        lambda value: Policy(value, "v1", [make_rule("rule-1")]),
    ):
        try:
            constructor(empty_text)
        except ValueError:
            continue
        raise AssertionError("empty policy contract string was accepted")


@given(rule_id=TEXT)
def test_invariant_generated_duplicate_rule_ids_fail_closed(rule_id: str) -> None:
    """Duplicate rule IDs are always rejected by Policy construction."""
    first = make_rule(rule_id)
    second = make_rule(rule_id)

    try:
        Policy("policy-1", "v1", [first, second])
    except ValueError:
        return
    raise AssertionError("duplicate rule IDs were accepted")


@given(
    confidence=st.one_of(
        st.floats(max_value=-0.000001, allow_nan=False, allow_infinity=False),
        st.floats(min_value=1.000001, allow_nan=False, allow_infinity=False),
    )
)
def test_invariant_confidence_outside_range_fails_closed(confidence: float) -> None:
    """World snapshot confidence outside [0.0, 1.0] is rejected."""
    try:
        WorldSnapshotStub("snapshot-1", 0, 1, "fixture", confidence)
    except ValueError:
        return
    raise AssertionError("out-of-range confidence was accepted")


@given(confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
def test_invariant_valid_confidence_inside_range_is_accepted(confidence: float) -> None:
    """World snapshot confidence inside [0.0, 1.0] is accepted."""
    snapshot = WorldSnapshotStub("snapshot-1", 0, 1, "fixture", confidence)

    assert snapshot.confidence == float(confidence)


@given(parameters=PARAMETERS)
def test_invariant_source_dictionary_mutation_cannot_change_contract_state(
    parameters: dict[str, object],
) -> None:
    """Caller-owned dictionaries cannot mutate stored Policy-v1 contract values."""
    original = deepcopy(parameters)
    capability = Capability("inspection.observe", parameters=parameters)
    expected = Capability("inspection.observe", parameters=original)

    parameters.clear()

    assert capability == expected


@given(parameters=PARAMETERS)
def test_invariant_same_policy_parameter_inputs_produce_equal_capabilities(
    parameters: dict[str, object],
) -> None:
    """Identical explicit inputs produce equal Capability contracts."""
    first = Capability("inspection.observe", parameters=parameters)
    second = Capability("inspection.observe", parameters=deepcopy(parameters))

    assert first == second
