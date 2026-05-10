"""Invariant tests for contracts-v1 determinism properties."""

from copy import deepcopy
from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from aegis.aegis_errors import ValidationError
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_validation import ValidationResult, Violation

TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=20,
).filter(lambda value: value.strip() != "")

JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=30),
)

JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
    ),
    max_leaves=12,
)

PARAMETERS = st.dictionaries(st.text(min_size=1, max_size=10), JSON_VALUE, max_size=3)


def make_context() -> ExecutionContext:
    """Return a fixed explicit context for invariant tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


@given(request_id=TEXT, policy_version=TEXT, run_id=st.one_of(st.none(), TEXT))
def test_invariant_same_execution_context_inputs_produce_equal_objects(
    request_id: str,
    policy_version: str,
    run_id: str | None,
) -> None:
    """Same explicit ExecutionContext inputs always produce equal objects."""
    submitted_at = datetime(2026, 5, 4, 12, 30, tzinfo=UTC)

    first = ExecutionContext(request_id, submitted_at, policy_version, run_id)
    second = ExecutionContext(request_id, submitted_at, policy_version, run_id)

    assert first == second


@given(
    command=TEXT,
    source_id=TEXT,
    priority=st.integers(min_value=1, max_value=10),
    parameters=PARAMETERS,
)
def test_invariant_same_raw_intent_inputs_produce_equal_objects(
    command: str,
    source_id: str,
    priority: int,
    parameters: dict[str, object],
) -> None:
    """Same explicit RawIntent inputs always produce equal objects."""
    context = make_context()

    first = RawIntent(command, parameters, source_id, priority, context)
    second = RawIntent(command, parameters, source_id, priority, context)

    assert first == second


@given(parameters=PARAMETERS)
def test_invariant_raw_intent_construction_does_not_mutate_caller_parameters(
    parameters: dict[str, object],
) -> None:
    """RawIntent construction never mutates the caller-owned parameter object."""
    original = deepcopy(parameters)

    RawIntent("inspect_area", parameters, "operator-1", 5, make_context())

    assert parameters == original


def test_invariant_caller_mutation_after_construction_does_not_mutate_raw_intent() -> None:
    """Caller-owned nested parameter mutation cannot alter RawIntent storage."""
    parameters = {"outer": {"items": [{"status": "before"}]}}
    intent = RawIntent("inspect_area", parameters, "operator-1", 5, make_context())

    parameters["outer"]["items"][0]["status"] = "after"

    assert intent.parameters["outer"]["items"][0]["status"] == "before"


@given(message=TEXT, layer=TEXT, context=PARAMETERS)
def test_invariant_same_error_inputs_produce_stable_str(
    message: str,
    layer: str,
    context: dict[str, object],
) -> None:
    """Same explicit error inputs always produce the same string representation."""
    first = ValidationError(message, layer, context)
    second = ValidationError(message, layer, context)

    assert str(first) == str(second)


@given(field=TEXT, reason=TEXT, code=TEXT, layer=TEXT)
def test_invariant_validation_result_equality_is_stable_for_same_inputs(
    field: str,
    reason: str,
    code: str,
    layer: str,
) -> None:
    """Same explicit ValidationResult inputs always produce equal objects."""
    intent = RawIntent("inspect_area", {}, "operator-1", 5, make_context())
    violation = Violation(field, reason, code, layer)

    first = ValidationResult(False, intent, [violation])
    second = ValidationResult(False, intent, [violation])

    assert first == second


def test_invariant_contracts_do_not_create_internal_time_or_ids() -> None:
    """Repeated construction from explicit values stays equal across all v1 contracts."""
    submitted_at = datetime(2026, 5, 4, 12, 30, tzinfo=UTC)
    first_context = ExecutionContext("request-123", submitted_at, "policy-v1", "run-123")
    second_context = ExecutionContext("request-123", submitted_at, "policy-v1", "run-123")
    first_intent = RawIntent("inspect_area", {"zone": "A"}, "operator-1", 5, first_context)
    second_intent = RawIntent("inspect_area", {"zone": "A"}, "operator-1", 5, second_context)

    assert first_context == second_context
    assert first_intent == second_intent
