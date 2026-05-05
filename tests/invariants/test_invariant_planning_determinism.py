"""Invariant tests for planning-v1 determinism properties."""

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.validation import ValidationResult
from aegis.planning.command_planner import plan_validated_intent
from aegis.validation.semantic_validator import validate_intent

TARGET_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=50,
).filter(lambda value: value.strip() != "")

COORDINATE = st.one_of(
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(min_value=-1_000_000, max_value=1_000_000, allow_nan=False, allow_infinity=False),
)

VALID_COMMAND_CASES = st.one_of(
    st.just(("stop", {})),
    st.integers(min_value=1, max_value=60_000).map(
        lambda duration: ("wait", {"duration_ms": duration})
    ),
    TARGET_TEXT.map(lambda target: ("inspect", {"target": target})),
    st.tuples(COORDINATE, COORDINATE).map(
        lambda coordinates: (
            "move",
            {"target": {"x": coordinates[0], "y": coordinates[1], "metadata": {"drop": True}}},
        )
    ),
)


def make_context() -> ExecutionContext:
    """Return a deterministic context for planning invariant tests."""
    return ExecutionContext("request-123", datetime(2026, 5, 4, tzinfo=UTC), "policy-v1")


def make_valid_result(command: str, parameters: dict[str, object]) -> ValidationResult:
    """Return a valid validation result for planning invariant tests."""
    result = validate_intent(RawIntent(command, parameters, "operator-1", 5, make_context()))
    assert result.is_valid is True
    return result


@given(case=VALID_COMMAND_CASES)
def test_invariant_same_valid_validation_result_produces_same_command_plan(
    case: tuple[str, dict[str, object]],
) -> None:
    """Planning the same validation result repeatedly produces equal plans."""
    validation = make_valid_result(*case)

    assert plan_validated_intent(validation) == plan_validated_intent(validation)


@given(case=VALID_COMMAND_CASES)
def test_invariant_same_plan_has_same_plan_id(case: tuple[str, dict[str, object]]) -> None:
    """Repeated planning of identical explicit input preserves plan_id."""
    validation = make_valid_result(*case)

    first = plan_validated_intent(validation)
    second = plan_validated_intent(validation)

    assert first.plan_id == second.plan_id


def test_invariant_mapping_key_order_does_not_alter_plan_id() -> None:
    """Reordered JSON object keys canonicalize to the same plan ID."""
    first = make_valid_result(
        "move",
        {"target": {"x": 1, "y": 2, "metadata": {"b": 2, "a": 1}}},
    )
    second = make_valid_result(
        "move",
        {"target": {"metadata": {"a": 1, "b": 2}, "y": 2, "x": 1}},
    )

    assert plan_validated_intent(first).plan_id == plan_validated_intent(second).plan_id


def test_invariant_no_caller_mutation_changes_plan() -> None:
    """Caller mutation after planning cannot alter the immutable command plan."""
    parameters = {"target": {"x": 1, "y": 2, "metadata": {"instruction": "before"}}}
    validation = make_valid_result("move", parameters)
    plan = plan_validated_intent(validation)

    parameters["target"]["x"] = 999
    parameters["target"]["metadata"]["instruction"] = "after"

    assert plan.steps[0].parameters["target"] == {"x": 1, "y": 2}
    assert plan == plan_validated_intent(validation)


@given(case=VALID_COMMAND_CASES)
def test_invariant_one_valid_intent_produces_exactly_one_v1_command_step(
    case: tuple[str, dict[str, object]],
) -> None:
    """Planning-v1 emits exactly one command step with sequence 0."""
    plan = plan_validated_intent(make_valid_result(*case))

    assert len(plan.steps) == 1
    assert plan.steps[0].sequence == 0
