"""Invariant tests for audit-v1 determinism properties."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from aegis.audit.audit_builder import build_audited_plan
from aegis.audit.checksum import plan_audit_id, plan_checksum
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.planning import CommandPlan
from aegis.planning.command_planner import plan_validated_intent
from aegis.validation.semantic_validator import validate_intent

_TARGET_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=50,
).filter(lambda v: v.strip() != "")

_COORDINATE = st.one_of(
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(min_value=-1_000_000, max_value=1_000_000, allow_nan=False, allow_infinity=False),
)

_VALID_COMMAND_CASES = st.one_of(
    st.just(("stop", {})),
    st.integers(min_value=1, max_value=60_000).map(lambda d: ("wait", {"duration_ms": d})),
    _TARGET_TEXT.map(lambda t: ("inspect", {"target": t})),
    st.tuples(_COORDINATE, _COORDINATE).map(
        lambda coords: ("move", {"target": {"x": coords[0], "y": coords[1]}})
    ),
)


def _make_context() -> ExecutionContext:
    return ExecutionContext("req-inv", datetime(2026, 3, 1, tzinfo=UTC), "policy-v1")


def _make_plan_for_case(command: str, parameters: dict[str, object]) -> CommandPlan:
    result = validate_intent(RawIntent(command, parameters, "operator-1", 5, _make_context()))
    assert result.is_valid
    return plan_validated_intent(result)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_same_plan_produces_same_checksum(
    case: tuple[str, dict[str, object]],
) -> None:
    """plan_checksum is stable for the same CommandPlan object."""
    plan = _make_plan_for_case(*case)
    assert plan_checksum(plan) == plan_checksum(plan)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_same_plan_produces_same_audit_id(
    case: tuple[str, dict[str, object]],
) -> None:
    """plan_audit_id is stable for the same plan and checksum."""
    plan = _make_plan_for_case(*case)
    checksum = plan_checksum(plan)
    assert plan_audit_id(plan, checksum) == plan_audit_id(plan, checksum)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_build_audited_plan_is_deterministic(
    case: tuple[str, dict[str, object]],
) -> None:
    """build_audited_plan produces equal AuditedPlan for the same CommandPlan."""
    plan = _make_plan_for_case(*case)
    assert build_audited_plan(plan) == build_audited_plan(plan)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_audit_does_not_mutate_command_plan(
    case: tuple[str, dict[str, object]],
) -> None:
    """build_audited_plan does not alter the CommandPlan passed to it."""
    plan = _make_plan_for_case(*case)

    original_plan_id = plan.plan_id
    original_steps_len = len(plan.steps)
    original_command = plan.intent.command

    build_audited_plan(plan)

    assert plan.plan_id == original_plan_id
    assert len(plan.steps) == original_steps_len
    assert plan.intent.command == original_command


def test_invariant_mapping_key_order_does_not_alter_checksum() -> None:
    """Reordering intent parameter keys produces the same plan checksum."""
    ctx = _make_context()

    result1 = validate_intent(
        RawIntent("move", {"target": {"x": 1, "y": 2, "extra": "a"}}, "op", 5, ctx)
    )
    result2 = validate_intent(
        RawIntent("move", {"target": {"extra": "a", "y": 2, "x": 1}}, "op", 5, ctx)
    )
    assert result1.is_valid and result2.is_valid

    plan1 = plan_validated_intent(result1)
    plan2 = plan_validated_intent(result2)

    # Both plans are from identical logical inputs so checksums must match
    assert plan_checksum(plan1) == plan_checksum(plan2)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_same_steps_different_context_same_checksum_different_audit_id(
    case: tuple[str, dict[str, object]],
) -> None:
    """Core separation invariant: checksum = what would be executed; audit_id = this receipt.

    Two plans with identical command steps but different execution contexts must:
    - produce the SAME checksum  (steps are identical)
    - produce a DIFFERENT audit_id  (context is different, plan_id is different)
    """
    command, parameters = case
    # context-A
    ctx_a = ExecutionContext("req-inv-A", datetime(2026, 3, 1, tzinfo=UTC), "policy-v1")
    result_a = validate_intent(RawIntent(command, parameters, "operator-1", 5, ctx_a))
    # context-B — different request_id, policy, and run_id
    ctx_b = ExecutionContext("req-inv-B", datetime(2026, 4, 1, tzinfo=UTC), "policy-v2", "run-99")
    result_b = validate_intent(RawIntent(command, parameters, "operator-2", 8, ctx_b))

    assert result_a.is_valid and result_b.is_valid
    plan_a = plan_validated_intent(result_a)
    plan_b = plan_validated_intent(result_b)

    checksum_a = plan_checksum(plan_a)
    checksum_b = plan_checksum(plan_b)

    # same executable steps → same checksum
    assert checksum_a == checksum_b
    # different context → different audit_id
    assert plan_audit_id(plan_a, checksum_a) != plan_audit_id(plan_b, checksum_b)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_audited_plan_checksum_and_audit_id_are_non_empty(
    case: tuple[str, dict[str, object]],
) -> None:
    """Every audited plan carries non-empty checksum and audit_id."""
    plan = _make_plan_for_case(*case)
    receipt = build_audited_plan(plan)
    assert receipt.checksum != ""
    assert receipt.audit_id != ""
