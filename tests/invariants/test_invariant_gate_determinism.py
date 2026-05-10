"""Invariant tests for gate-v1 determinism properties."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from aegis.audit.aegis_audit_builder import build_audited_plan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_gate import GateBlockReason, GateDecisionStatus
from aegis.contracts.aegis_intent import RawIntent
from aegis.gate.aegis_decision_gate import gate_audited_plan
from aegis.planning.aegis_command_planner import plan_validated_intent
from aegis.validation.aegis_semantic_validator import validate_intent

_TARGET_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=50,
).filter(lambda value: value.strip() != "")

_COORDINATE = st.one_of(
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(min_value=-1_000_000, max_value=1_000_000, allow_nan=False, allow_infinity=False),
)

_VALID_COMMAND_CASES = st.one_of(
    st.just(("stop", {})),
    st.integers(min_value=1, max_value=60_000).map(
        lambda duration: ("wait", {"duration_ms": duration})
    ),
    _TARGET_TEXT.map(lambda target: ("inspect", {"target": target})),
    st.tuples(_COORDINATE, _COORDINATE).map(
        lambda coordinates: ("move", {"target": {"x": coordinates[0], "y": coordinates[1]}})
    ),
)


def _make_context(request_id: str = "req-gate") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 3, 1, tzinfo=UTC), "policy-v1")


def _make_audited_plan(command: str, parameters: dict[str, object], context: ExecutionContext):
    result = validate_intent(RawIntent(command, parameters, "operator-1", 5, context))
    assert result.is_valid
    return build_audited_plan(plan_validated_intent(result))


@given(case=_VALID_COMMAND_CASES)
def test_invariant_same_audited_plan_produces_equal_gate_decisions(
    case: tuple[str, dict[str, object]],
) -> None:
    audited_plan = _make_audited_plan(*case, context=_make_context())

    assert gate_audited_plan(audited_plan) == gate_audited_plan(audited_plan)


@given(case=_VALID_COMMAND_CASES)
def test_invariant_equivalent_valid_plans_with_same_context_gate_the_same(
    case: tuple[str, dict[str, object]],
) -> None:
    context = _make_context()
    first = _make_audited_plan(*case, context=context)
    second = _make_audited_plan(*case, context=context)

    assert gate_audited_plan(first) == gate_audited_plan(second)
    assert gate_audited_plan(first).status is GateDecisionStatus.ALLOWED


@given(case=_VALID_COMMAND_CASES)
def test_invariant_gate_does_not_mutate_audited_plan(case: tuple[str, dict[str, object]]) -> None:
    audited_plan = _make_audited_plan(*case, context=_make_context())
    before = (
        audited_plan.audit_id,
        audited_plan.checksum,
        audited_plan.plan.plan_id,
        audited_plan.plan.intent.command,
        audited_plan.plan.intent.parameters,
        audited_plan.plan.steps,
    )

    gate_audited_plan(audited_plan)

    after = (
        audited_plan.audit_id,
        audited_plan.checksum,
        audited_plan.plan.plan_id,
        audited_plan.plan.intent.command,
        audited_plan.plan.intent.parameters,
        audited_plan.plan.steps,
    )
    assert after == before


def test_invariant_same_steps_changed_context_preserves_checksum_but_blocks_audit_id() -> None:
    audited_plan = _make_audited_plan("stop", {}, _make_context("req-original"))
    changed_context = ExecutionContext("req-changed", datetime(2026, 3, 1, tzinfo=UTC), "policy-v1")
    object.__setattr__(audited_plan.plan.intent, "context", changed_context)

    decision = gate_audited_plan(audited_plan)

    assert decision.status is GateDecisionStatus.BLOCKED
    assert decision.reasons == (GateBlockReason.AUDIT_ID_MISMATCH,)
    assert decision.checksum_verified is True
    assert decision.audit_id_verified is False


def test_invariant_reason_order_is_stable() -> None:
    audited_plan = _make_audited_plan("stop", {}, _make_context())
    object.__setattr__(audited_plan, "checksum", "a" * 64)
    object.__setattr__(audited_plan, "audit_id", "b" * 64)

    first = gate_audited_plan(audited_plan)
    second = gate_audited_plan(audited_plan)

    assert first.reasons == (
        GateBlockReason.CHECKSUM_MISMATCH,
        GateBlockReason.AUDIT_ID_MISMATCH,
    )
    assert first.reasons == second.reasons
