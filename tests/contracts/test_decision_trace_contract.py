"""Contract tests for deterministic decision traces."""

from __future__ import annotations

from typing import cast

import pytest

from aegis.contracts.decision_trace import (
    DecisionTrace,
    DecisionTraceStep,
    decision_trace_checksum,
    decision_trace_integrity_errors,
    decision_trace_step_checksum,
)
from aegis.contracts.json_types import JsonValue


def _step(
    stage_name: str = "raw_intent",
    *,
    input_checksum: str = "context-checksum",
    output_checksum: str = "raw-checksum",
    predecessor_checksum: str | None = None,
) -> DecisionTraceStep:
    return DecisionTraceStep(
        stage_name=stage_name,
        stage_status="OK",
        stage_reason="TRACE_STEP_OK",
        input_checksum=input_checksum,
        output_checksum=output_checksum,
        predecessor_checksum=predecessor_checksum,
        metadata={"sequence": 1, "labels": [stage_name]},
    )


def _linked_steps() -> tuple[DecisionTraceStep, DecisionTraceStep, DecisionTraceStep]:
    raw = _step()
    validation = _step(
        "validation",
        input_checksum=raw.output_checksum,
        output_checksum="validation-checksum",
        predecessor_checksum=raw.stage_checksum,
    )
    planning = _step(
        "planning",
        input_checksum=validation.output_checksum,
        output_checksum="planning-checksum",
        predecessor_checksum=validation.stage_checksum,
    )
    return raw, validation, planning


def test_decision_trace_step_checksum_is_canonical() -> None:
    step = _step()

    assert step.stage_checksum == decision_trace_step_checksum(
        stage_name=step.stage_name,
        stage_status=step.stage_status,
        stage_reason=step.stage_reason,
        input_checksum=step.input_checksum,
        output_checksum=step.output_checksum,
        predecessor_checksum=step.predecessor_checksum,
        metadata=step.metadata,
    )


def test_decision_trace_rejects_broken_predecessor_link() -> None:
    raw = _step()
    validation = _step(
        "validation",
        input_checksum=raw.output_checksum,
        output_checksum="validation-checksum",
        predecessor_checksum="not-the-raw-step",
    )

    with pytest.raises(ValueError, match="PREDECESSOR"):
        DecisionTrace((raw, validation))


def test_decision_trace_rejects_reordered_stages() -> None:
    raw = _step()
    planning = _step(
        "planning",
        input_checksum=raw.output_checksum,
        output_checksum="planning-before-validation",
        predecessor_checksum=raw.stage_checksum,
    )
    reordered_validation = _step(
        "validation",
        input_checksum=planning.output_checksum,
        output_checksum="validation-after-planning",
        predecessor_checksum=planning.stage_checksum,
    )

    with pytest.raises(ValueError, match="STAGE_ORDER"):
        DecisionTrace((raw, planning, reordered_validation))


def test_decision_trace_rejects_duplicate_stage_names() -> None:
    raw = _step()
    duplicate = _step(
        input_checksum=raw.output_checksum,
        output_checksum="second-raw",
        predecessor_checksum=raw.stage_checksum,
    )

    with pytest.raises(ValueError, match="DUPLICATE"):
        DecisionTrace((raw, duplicate))


def test_decision_trace_rejects_confusable_stage_name() -> None:
    with pytest.raises(ValueError, match="stage_name"):
        _step("p\u043eolicy_evaluation")


def test_decision_trace_rejects_metadata_object_injection() -> None:
    bad_metadata = cast(dict[str, JsonValue], {"bad": object()})

    with pytest.raises(ValueError, match="JSON-compatible"):
        DecisionTraceStep(
            stage_name="raw_intent",
            stage_status="OK",
            stage_reason="TRACE_STEP_OK",
            input_checksum="in",
            output_checksum="out",
            predecessor_checksum=None,
            metadata=bad_metadata,
        )


def test_decision_trace_metadata_is_immutable() -> None:
    step = _step()

    with pytest.raises(TypeError):
        step.metadata["sequence"] = 2  # type: ignore[index]


def test_decision_trace_integrity_detects_mutated_stage_checksum() -> None:
    trace = DecisionTrace(_linked_steps())
    object.__setattr__(trace.steps[1], "stage_checksum", "forged-stage-checksum")

    assert "DECISION_TRACE_STAGE_CHECKSUM_MISMATCH" in decision_trace_integrity_errors(trace)


def test_decision_trace_checksum_is_recomputed_from_stage_checksums() -> None:
    trace = DecisionTrace(_linked_steps())

    assert trace.trace_checksum == decision_trace_checksum(trace.steps)
