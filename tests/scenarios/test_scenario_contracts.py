"""Contract tests for ADR-0013 scenario runner models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

import pytest

from aegis.contracts.decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.contracts.json_types import FrozenJsonValue
from aegis.contracts.pipeline import PipelineOutcome
from aegis.scenarios.contracts import ScenarioExpectation
from aegis.scenarios.fixtures import canonical_scenario_definitions
from aegis.scenarios.runner import run_scenario_suite


def test_scenario_definition_freezes_metadata_deeply() -> None:
    base = canonical_scenario_definitions()[0]

    scenario = replace(
        base,
        scenario_id="scenario.contract_metadata",
        metadata={"nested": {"values": [1, 2, 3]}},
    )

    nested = scenario.metadata["nested"]
    assert isinstance(nested, Mapping)
    assert nested["values"] == (1, 2, 3)


def test_scenario_definition_rejects_callable_metadata() -> None:
    base = canonical_scenario_definitions()[0]
    bad_metadata = cast(
        Mapping[str, FrozenJsonValue],
        {"callback": test_scenario_definition_rejects_callable_metadata},
    )

    with pytest.raises(ValueError, match="JSON-compatible"):
        replace(base, scenario_id="scenario.bad_metadata", metadata=bad_metadata)


def test_scenario_definition_rejects_non_ascii_scenario_id() -> None:
    base = canonical_scenario_definitions()[0]

    with pytest.raises(ValueError, match="ASCII"):
        replace(base, scenario_id="scenario.snowman.☃")


def test_allowed_expectation_requires_full_trace_chain() -> None:
    with pytest.raises(ValueError, match="full decision trace chain"):
        ScenarioExpectation(
            expected_outcome=PipelineOutcome.ALLOWED,
            expected_reason="GATE_ALLOWED",
            expected_terminal_stage="gate_decision",
            required_stages=("raw_intent",),
            forbidden_stages=(),
            receipt_must_be_valid=True,
            approval_receipt_required=True,
            allow_late_stage_artifacts=False,
        )


def test_allowed_expectation_accepts_full_trace_chain() -> None:
    expectation = ScenarioExpectation(
        expected_outcome=PipelineOutcome.ALLOWED,
        expected_reason="GATE_ALLOWED",
        expected_terminal_stage="gate_decision",
        required_stages=DECISION_TRACE_STAGE_ORDER,
        forbidden_stages=(),
        receipt_must_be_valid=True,
        approval_receipt_required=True,
        allow_late_stage_artifacts=True,
    )

    assert expectation.required_stages == DECISION_TRACE_STAGE_ORDER


def test_duplicate_scenario_ids_are_rejected() -> None:
    first = canonical_scenario_definitions()[0]
    duplicate = replace(first, name="Duplicate allowed scenario")

    with pytest.raises(ValueError, match="duplicate scenario_id"):
        run_scenario_suite("duplicate-suite", (first, duplicate))
