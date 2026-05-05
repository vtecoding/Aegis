"""Scenario runner data models for the Aegis proof harness."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aegis.contracts.json_types import FrozenJsonValue, JsonValue


@dataclass(frozen=True, slots=True)
class ScenarioExpected:
    """Expected pipeline outcomes for a scenario fixture.

    Args:
        validation: Expected validation outcome — ``"valid"`` or ``"invalid"``.
        planning: Expected planning outcome — ``"valid"``, ``"invalid"``, or
            ``"skipped"``.  ``"skipped"`` means planning was not attempted
            because validation was invalid.
        metadata_dropped: True when the fixture contains hostile metadata that
            should be absent from the plan step parameters after planning.
        audit_created: True when the scenario should produce an audit receipt.
    """

    validation: str
    planning: str
    metadata_dropped: bool
    audit_created: bool


@dataclass(frozen=True, slots=True)
class ScenarioIntentFixture:
    """Raw intent data extracted from a scenario JSON fixture.

    Context is not included here; it is injected by the caller into
    ``run_scenario`` so that context injection remains explicit and
    deterministic replays remain possible with any context.

    Args:
        command: Intent command string.
        parameters: JSON-compatible parameter mapping.
        source_id: Caller/source identifier.
        priority: Integer priority from 1 through 10.
    """

    command: str
    parameters: Mapping[str, JsonValue]
    source_id: str
    priority: int


@dataclass(frozen=True, slots=True)
class ScenarioFixture:
    """A scenario fixture binding raw intent data to expected pipeline outcomes.

    Args:
        name: Unique scenario name.
        intent: Raw intent fields before context injection.
        expected: Expected pipeline outcomes.
    """

    name: str
    intent: ScenarioIntentFixture
    expected: ScenarioExpected


@dataclass(frozen=True, slots=True)
class ScenarioPlanStep:
    """Summary of the plan step produced by the planning layer.

    Args:
        step_type: String value of the ``CommandStepType`` (e.g. ``"move"``).
        parameters: Frozen JSON-compatible parameters from the command step.
    """

    step_type: str
    parameters: Mapping[str, FrozenJsonValue]


@dataclass(frozen=True, slots=True)
class ScenarioAuditSummary:
    """Summary of the audit data produced by the audit layer.

    Args:
        checksum: SHA-256 checksum of the executable command steps.
        audit_id: SHA-256 audit event identifier binding checksum and plan context.
    """

    checksum: str
    audit_id: str


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """Result of running one scenario through the Aegis pipeline.

    Args:
        scenario: Scenario name.
        status: Overall result — ``"passed"`` or ``"failed"``.
        validation: Validation outcome — ``"valid"``, ``"invalid"``, or
            ``"error"``.  ``"error"`` means ``RawIntent`` construction was
            rejected at the boundary before validation could run.
        planned: True when planning succeeded and produced a command plan.
        audited: True when an audit receipt was produced.
        violations: Violation codes emitted by the validation layer.
        plan_step: Plan step summary when planning succeeded; else ``None``.
        audit: Audit summary when auditing succeeded; else ``None``.
        gate_status: Gate decision status string — ``"allowed"``, ``"blocked"``,
            or ``None`` when the gate was not reached (auditing was skipped).
        gate_integrity_mismatch: True when the gate was blocked due to
            ``CHECKSUM_MISMATCH`` or ``AUDIT_ID_MISMATCH`` reasons.
        failure_reason: Internal failure detail when an execution error
            occurred (boundary rejection, planning failure, or unexpected
            exception).  Distinct from validation violations.
    """

    scenario: str
    status: str
    validation: str
    planned: bool
    audited: bool
    violations: tuple[str, ...]
    plan_step: ScenarioPlanStep | None
    audit: ScenarioAuditSummary | None
    gate_status: str | None
    gate_integrity_mismatch: bool
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class ScenarioMetrics:
    """Aggregate metrics across all scenarios in a run.

    Args:
        scenario_count: Total scenarios executed.
        valid_count: Scenarios where validation passed.
        invalid_count: Scenarios where validation produced violations.
        planned_count: Scenarios where planning succeeded.
        audit_created_count: Scenarios where an audit receipt was produced.
        metadata_leak_count: Scenarios where a ``"metadata"`` key appeared
            anywhere in the plan step parameters after planning.
        unexpected_exception_count: Scenarios where a non-Aegis exception
            occurred during execution.
        deterministic_replay_failures: Scenarios where re-running with the
            same fixture and context produced a different ``ScenarioResult``.
        gate_allowed_count: Scenarios where the gate returned
            ``GateDecisionStatus.ALLOWED``.
        gate_blocked_count: Scenarios where the gate returned
            ``GateDecisionStatus.BLOCKED``.
        gate_integrity_mismatch_count: Scenarios where the gate was blocked
            due to ``CHECKSUM_MISMATCH`` or ``AUDIT_ID_MISMATCH`` reasons.
    """

    scenario_count: int
    valid_count: int
    invalid_count: int
    planned_count: int
    audit_created_count: int
    metadata_leak_count: int
    unexpected_exception_count: int
    deterministic_replay_failures: int
    gate_allowed_count: int
    gate_blocked_count: int
    gate_integrity_mismatch_count: int
