"""Phase 1 deterministic pipeline orchestrator."""

from __future__ import annotations

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.intent import RawIntent
from aegis.contracts.pipeline import PipelineOutcome, PipelineResult
from aegis.errors import AegisError
from aegis.gate import gate_audited_plan
from aegis.planning import plan_validated_intent
from aegis.validation import validate_intent


def run_pipeline(raw_intent: RawIntent, context: ExecutionContext) -> PipelineResult:
    """Run raw intent through the full Phase 1 Aegis pipeline.

    Composes ``validate_intent`` -> ``plan_validated_intent`` ->
    ``build_audited_plan`` -> ``gate_audited_plan`` deterministically.

    ``AegisError`` subclasses (``ValidationError``, ``PlanningError``,
    ``AuditError``, ``GateError``) propagate to the caller unchanged.

    Only unexpected non-``AegisError`` exceptions are caught and returned
    as ``PipelineOutcome.ERROR`` with the fields populated up to the point
    of failure.  This narrow boundary mirrors the scenario runner harness
    policy and must not be copied into layer implementations.

    Args:
        raw_intent: Validated boundary object carrying raw intent data.
        context: Injected execution context for deterministic replay.

    Returns:
        A ``PipelineResult`` with outcome ``ALLOWED``, ``BLOCKED``,
        ``INVALID``, or ``ERROR``.
    """
    return _run(raw_intent, context)


def _run(raw_intent: RawIntent, context: ExecutionContext) -> PipelineResult:
    """Inner pipeline composition — separated for testability."""
    # Step 1: Validate — always runs; produces ValidationResult.
    try:
        validation_result = validate_intent(raw_intent)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        # validate_intent is a pure function with no expected exceptions beyond
        # AegisError; any non-AegisError here is a framework-level failure.
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=None,
            plan=None,
            audited_plan=None,
            gate_decision=None,
        )

    if not validation_result.is_valid:
        return PipelineResult(
            outcome=PipelineOutcome.INVALID,
            validation_result=validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=None,
        )

    # Step 2: Plan — only when validation passed.
    # PlanningError propagates to caller.
    try:
        plan = plan_validated_intent(validation_result)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=None,
            audited_plan=None,
            gate_decision=None,
        )

    # Step 3: Audit — produces AuditedPlan.
    # AuditError propagates to caller.
    try:
        audited_plan = build_audited_plan(plan)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=None,
            gate_decision=None,
        )

    # Step 4: Gate — deterministic approval boundary.
    # GateError propagates to caller.
    try:
        decision = gate_audited_plan(audited_plan)
    except AegisError:
        raise
    except Exception:  # noqa: BLE001
        return PipelineResult(
            outcome=PipelineOutcome.ERROR,
            validation_result=validation_result,
            plan=plan,
            audited_plan=audited_plan,
            gate_decision=None,
        )

    outcome = PipelineOutcome.ALLOWED if decision.status == "allowed" else PipelineOutcome.BLOCKED
    return PipelineResult(
        outcome=outcome,
        validation_result=validation_result,
        plan=plan,
        audited_plan=audited_plan,
        gate_decision=decision,
    )
