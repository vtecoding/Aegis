"""Pipeline orchestrator v1 contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateDecision
from aegis.contracts.planning import CommandPlan
from aegis.contracts.validation import ValidationResult


class PipelineOutcome(StrEnum):
    """Final Phase 1 pipeline outcome values."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    INVALID = "invalid"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Immutable result of one full Phase 1 pipeline run.

    Args:
        outcome: Final pipeline outcome.
        validation_result: Validation outcome; ``None`` only when
            ``outcome == ERROR`` and validation did not complete.
        plan: Command plan produced by the planning layer; ``None`` when
            validation failed or planning was not reached.
        audited_plan: Audit receipt; ``None`` when planning was skipped
            or auditing was not reached.
        gate_decision: Gate decision; ``None`` when the gate was not reached.

    Raises:
        ValueError: If the outcome/field combination violates pipeline-v1
            invariants.
    """

    outcome: PipelineOutcome
    validation_result: ValidationResult | None
    plan: CommandPlan | None
    audited_plan: AuditedPlan | None
    gate_decision: GateDecision | None

    def __post_init__(self) -> None:
        """Enforce pipeline-v1 outcome/field invariants."""
        if self.outcome == PipelineOutcome.ALLOWED:
            if self.gate_decision is None or self.gate_decision.status != "allowed":
                raise ValueError(
                    "PipelineResult outcome=ALLOWED requires gate_decision with status='allowed'"
                )
        elif self.outcome == PipelineOutcome.BLOCKED:
            if self.gate_decision is None or self.gate_decision.status != "blocked":
                raise ValueError(
                    "PipelineResult outcome=BLOCKED requires gate_decision with status='blocked'"
                )
        elif self.outcome == PipelineOutcome.INVALID:
            if self.plan is not None:
                raise ValueError("PipelineResult outcome=INVALID must have plan=None")
            if self.audited_plan is not None:
                raise ValueError("PipelineResult outcome=INVALID must have audited_plan=None")
            if self.gate_decision is not None:
                raise ValueError("PipelineResult outcome=INVALID must have gate_decision=None")
