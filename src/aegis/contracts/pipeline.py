"""Pipeline orchestrator v1 contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateDecision
from aegis.contracts.planning import CommandPlan
from aegis.contracts.policy import PolicyDecision
from aegis.contracts.policy_admission import (
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    disabled_policy_admission_record,
    is_policy_backed_approval,
)
from aegis.contracts.validation import ValidationResult


class PipelineOutcome(StrEnum):
    """Final Phase 1 pipeline outcome values."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    INVALID = "invalid"
    ERROR = "error"


_FRESHNESS_INVALID_REASONS = frozenset(
    {
        "WORLD_SNAPSHOT_CONTRADICTORY_METADATA",
        "WORLD_SNAPSHOT_INVALID_MAX_AGE",
        "WORLD_SNAPSHOT_INVALID_TIMESTAMP",
    }
)

_TRUST_INVALID_REASONS = frozenset(
    {
        "WORLD_SNAPSHOT_TRUST_CONTRADICTORY_EVIDENCE",
        "WORLD_SNAPSHOT_TRUST_MALFORMED_EVIDENCE",
    }
)


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
        policy_admission: Policy admission state for this pipeline run.

    Raises:
        ValueError: If the outcome/field combination violates pipeline-v1
            invariants.
    """

    outcome: PipelineOutcome
    validation_result: ValidationResult | None
    plan: CommandPlan | None
    audited_plan: AuditedPlan | None
    gate_decision: GateDecision | None
    policy_admission: PolicyAdmissionRecord = field(
        default_factory=disabled_policy_admission_record
    )

    def __post_init__(self) -> None:
        """Enforce pipeline-v1 outcome/field invariants."""
        if self.outcome == PipelineOutcome.ALLOWED:
            if self.validation_result is None or self.plan is None or self.audited_plan is None:
                raise ValueError(
                    "PipelineResult outcome=ALLOWED requires validation, plan, and audited_plan"
                )
            if self.gate_decision is None or self.gate_decision.status != "allowed":
                raise ValueError(
                    "PipelineResult outcome=ALLOWED requires gate_decision with status='allowed'"
                )
            if not is_policy_backed_approval(
                self.audited_plan, self.policy_admission, self.gate_decision
            ):
                raise ValueError(
                    "PipelineResult outcome=ALLOWED requires policy-backed admission integrity"
                )
        elif self.outcome == PipelineOutcome.BLOCKED:
            gate_blocked = self.gate_decision is not None and self.gate_decision.status == "blocked"
            policy_blocked = (
                self.policy_admission.enforced
                or self.policy_admission.mode is PolicyAdmissionMode.DISABLED
            ) and not self.policy_admission.admission_allowed
            if self.gate_decision is not None and self.gate_decision.status != "blocked":
                raise ValueError(
                    "PipelineResult outcome=BLOCKED must not include an allowed gate_decision"
                )
            if not gate_blocked and not policy_blocked:
                raise ValueError(
                    "PipelineResult outcome=BLOCKED requires blocked gate_decision "
                    "or denied policy admission"
                )
        elif self.outcome == PipelineOutcome.INVALID:
            policy_invalid = (
                self.policy_admission.enforced
                and not self.policy_admission.admission_allowed
                and self.policy_admission.policy_result is not None
                and self.policy_admission.policy_result.decision is PolicyDecision.INVALID
            )
            freshness_invalid = (
                self.policy_admission.enforced
                and not self.policy_admission.admission_allowed
                and self.policy_admission.policy_result is None
                and any(
                    reason in _FRESHNESS_INVALID_REASONS for reason in self.policy_admission.reasons
                )
            )
            trust_invalid = (
                self.policy_admission.enforced
                and not self.policy_admission.admission_allowed
                and self.policy_admission.policy_result is None
                and any(
                    reason in _TRUST_INVALID_REASONS for reason in self.policy_admission.reasons
                )
            )
            if (
                self.plan is not None
                and not policy_invalid
                and not freshness_invalid
                and not trust_invalid
            ):
                raise ValueError("PipelineResult outcome=INVALID must have plan=None")
            if (
                self.audited_plan is not None
                and not policy_invalid
                and not freshness_invalid
                and not trust_invalid
            ):
                raise ValueError("PipelineResult outcome=INVALID must have audited_plan=None")
            if self.gate_decision is not None:
                raise ValueError("PipelineResult outcome=INVALID must have gate_decision=None")
            if self.policy_admission.admission_allowed:
                raise ValueError("PipelineResult outcome=INVALID must not include approval")
        elif self.outcome == PipelineOutcome.ERROR:
            gate_allowed = self.gate_decision is not None and self.gate_decision.status == "allowed"
            if gate_allowed or self.policy_admission.admission_allowed:
                raise ValueError("PipelineResult outcome=ERROR must not include approval")
