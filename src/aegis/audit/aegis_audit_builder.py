"""Audit-v1 plan auditing: converts CommandPlan → AuditedPlan."""

from __future__ import annotations

from aegis.audit.aegis_checksum import plan_audit_id, plan_checksum
from aegis.contracts.aegis_audit import AuditedPlan
from aegis.contracts.aegis_planning import CommandPlan


def build_audited_plan(plan: CommandPlan) -> AuditedPlan:
    """Create a deterministic audit receipt for a command plan.

    This function is pure and deterministic: the same ``plan`` always produces
    the same ``AuditedPlan``.  It performs no I/O, no side-effects, no logging,
    no file writes, and no network calls.

    Args:
        plan: The command plan to audit.

    Returns:
        An immutable audit receipt containing the original plan, a deterministic
        SHA-256 checksum of the executable command steps, and a deterministic
        SHA-256 audit event identifier.
    """
    checksum = plan_checksum(plan)
    audit_id = plan_audit_id(plan, checksum)
    return AuditedPlan(plan=plan, audit_id=audit_id, checksum=checksum)
