"""Gate-v1 deterministic approval boundary for audited plans."""

from __future__ import annotations

from aegis.audit.checksum import plan_audit_id, plan_checksum
from aegis.contracts.audit import AuditedPlan
from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.planning import CommandPlan


def gate_audited_plan(audited_plan: AuditedPlan) -> GateDecision:
    """Verify an audited plan before future execution layers.

    Gate-v1 is a pure integrity boundary. It recomputes the audit-v1 checksum
    and audit ID from the supplied audited plan, compares those values with the
    stored receipt fields, and returns a deterministic allow/block decision. It
    performs no execution, simulation, persistence, logging, I/O, or authority
    creation.

    Args:
        audited_plan: The audited plan receipt to verify.

    Returns:
        A deterministic immutable ``GateDecision``.
    """
    return _decide_audited_plan(audited_plan)


def _decide_audited_plan(audited_plan: object) -> GateDecision:
    if not isinstance(audited_plan, AuditedPlan):
        return _malformed_decision(audit_id=None, plan_id=None)

    fields = _audited_plan_fields_or_none(audited_plan)
    if fields is None:
        return _malformed_decision(audit_id=None, plan_id=None)
    raw_plan, raw_audit_id, raw_checksum = fields

    audit_id = _text_identifier_or_none(raw_audit_id)
    checksum = _text_identifier_or_none(raw_checksum)

    if not isinstance(raw_plan, CommandPlan):
        return _malformed_decision(audit_id=audit_id, plan_id=None)

    plan_id = _text_identifier_or_none(raw_plan.plan_id)
    if audit_id is None or checksum is None or plan_id is None:
        return _malformed_decision(audit_id=audit_id, plan_id=plan_id)

    expected_values = _recompute_audit_values(raw_plan)
    if expected_values is None:
        return _malformed_decision(audit_id=audit_id, plan_id=plan_id)

    expected_checksum, expected_audit_id = expected_values
    checksum_verified = checksum == expected_checksum
    audit_id_verified = audit_id == expected_audit_id

    if checksum_verified and audit_id_verified:
        return GateDecision(
            status=GateDecisionStatus.ALLOWED,
            audit_id=audit_id,
            plan_id=plan_id,
            reasons=(),
            checksum_verified=True,
            audit_id_verified=True,
        )

    reasons: list[GateBlockReason] = []
    if not checksum_verified:
        reasons.append(GateBlockReason.CHECKSUM_MISMATCH)
    if not audit_id_verified:
        reasons.append(GateBlockReason.AUDIT_ID_MISMATCH)

    return GateDecision(
        status=GateDecisionStatus.BLOCKED,
        audit_id=audit_id,
        plan_id=plan_id,
        reasons=tuple(reasons),
        checksum_verified=checksum_verified,
        audit_id_verified=audit_id_verified,
    )


def _recompute_audit_values(plan: CommandPlan) -> tuple[str, str] | None:
    try:
        expected_checksum = plan_checksum(plan)
        expected_audit_id = plan_audit_id(plan, expected_checksum)
    except (AttributeError, KeyError, RecursionError, TypeError):
        return None
    return expected_checksum, expected_audit_id


def _audited_plan_fields_or_none(audited_plan: AuditedPlan) -> tuple[object, object, object] | None:
    try:
        return audited_plan.plan, audited_plan.audit_id, audited_plan.checksum
    except AttributeError:
        return None


def _malformed_decision(audit_id: str | None, plan_id: str | None) -> GateDecision:
    return GateDecision(
        status=GateDecisionStatus.BLOCKED,
        audit_id=audit_id,
        plan_id=plan_id,
        reasons=(GateBlockReason.MALFORMED_AUDITED_PLAN,),
        checksum_verified=False,
        audit_id_verified=False,
    )


def _text_identifier_or_none(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped_value = value.strip()
    if stripped_value == "":
        return None
    return stripped_value
