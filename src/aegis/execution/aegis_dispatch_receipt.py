"""Dry-run dispatch receipts for ADR-0017 firewall decisions."""

from __future__ import annotations

from aegis.contracts.aegis_runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchPlan,
    RuntimeDispatchReceipt,
)


def build_runtime_dispatch_receipt(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
) -> RuntimeDispatchReceipt:
    """Build a dry-run receipt for a runtime dispatch firewall decision."""
    return RuntimeDispatchReceipt(
        status=decision.status,
        reason_code=decision.reason_code,
        plan_checksum=plan.plan_checksum,
        source_envelope_checksum=plan.source_envelope_checksum,
        source_replay_proof_checksum=decision.source_replay_proof_checksum,
        decision_checksum=decision.decision_checksum,
        dispatch_mode=plan.dispatch_mode,
    )


__all__ = ["build_runtime_dispatch_receipt"]
