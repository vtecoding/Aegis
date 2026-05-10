"""Build and verify null-backend dry-run receipts for ADR-0018."""

from __future__ import annotations

from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    BackendDryRunReceipt,
    RuntimeBackendContract,
    backend_dry_run_receipt_id,
    recompute_backend_certification_checksum,
    recompute_backend_dry_run_receipt_checksum,
    recompute_runtime_backend_descriptor_checksum,
    runtime_backend_observed_dispatch_items,
)
from aegis.contracts.runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchPlan,
    recompute_dispatch_firewall_decision_checksum,
    recompute_runtime_dispatch_plan_checksum,
)


def build_backend_dry_run_receipt(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    backend: RuntimeBackendContract,
    certification: BackendCertificationResult,
) -> BackendDryRunReceipt:
    """Build a receipt proving a certified null backend executed nothing."""
    _validate_receipt_inputs(plan, decision, backend, certification)
    observed_items = runtime_backend_observed_dispatch_items(plan.dispatch_items)
    receipt_id = backend_dry_run_receipt_id(
        dispatch_plan_checksum=plan.plan_checksum,
        firewall_decision_checksum=decision.decision_checksum,
        backend_certification_checksum=certification.certification_checksum,
    )
    return BackendDryRunReceipt(
        receipt_id=receipt_id,
        dispatch_plan_checksum=plan.plan_checksum,
        firewall_decision_checksum=decision.decision_checksum,
        backend_certification_checksum=certification.certification_checksum,
        backend_descriptor_checksum=backend.descriptor.descriptor_checksum,
        observed_dispatch_items=observed_items,
        executed_count=0,
        blocked_execution_count=len(observed_items),
    )


def is_backend_dry_run_receipt_valid(
    receipt: BackendDryRunReceipt,
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    backend: RuntimeBackendContract,
    certification: BackendCertificationResult,
) -> bool:
    """Return whether a backend dry-run receipt still binds to source evidence."""
    if receipt.executed_count != 0:
        return False
    if receipt.dispatch_plan_checksum != plan.plan_checksum:
        return False
    if receipt.firewall_decision_checksum != decision.decision_checksum:
        return False
    if receipt.backend_certification_checksum != certification.certification_checksum:
        return False
    if receipt.backend_descriptor_checksum != backend.descriptor.descriptor_checksum:
        return False
    if receipt.observed_dispatch_items != runtime_backend_observed_dispatch_items(
        plan.dispatch_items
    ):
        return False
    if receipt.blocked_execution_count != len(receipt.observed_dispatch_items):
        return False
    try:
        return receipt.receipt_checksum == recompute_backend_dry_run_receipt_checksum(receipt)
    except ValueError:
        return False


def _validate_receipt_inputs(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    backend: RuntimeBackendContract,
    certification: BackendCertificationResult,
) -> None:
    if certification.status is not BackendCertificationStatus.CERTIFIED_NULL:
        raise ValueError(BackendCertificationReason.BACKEND_FIREWALL_DECISION_NOT_ALLOWED.value)
    if certification.certification_checksum != recompute_backend_certification_checksum(
        certification
    ):
        raise ValueError(BackendCertificationReason.BACKEND_CERTIFICATION_CHECKSUM_DRIFT.value)
    if plan.plan_checksum != recompute_runtime_dispatch_plan_checksum(plan):
        raise ValueError(BackendCertificationReason.BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH.value)
    if decision.decision_checksum != recompute_dispatch_firewall_decision_checksum(decision):
        raise ValueError(
            BackendCertificationReason.BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH.value
        )
    if backend.descriptor.descriptor_checksum != recompute_runtime_backend_descriptor_checksum(
        backend.descriptor
    ):
        raise ValueError(BackendCertificationReason.BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH.value)
    if certification.dispatch_plan_checksum != plan.plan_checksum:
        raise ValueError(BackendCertificationReason.BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH.value)
    if certification.firewall_decision_checksum != decision.decision_checksum:
        raise ValueError(
            BackendCertificationReason.BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH.value
        )
    if certification.backend_descriptor_checksum != backend.descriptor.descriptor_checksum:
        raise ValueError(BackendCertificationReason.BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH.value)


__all__ = ["build_backend_dry_run_receipt", "is_backend_dry_run_receipt_valid"]
