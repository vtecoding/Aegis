"""Proof harness for deterministic backend replay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from aegis.contracts.backend_replay import (
    BackendReplayProfile,
    BackendReplayProofResult,
    BackendReplayReason,
    BackendReplayRequest,
)
from aegis.contracts.runtime_backend import (
    BackendCertificationResult,
    BackendCertificationStatus,
    BackendDryRunReceipt,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
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
from aegis.execution.backend_receipt import is_backend_dry_run_receipt_valid
from aegis.execution.backend_replay import BackendReplayOutput, replay_runtime_backend
from aegis.execution.null_runtime_backend import NullRuntimeBackend, build_null_runtime_backend
from aegis.execution.runtime_backend import (
    dispatch_plan_capability_scope,
    dispatch_plan_runtime_kind_scope,
)

_FALLBACK_CHECKSUM = "0" * 64


def prove_backend_replay(request: BackendReplayRequest) -> BackendReplayProofResult:
    """Prove whether backend certification and receipt evidence exactly replay."""
    plan_object = _object_field(request, "dispatch_plan")
    decision_object = _object_field(request, "firewall_decision")
    descriptor_object = _object_field(request, "backend_descriptor")
    certification_object = _object_field(request, "expected_certification")
    receipt_object = _object_field(request, "expected_receipt")
    profile_object = _object_field(request, "replay_profile")

    if not isinstance(plan_object, RuntimeDispatchPlan):
        return _blocked_result(
            reason=BackendReplayReason.BACKEND_REPLAY_INVALID_DISPATCH_PLAN,
            failure_stage="dispatch_plan",
        )
    if not isinstance(decision_object, DispatchFirewallDecision):
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan_object.plan_checksum),
            reason=BackendReplayReason.BACKEND_REPLAY_INVALID_FIREWALL_DECISION,
            failure_stage="firewall_decision",
        )
    if not isinstance(descriptor_object, RuntimeBackendDescriptor):
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan_object.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(decision_object.decision_checksum),
            reason=BackendReplayReason.BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION,
            failure_stage="backend_descriptor",
        )
    if not isinstance(certification_object, BackendCertificationResult):
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan_object.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(decision_object.decision_checksum),
            backend_descriptor_checksum=_checksum_or_fallback(
                descriptor_object.descriptor_checksum
            ),
            reason=BackendReplayReason.BACKEND_REPLAY_INVALID_CERTIFICATION,
            failure_stage="certification",
        )
    if not isinstance(receipt_object, BackendDryRunReceipt):
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan_object.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(decision_object.decision_checksum),
            backend_descriptor_checksum=_checksum_or_fallback(
                descriptor_object.descriptor_checksum
            ),
            expected_certification_checksum=_checksum_or_fallback(
                certification_object.certification_checksum
            ),
            reason=BackendReplayReason.BACKEND_REPLAY_INVALID_RECEIPT,
            failure_stage="receipt",
        )
    if profile_object is not BackendReplayProfile.STRICT_BACKEND_REPLAY_V1:
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan_object.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(decision_object.decision_checksum),
            backend_descriptor_checksum=_checksum_or_fallback(
                descriptor_object.descriptor_checksum
            ),
            expected_certification_checksum=_checksum_or_fallback(
                certification_object.certification_checksum
            ),
            expected_receipt_checksum=_checksum_or_fallback(receipt_object.receipt_checksum),
            reason=BackendReplayReason.BACKEND_REPLAY_INVALID_PROFILE,
            failure_stage="replay_profile",
        )

    plan = plan_object
    decision = decision_object
    descriptor = descriptor_object
    expected_certification = certification_object
    expected_receipt = receipt_object

    source_block = _source_block_reason(plan, decision, descriptor)
    if source_block is not None:
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(plan.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(decision.decision_checksum),
            backend_descriptor_checksum=_checksum_or_fallback(descriptor.descriptor_checksum),
            expected_certification_checksum=_checksum_or_fallback(
                expected_certification.certification_checksum
            ),
            expected_receipt_checksum=_checksum_or_fallback(expected_receipt.receipt_checksum),
            reason=source_block.reason,
            failure_stage=source_block.stage,
        )
    if expected_certification.status is not BackendCertificationStatus.CERTIFIED_NULL:
        return _blocked_result(
            dispatch_plan_checksum=plan.plan_checksum,
            firewall_decision_checksum=decision.decision_checksum,
            backend_descriptor_checksum=descriptor.descriptor_checksum,
            expected_certification_checksum=expected_certification.certification_checksum,
            expected_receipt_checksum=expected_receipt.receipt_checksum,
            reason=BackendReplayReason.BACKEND_REPLAY_EXPECTED_CERTIFICATION_NOT_CERTIFIED_NULL,
            failure_stage="certification",
        )

    replayed = _replay_or_block(request)
    if isinstance(replayed, BackendReplayProofResult):
        return replayed

    replayed_certification = replayed.certification
    replayed_receipt = replayed.receipt
    backend = NullRuntimeBackend(descriptor=descriptor)
    scope_match = _scope_matches(plan, descriptor)
    zero_execution_verified = (
        expected_receipt.executed_count == 0 and replayed_receipt.executed_count == 0
    )
    certification_match = expected_certification == replayed_certification
    receipt_match = expected_receipt == replayed_receipt and is_backend_dry_run_receipt_valid(
        expected_receipt,
        plan,
        decision,
        backend,
        expected_certification,
    )
    if certification_match and receipt_match and zero_execution_verified and scope_match:
        return BackendReplayProofResult(
            status="PASSED",
            reason_code=BackendReplayReason.BACKEND_REPLAY_PASSED.value,
            dispatch_plan_checksum=plan.plan_checksum,
            firewall_decision_checksum=decision.decision_checksum,
            backend_descriptor_checksum=descriptor.descriptor_checksum,
            expected_certification_checksum=expected_certification.certification_checksum,
            replayed_certification_checksum=replayed_certification.certification_checksum,
            expected_receipt_checksum=expected_receipt.receipt_checksum,
            replayed_receipt_checksum=replayed_receipt.receipt_checksum,
            zero_execution_verified=True,
            scope_match_verified=True,
            certification_match=True,
            receipt_match=True,
            mutation_detected=False,
            failure_stage=None,
        )
    return BackendReplayProofResult(
        status="FAILED",
        reason_code=_failure_reason(
            plan=plan,
            decision=decision,
            descriptor=descriptor,
            expected_certification=expected_certification,
            expected_receipt=expected_receipt,
            certification_match=certification_match,
            receipt_match=receipt_match,
            zero_execution_verified=zero_execution_verified,
        ).value,
        dispatch_plan_checksum=plan.plan_checksum,
        firewall_decision_checksum=decision.decision_checksum,
        backend_descriptor_checksum=descriptor.descriptor_checksum,
        expected_certification_checksum=expected_certification.certification_checksum,
        replayed_certification_checksum=replayed_certification.certification_checksum,
        expected_receipt_checksum=expected_receipt.receipt_checksum,
        replayed_receipt_checksum=replayed_receipt.receipt_checksum,
        zero_execution_verified=zero_execution_verified,
        scope_match_verified=scope_match,
        certification_match=certification_match,
        receipt_match=receipt_match,
        mutation_detected=True,
        failure_stage=_failure_stage(
            certification_match=certification_match,
            receipt_match=receipt_match,
            zero_execution_verified=zero_execution_verified,
        ),
    )


def _replay_or_block(
    request: BackendReplayRequest,
) -> BackendReplayOutput | BackendReplayProofResult:
    try:
        return replay_runtime_backend(request)
    except ValueError:
        return _blocked_result(
            dispatch_plan_checksum=_checksum_or_fallback(request.dispatch_plan.plan_checksum),
            firewall_decision_checksum=_checksum_or_fallback(
                request.firewall_decision.decision_checksum
            ),
            backend_descriptor_checksum=_checksum_or_fallback(
                request.backend_descriptor.descriptor_checksum
            ),
            expected_certification_checksum=_checksum_or_fallback(
                request.expected_certification.certification_checksum
            ),
            expected_receipt_checksum=_checksum_or_fallback(
                request.expected_receipt.receipt_checksum
            ),
            reason=BackendReplayReason.BACKEND_REPLAY_REPLAY_BLOCKED,
            failure_stage="backend_replay",
        )


def _failure_reason(
    *,
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    descriptor: RuntimeBackendDescriptor,
    expected_certification: BackendCertificationResult,
    expected_receipt: BackendDryRunReceipt,
    certification_match: bool,
    receipt_match: bool,
    zero_execution_verified: bool,
) -> BackendReplayReason:
    certification_reason = _certification_failure_reason(
        plan,
        decision,
        descriptor,
        expected_certification,
    )
    if certification_reason is not None:
        return certification_reason
    receipt_reason = _receipt_failure_reason(
        plan, decision, descriptor, expected_certification, expected_receipt
    )
    if receipt_reason is not None:
        return receipt_reason
    if not zero_execution_verified:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO
    if not certification_match:
        return BackendReplayReason.BACKEND_REPLAY_CERTIFICATION_MISMATCH
    if not receipt_match:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_MISMATCH
    return BackendReplayReason.BACKEND_REPLAY_REPLAY_BLOCKED


def _certification_failure_reason(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    descriptor: RuntimeBackendDescriptor,
    expected_certification: BackendCertificationResult,
) -> BackendReplayReason | None:
    if not _certification_checksum_matches(expected_certification):
        return BackendReplayReason.BACKEND_REPLAY_CERTIFICATION_CHECKSUM_DRIFT
    if expected_certification.dispatch_plan_checksum != plan.plan_checksum:
        return BackendReplayReason.BACKEND_REPLAY_CERTIFICATION_DISPATCH_PLAN_MISMATCH
    if expected_certification.firewall_decision_checksum != decision.decision_checksum:
        return BackendReplayReason.BACKEND_REPLAY_CERTIFICATION_FIREWALL_DECISION_MISMATCH
    if expected_certification.backend_descriptor_checksum != descriptor.descriptor_checksum:
        return BackendReplayReason.BACKEND_REPLAY_CERTIFICATION_DESCRIPTOR_MISMATCH
    return None


def _receipt_failure_reason(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    descriptor: RuntimeBackendDescriptor,
    expected_certification: BackendCertificationResult,
    expected_receipt: BackendDryRunReceipt,
) -> BackendReplayReason | None:
    if expected_receipt.executed_count != 0:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO
    if expected_receipt.dispatch_plan_checksum != plan.plan_checksum:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_PLAN_MISMATCH
    if expected_receipt.firewall_decision_checksum != decision.decision_checksum:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_FIREWALL_DECISION_MISMATCH
    if (
        expected_receipt.backend_certification_checksum
        != expected_certification.certification_checksum
    ):
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_CERTIFICATION_MISMATCH
    if expected_receipt.backend_descriptor_checksum != descriptor.descriptor_checksum:
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_BACKEND_DESCRIPTOR_MISMATCH
    if expected_receipt.observed_dispatch_items != runtime_backend_observed_dispatch_items(
        plan.dispatch_items
    ):
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT
    if expected_receipt.blocked_execution_count != len(expected_receipt.observed_dispatch_items):
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT
    if not _receipt_checksum_matches(expected_receipt):
        return BackendReplayReason.BACKEND_REPLAY_RECEIPT_CHECKSUM_DRIFT
    return None


def _failure_stage(
    *,
    certification_match: bool,
    receipt_match: bool,
    zero_execution_verified: bool,
) -> str:
    if not zero_execution_verified:
        return "receipt"
    if not certification_match:
        return "certification"
    if not receipt_match:
        return "receipt"
    return "backend_replay_proof"


@dataclass(frozen=True, slots=True)
class _SourceBlockReason:
    reason: BackendReplayReason
    stage: str


def _source_block_reason(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    descriptor: RuntimeBackendDescriptor,
) -> _SourceBlockReason | None:
    if not _plan_checksum_matches(plan):
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_DISPATCH_PLAN_CHECKSUM_DRIFT,
            "dispatch_plan",
        )
    if decision.status != "ALLOWED_DRY_RUN":
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_FIREWALL_DECISION_NOT_ALLOWED,
            "firewall_decision",
        )
    if decision.plan_checksum != plan.plan_checksum:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_FIREWALL_PLAN_MISMATCH,
            "firewall_decision",
        )
    if not _firewall_decision_checksum_matches(decision):
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_FIREWALL_DECISION_CHECKSUM_DRIFT,
            "firewall_decision",
        )
    if not _descriptor_checksum_matches(descriptor):
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_DESCRIPTOR_CHECKSUM_DRIFT,
            "backend_descriptor",
        )
    if descriptor.backend_kind is not RuntimeBackendKind.NULL_BACKEND_V1:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_BACKEND_KIND_NOT_NULL,
            "backend_descriptor",
        )
    if descriptor.backend_mode is not RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY,
            "backend_descriptor",
        )
    if descriptor.allows_execution is not False:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_EXECUTION_CAPABILITY_CLAIMED,
            "backend_descriptor",
        )
    if descriptor.allows_io is not False:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_IO_CAPABILITY_CLAIMED,
            "backend_descriptor",
        )
    if descriptor.allows_async is not False:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_ASYNC_CAPABILITY_CLAIMED,
            "backend_descriptor",
        )
    if descriptor.supported_capabilities != dispatch_plan_capability_scope(plan):
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_CAPABILITY_SCOPE_DRIFT,
            "backend_descriptor",
        )
    if descriptor.supported_runtime_kinds != dispatch_plan_runtime_kind_scope(plan):
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_RUNTIME_KIND_SCOPE_DRIFT,
            "backend_descriptor",
        )
    if descriptor != build_null_runtime_backend(plan).descriptor:
        return _SourceBlockReason(
            BackendReplayReason.BACKEND_REPLAY_DESCRIPTOR_SHAPE_MISMATCH,
            "backend_descriptor",
        )
    return None


def _scope_matches(plan: RuntimeDispatchPlan, descriptor: RuntimeBackendDescriptor) -> bool:
    return descriptor.supported_capabilities == dispatch_plan_capability_scope(
        plan
    ) and descriptor.supported_runtime_kinds == dispatch_plan_runtime_kind_scope(plan)


def _plan_checksum_matches(plan: RuntimeDispatchPlan) -> bool:
    try:
        return plan.plan_checksum == recompute_runtime_dispatch_plan_checksum(plan)
    except ValueError:
        return False


def _firewall_decision_checksum_matches(decision: DispatchFirewallDecision) -> bool:
    try:
        return decision.decision_checksum == recompute_dispatch_firewall_decision_checksum(decision)
    except ValueError:
        return False


def _descriptor_checksum_matches(descriptor: RuntimeBackendDescriptor) -> bool:
    try:
        return descriptor.descriptor_checksum == recompute_runtime_backend_descriptor_checksum(
            descriptor
        )
    except ValueError:
        return False


def _certification_checksum_matches(certification: BackendCertificationResult) -> bool:
    try:
        return certification.certification_checksum == recompute_backend_certification_checksum(
            certification
        )
    except ValueError:
        return False


def _receipt_checksum_matches(receipt: BackendDryRunReceipt) -> bool:
    try:
        return receipt.receipt_checksum == recompute_backend_dry_run_receipt_checksum(receipt)
    except ValueError:
        return False


def _blocked_result(
    *,
    reason: BackendReplayReason,
    failure_stage: str,
    dispatch_plan_checksum: str = _FALLBACK_CHECKSUM,
    firewall_decision_checksum: str = _FALLBACK_CHECKSUM,
    backend_descriptor_checksum: str = _FALLBACK_CHECKSUM,
    expected_certification_checksum: str = _FALLBACK_CHECKSUM,
    expected_receipt_checksum: str = _FALLBACK_CHECKSUM,
) -> BackendReplayProofResult:
    return BackendReplayProofResult(
        status="BLOCKED",
        reason_code=reason.value,
        dispatch_plan_checksum=dispatch_plan_checksum,
        firewall_decision_checksum=firewall_decision_checksum,
        backend_descriptor_checksum=backend_descriptor_checksum,
        expected_certification_checksum=expected_certification_checksum,
        replayed_certification_checksum=None,
        expected_receipt_checksum=expected_receipt_checksum,
        replayed_receipt_checksum=None,
        zero_execution_verified=False,
        scope_match_verified=False,
        certification_match=False,
        receipt_match=False,
        mutation_detected=False,
        failure_stage=failure_stage,
    )


def _checksum_or_fallback(value: object) -> str:
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return _FALLBACK_CHECKSUM


def _object_field(instance: object, field_name: str) -> object:
    return cast(object, getattr(instance, field_name))


__all__ = ["prove_backend_replay"]
