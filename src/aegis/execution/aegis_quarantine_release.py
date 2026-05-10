"""Fail-closed quarantine release decisions for ADR-0022."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import COMMAND_QUARANTINE_CONTRACT_VERSION
from aegis.contracts.aegis_backend_replay import BackendReplayProofResult
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    RuntimeBackendDescriptor,
)
from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution.aegis_backend_admission import BackendAdmissionDecision
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease, checksum_or_fallback
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    CommandQuarantineReason,
    CommandQuarantineStatus,
    QuarantinedCommandItem,
    command_quarantine_evidence_drift_reason,
    quarantine_item_checksums,
    quarantine_items_from_dispatch_plan,
    recompute_command_quarantine_checksum,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease
from aegis.execution.aegis_operator_approval import (
    OperatorApprovalReceipt,
    OperatorApprovalStatus,
    approval_checksum_or_fallback,
    normalize_operator_id,
    recompute_operator_approval_checksum,
)

type QuarantineReleaseStatusValue = Literal["RELEASED_DRY_RUN", "BLOCKED"]
type CanonicalQuarantineReleaseValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalQuarantineReleaseValue]
    | dict[str, CanonicalQuarantineReleaseValue]
)

_FALLBACK_CHECKSUM = "0" * 64


class QuarantineReleaseStatus(StrEnum):
    """Closed ADR-0022 quarantine release statuses."""

    RELEASED_DRY_RUN = "RELEASED_DRY_RUN"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class _QuarantineReleaseAuthorization:
    """Internal proof object required to emit RELEASED_DRY_RUN decisions."""

    quarantine: CommandQuarantineEnvelope
    approval: OperatorApprovalReceipt
    lease: RuntimeCapabilityLease
    dispatch_plan: RuntimeDispatchPlan


@dataclass(frozen=True, slots=True, init=False)
class QuarantineReleaseDecision:
    """Checksum-bound release decision that remains dry-run and inert."""

    status: QuarantineReleaseStatusValue
    reason_code: str
    quarantine_checksum: str
    approval_checksum: str
    lease_checksum: str
    dispatch_plan_checksum: str
    released_item_count: int
    decision_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        quarantine_checksum: object,
        approval_checksum: object,
        lease_checksum: object,
        dispatch_plan_checksum: object,
        released_item_count: object,
        decision_checksum: str | None = None,
        authorization: object = None,
    ) -> None:
        normalized_status = _normalize_release_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_quarantine = _normalize_required_checksum(
            quarantine_checksum, "quarantine_checksum"
        )
        normalized_approval = _normalize_required_checksum(approval_checksum, "approval_checksum")
        normalized_lease = _normalize_required_checksum(lease_checksum, "lease_checksum")
        normalized_dispatch = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_count = _normalize_non_negative_int(released_item_count, "released_item_count")
        _validate_release_authorization(
            status=normalized_status,
            reason_code=normalized_reason,
            quarantine_checksum=normalized_quarantine,
            approval_checksum=normalized_approval,
            lease_checksum=normalized_lease,
            dispatch_plan_checksum=normalized_dispatch,
            released_item_count=normalized_count,
            authorization=authorization,
        )
        computed_checksum = quarantine_release_decision_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            quarantine_checksum=normalized_quarantine,
            approval_checksum=normalized_approval,
            lease_checksum=normalized_lease,
            dispatch_plan_checksum=normalized_dispatch,
            released_item_count=normalized_count,
        )
        normalized_checksum = _normalize_supplied_checksum(
            decision_checksum, computed_checksum, "decision_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "quarantine_checksum", normalized_quarantine)
        object.__setattr__(self, "approval_checksum", normalized_approval)
        object.__setattr__(self, "lease_checksum", normalized_lease)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_dispatch)
        object.__setattr__(self, "released_item_count", normalized_count)
        object.__setattr__(self, "decision_checksum", normalized_checksum)


def evaluate_quarantine_release(
    *,
    quarantine: object,
    approval: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> QuarantineReleaseDecision:
    """Return a deterministic fail-closed release decision for quarantined intent.

    The positive path releases only dry-run intent evidence. It does not execute, publish,
    queue, call ROS, contact a backend, or create runtime side effects.
    """
    reason = quarantine_release_block_reason(
        quarantine=quarantine,
        approval=approval,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if reason is not None:
        return _blocked_decision(
            reason=reason,
            quarantine=quarantine,
            approval=approval,
            capability_lease=capability_lease,
            dispatch_plan=dispatch_plan,
        )
    current_quarantine = cast(CommandQuarantineEnvelope, quarantine)
    current_approval = cast(OperatorApprovalReceipt, approval)
    lease = cast(RuntimeCapabilityLease, capability_lease)
    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    return QuarantineReleaseDecision(
        status="RELEASED_DRY_RUN",
        reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value,
        quarantine_checksum=current_quarantine.quarantine_checksum,
        approval_checksum=current_approval.approval_checksum,
        lease_checksum=lease.lease_checksum,
        dispatch_plan_checksum=plan.plan_checksum,
        released_item_count=len(current_quarantine.quarantined_items),
        authorization=_QuarantineReleaseAuthorization(
            quarantine=current_quarantine,
            approval=current_approval,
            lease=lease,
            dispatch_plan=plan,
        ),
    )


def quarantine_release_block_reason(
    *,
    quarantine: object,
    approval: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> CommandQuarantineReason | None:
    """Return the first deterministic reason a quarantine cannot be released."""
    source_reason = _source_shape_reason(
        quarantine=quarantine,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
    )
    if source_reason is not None:
        return source_reason
    current_quarantine = cast(CommandQuarantineEnvelope, quarantine)
    lease = cast(RuntimeCapabilityLease, capability_lease)
    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    admission = cast(BackendAdmissionDecision, backend_admission_decision)
    descriptor = cast(RuntimeBackendDescriptor, backend_descriptor)
    manifest = cast(BackendAuthorityManifest, authority_manifest)
    certification = cast(BackendCertificationResult, backend_certification)
    replay_proof = cast(BackendReplayProofResult, backend_replay_proof)
    firewall = cast(DispatchFirewallDecision, firewall_decision)
    quarantine_shape_reason = _quarantine_shape_reason(current_quarantine)
    if quarantine_shape_reason is not None:
        return quarantine_shape_reason
    if current_quarantine.quarantine_status is not CommandQuarantineStatus.QUARANTINED:
        return CommandQuarantineReason.COMMAND_QUARANTINE_STATUS_INVALID
    if current_quarantine.quarantine_checksum != recompute_command_quarantine_checksum(
        current_quarantine
    ):
        return CommandQuarantineReason.COMMAND_QUARANTINE_CHECKSUM_DRIFT
    item_reason = _quarantined_items_match_dispatch_plan(current_quarantine, plan)
    if item_reason is not None:
        return item_reason
    drift_reason = command_quarantine_evidence_drift_reason(
        quarantine=current_quarantine,
        dispatch_plan=plan,
        backend_admission_decision=admission,
        capability_lease=lease,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        context_authority_checksum=context_authority_checksum,
    )
    if drift_reason is not None:
        return drift_reason
    validation = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=firewall,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if validation.status != "VALID":
        if validation.reason_code == "CAPABILITY_LEASE_CHECKSUM_DRIFT":
            return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT
        if validation.status == "REVOKED":
            return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_REVOKED
        return CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_INVALID
    if approval is None:
        return CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL
    if type(approval) is not OperatorApprovalReceipt:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    current_approval = approval
    approval_shape_reason = _approval_shape_reason(current_approval)
    if approval_shape_reason is not None:
        return approval_shape_reason
    if current_approval.approval_checksum != recompute_operator_approval_checksum(current_approval):
        return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT
    if current_approval.quarantine_checksum != current_quarantine.quarantine_checksum:
        return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH
    if current_approval.approval_status is OperatorApprovalStatus.REJECTED:
        return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REJECTED
    if current_approval.approval_status is not OperatorApprovalStatus.APPROVED:
        return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID
    if current_approval.approval_epoch != current_quarantine.quarantine_epoch:
        return CommandQuarantineReason.COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH
    return _approval_scope_reason(current_quarantine, current_approval)


def quarantine_release_decision_checksum(
    *,
    status: QuarantineReleaseStatusValue,
    reason_code: str,
    quarantine_checksum: str,
    approval_checksum: str,
    lease_checksum: str,
    dispatch_plan_checksum: str,
    released_item_count: int,
) -> str:
    """Return the deterministic checksum for a quarantine release decision."""
    return _sha256(
        {
            "command_quarantine_contract_version": COMMAND_QUARANTINE_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "quarantine_checksum": quarantine_checksum,
            "approval_checksum": approval_checksum,
            "lease_checksum": lease_checksum,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "released_item_count": released_item_count,
        }
    )


def recompute_quarantine_release_decision_checksum(decision: QuarantineReleaseDecision) -> str:
    """Recompute a QuarantineReleaseDecision checksum from authoritative fields."""
    return quarantine_release_decision_checksum(
        status=decision.status,
        reason_code=decision.reason_code,
        quarantine_checksum=decision.quarantine_checksum,
        approval_checksum=decision.approval_checksum,
        lease_checksum=decision.lease_checksum,
        dispatch_plan_checksum=decision.dispatch_plan_checksum,
        released_item_count=decision.released_item_count,
    )


def _blocked_decision(
    *,
    reason: CommandQuarantineReason,
    quarantine: object,
    approval: object,
    capability_lease: object,
    dispatch_plan: object,
) -> QuarantineReleaseDecision:
    return QuarantineReleaseDecision(
        status="BLOCKED",
        reason_code=reason.value,
        quarantine_checksum=_quarantine_checksum_or_fallback(quarantine),
        approval_checksum=approval_checksum_or_fallback(approval),
        lease_checksum=_lease_checksum_or_fallback(capability_lease),
        dispatch_plan_checksum=_dispatch_plan_checksum_or_fallback(dispatch_plan),
        released_item_count=0,
    )


def _validate_release_authorization(
    *,
    status: QuarantineReleaseStatusValue,
    reason_code: str,
    quarantine_checksum: str,
    approval_checksum: str,
    lease_checksum: str,
    dispatch_plan_checksum: str,
    released_item_count: int,
    authorization: object,
) -> None:
    if status == "BLOCKED":
        if reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value:
            raise ValueError("BLOCKED decisions require a blocking reason")
        if released_item_count != 0:
            raise ValueError("BLOCKED decisions cannot release items")
        return
    if not isinstance(authorization, _QuarantineReleaseAuthorization):
        raise ValueError(CommandQuarantineReason.DIRECT_QUARANTINE_RELEASE_CONSTRUCTION.value)
    if reason_code != CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value:
        raise ValueError("RELEASED_DRY_RUN requires release reason")
    if quarantine_checksum != authorization.quarantine.quarantine_checksum:
        raise ValueError("RELEASED_DRY_RUN quarantine checksum must match authorization")
    if approval_checksum != authorization.approval.approval_checksum:
        raise ValueError("RELEASED_DRY_RUN approval checksum must match authorization")
    if lease_checksum != authorization.lease.lease_checksum:
        raise ValueError("RELEASED_DRY_RUN lease checksum must match authorization")
    if dispatch_plan_checksum != authorization.dispatch_plan.plan_checksum:
        raise ValueError("RELEASED_DRY_RUN dispatch checksum must match authorization")
    if released_item_count != len(authorization.quarantine.quarantined_items):
        raise ValueError("RELEASED_DRY_RUN released count must match quarantined items")


def _source_shape_reason(
    *,
    quarantine: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_manifest: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
) -> CommandQuarantineReason | None:
    if type(quarantine) is not CommandQuarantineEnvelope:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if type(capability_lease) is not RuntimeCapabilityLease:
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(dispatch_plan, RuntimeDispatchPlan):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_admission_decision, BackendAdmissionDecision):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(authority_manifest, BackendAuthorityManifest):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_certification, BackendCertificationResult):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_replay_proof, BackendReplayProofResult):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not isinstance(firewall_decision, DispatchFirewallDecision):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    return None


def _quarantine_shape_reason(
    quarantine: CommandQuarantineEnvelope,
) -> CommandQuarantineReason | None:
    quarantined_items = cast(object, quarantine.quarantined_items)
    if not isinstance(quarantined_items, tuple):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    item_values = cast(tuple[object, ...], quarantined_items)
    seen: set[str] = set()
    for item in item_values:
        if type(item) is not QuarantinedCommandItem:
            return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
        if item.item_checksum in seen:
            return CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION
        seen.add(item.item_checksum)
    if not seen:
        return CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION
    return None


def _approval_shape_reason(approval: OperatorApprovalReceipt) -> CommandQuarantineReason | None:
    try:
        normalize_operator_id(approval.operator_id)
    except ValueError:
        return CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED
    approved_scope = cast(object, approval.approved_scope)
    if not isinstance(approved_scope, frozenset):
        return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    scope_values = cast(frozenset[object], approved_scope)
    for scope_item in scope_values:
        if callable(scope_item):
            return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
        if scope_item == "*":
            return CommandQuarantineReason.COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE
        if checksum_or_fallback(scope_item) != scope_item:
            return CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION
    if not scope_values:
        return CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY
    return None


def _approval_scope_reason(
    quarantine: CommandQuarantineEnvelope,
    approval: OperatorApprovalReceipt,
) -> CommandQuarantineReason | None:
    quarantine_scope = quarantine_item_checksums(quarantine)
    if "*" in approval.approved_scope:
        return CommandQuarantineReason.COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE
    if not approval.approved_scope.issubset(quarantine_scope):
        return CommandQuarantineReason.COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE
    if approval.approved_scope != quarantine_scope:
        return CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION
    return None


def _quarantined_items_match_dispatch_plan(
    quarantine: CommandQuarantineEnvelope,
    dispatch_plan: RuntimeDispatchPlan,
) -> CommandQuarantineReason | None:
    expected = quarantine_items_from_dispatch_plan(dispatch_plan)
    expected_scope = frozenset(item.item_checksum for item in expected)
    actual_scope = quarantine_item_checksums(quarantine)
    if len(expected) != len(quarantine.quarantined_items) or actual_scope != expected_scope:
        return CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION
    return None


def _quarantine_checksum_or_fallback(value: object) -> str:
    if type(value) is CommandQuarantineEnvelope:
        return checksum_or_fallback(value.quarantine_checksum)
    return checksum_or_fallback(getattr(value, "quarantine_checksum", None))


def _lease_checksum_or_fallback(value: object) -> str:
    if type(value) is RuntimeCapabilityLease:
        return checksum_or_fallback(value.lease_checksum)
    return checksum_or_fallback(getattr(value, "lease_checksum", None))


def _dispatch_plan_checksum_or_fallback(value: object) -> str:
    if isinstance(value, RuntimeDispatchPlan):
        return checksum_or_fallback(value.plan_checksum)
    return checksum_or_fallback(getattr(value, "plan_checksum", None))


def _normalize_release_status(value: object) -> QuarantineReleaseStatusValue:
    if value in {"RELEASED_DRY_RUN", "BLOCKED"}:
        return cast(QuarantineReleaseStatusValue, value)
    raise ValueError("status must be RELEASED_DRY_RUN or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(f"{field_name} must not be callable")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if checksum_or_fallback(normalized) != normalized:
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied_checksum, field_name)
    if normalized is None:
        return computed_checksum
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _sha256(payload: Mapping[str, CanonicalQuarantineReleaseValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalQuarantineReleaseValue],
) -> dict[str, CanonicalQuarantineReleaseValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalQuarantineReleaseValue) -> CanonicalQuarantineReleaseValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalQuarantineReleaseValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "QuarantineReleaseDecision",
    "QuarantineReleaseStatus",
    "QuarantineReleaseStatusValue",
    "evaluate_quarantine_release",
    "quarantine_release_block_reason",
    "quarantine_release_decision_checksum",
    "recompute_quarantine_release_decision_checksum",
]
