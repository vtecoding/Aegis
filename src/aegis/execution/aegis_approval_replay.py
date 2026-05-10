"""Authority-bound approval receipts and replay validation for ADR-0023."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.aegis_constants import OPERATOR_AUTHORITY_CONTRACT_VERSION
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
    command_quarantine_evidence_drift_reason,
    quarantine_item_checksums,
    quarantine_items_from_dispatch_plan,
    recompute_command_quarantine_checksum,
)
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease
from aegis.execution.aegis_operator_approval import OperatorApprovalStatus
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityManifest,
    OperatorAuthorityReason,
    normalize_operator_approval_scopes,
    operator_authority_manifest_checksum_or_fallback,
    recompute_operator_authority_manifest_checksum,
)
from aegis.execution.aegis_operator_identity import (
    OperatorApprovalNonce,
    OperatorIdentityClaim,
    operator_identity_checksum_or_fallback,
    operator_nonce_checksum_or_fallback,
    recompute_operator_approval_nonce_checksum,
    recompute_operator_identity_claim_checksum,
)

type AuthorityBoundApprovalStatusValue = Literal["APPROVED", "REJECTED"]
type ApprovalReplayStatusValue = Literal["VALID", "BLOCKED"]
type CanonicalApprovalReplayValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalApprovalReplayValue]
    | dict[str, CanonicalApprovalReplayValue]
)

_AUTHORITY_APPROVAL_CONSTRUCTION_TOKEN = object()
_APPROVAL_REPLAY_VALIDATION_TOKEN = object()


class ApprovalReplayStatus(StrEnum):
    """Closed ADR-0023 approval replay validation statuses."""

    VALID = "VALID"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True, init=False)
class AuthorityBoundApprovalReceipt:
    """Checksum-bound approval receipt tied to authority, identity, nonce, and quarantine."""

    approval_id: str
    approval_status: OperatorApprovalStatus
    quarantine_checksum: str
    operator_identity_checksum: str
    operator_authority_manifest_checksum: str
    approval_nonce_checksum: str
    approved_scope: frozenset[str]
    approval_epoch: int
    authority_bound_checksum: str

    def __init__(
        self,
        *,
        approval_id: object,
        approval_status: object,
        quarantine_checksum: object,
        operator_identity_checksum: object,
        operator_authority_manifest_checksum: object,
        approval_nonce_checksum: object,
        approved_scope: Iterable[object],
        approval_epoch: object,
        authority_bound_checksum: str | None = None,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _AUTHORITY_APPROVAL_CONSTRUCTION_TOKEN:
            raise ValueError(
                OperatorAuthorityReason.DIRECT_AUTHORITY_BOUND_APPROVAL_CONSTRUCTION.value
            )
        normalized_id = _normalize_required_checksum(approval_id, "approval_id")
        normalized_status = _normalize_approval_status(approval_status)
        normalized_quarantine = _normalize_required_checksum(
            quarantine_checksum, "quarantine_checksum"
        )
        normalized_identity = _normalize_required_checksum(
            operator_identity_checksum, "operator_identity_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            operator_authority_manifest_checksum, "operator_authority_manifest_checksum"
        )
        normalized_nonce = _normalize_required_checksum(
            approval_nonce_checksum, "approval_nonce_checksum"
        )
        normalized_scope = normalize_operator_approval_scopes(approved_scope)
        normalized_epoch = _normalize_non_negative_int(approval_epoch, "approval_epoch")
        computed_checksum = authority_bound_approval_receipt_checksum(
            approval_id=normalized_id,
            approval_status=normalized_status,
            quarantine_checksum=normalized_quarantine,
            operator_identity_checksum=normalized_identity,
            operator_authority_manifest_checksum=normalized_manifest,
            approval_nonce_checksum=normalized_nonce,
            approved_scope=normalized_scope,
            approval_epoch=normalized_epoch,
        )
        normalized_checksum = _normalize_supplied_checksum(
            authority_bound_checksum, computed_checksum, "authority_bound_checksum"
        )

        object.__setattr__(self, "approval_id", normalized_id)
        object.__setattr__(self, "approval_status", normalized_status)
        object.__setattr__(self, "quarantine_checksum", normalized_quarantine)
        object.__setattr__(self, "operator_identity_checksum", normalized_identity)
        object.__setattr__(self, "operator_authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "approval_nonce_checksum", normalized_nonce)
        object.__setattr__(self, "approved_scope", normalized_scope)
        object.__setattr__(self, "approval_epoch", normalized_epoch)
        object.__setattr__(self, "authority_bound_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class ApprovalReplayValidationResult:
    """Checksum-bound result proving one approval receipt is replay-valid or blocked."""

    status: ApprovalReplayStatusValue
    reason_code: str
    approval_checksum: str
    quarantine_checksum: str
    operator_identity_checksum: str
    authority_manifest_checksum: str
    nonce_checksum: str
    context_authority_checksum: str
    replay_validation_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        approval_checksum: object,
        quarantine_checksum: object,
        operator_identity_checksum: object,
        authority_manifest_checksum: object,
        nonce_checksum: object,
        context_authority_checksum: object,
        replay_validation_checksum: str | None = None,
        _validation_token: object | None = None,
    ) -> None:
        normalized_status = _normalize_replay_status(status)
        normalized_reason = _normalize_reason_code(reason_code)
        if (
            normalized_status == "VALID"
            and _validation_token is not _APPROVAL_REPLAY_VALIDATION_TOKEN
        ):
            raise ValueError(
                OperatorAuthorityReason.DIRECT_APPROVAL_REPLAY_VALIDATION_CONSTRUCTION.value
            )
        if normalized_status == "VALID" and normalized_reason != (
            OperatorAuthorityReason.OPERATOR_AUTHORITY_REPLAY_VALID.value
        ):
            raise ValueError("VALID approval replay requires OPERATOR_AUTHORITY_REPLAY_VALID")
        if normalized_status == "BLOCKED" and normalized_reason == (
            OperatorAuthorityReason.OPERATOR_AUTHORITY_REPLAY_VALID.value
        ):
            raise ValueError("BLOCKED approval replay requires a blocking reason")
        normalized_approval = _normalize_required_checksum(approval_checksum, "approval_checksum")
        normalized_quarantine = _normalize_required_checksum(
            quarantine_checksum, "quarantine_checksum"
        )
        normalized_identity = _normalize_required_checksum(
            operator_identity_checksum, "operator_identity_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            authority_manifest_checksum, "authority_manifest_checksum"
        )
        normalized_nonce = _normalize_required_checksum(nonce_checksum, "nonce_checksum")
        normalized_context = _normalize_required_checksum(
            context_authority_checksum, "context_authority_checksum"
        )
        computed_checksum = approval_replay_validation_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            approval_checksum=normalized_approval,
            quarantine_checksum=normalized_quarantine,
            operator_identity_checksum=normalized_identity,
            authority_manifest_checksum=normalized_manifest,
            nonce_checksum=normalized_nonce,
            context_authority_checksum=normalized_context,
        )
        normalized_checksum = _normalize_supplied_checksum(
            replay_validation_checksum, computed_checksum, "replay_validation_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "approval_checksum", normalized_approval)
        object.__setattr__(self, "quarantine_checksum", normalized_quarantine)
        object.__setattr__(self, "operator_identity_checksum", normalized_identity)
        object.__setattr__(self, "authority_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "nonce_checksum", normalized_nonce)
        object.__setattr__(self, "context_authority_checksum", normalized_context)
        object.__setattr__(self, "replay_validation_checksum", normalized_checksum)


def build_authority_bound_approval_receipt(
    *,
    quarantine: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    approval_status: object,
    approved_scope: Iterable[object],
) -> AuthorityBoundApprovalReceipt:
    """Build an authority-bound structural approval or rejection receipt."""
    reason = _approval_build_block_reason(
        quarantine=quarantine,
        operator_identity=operator_identity,
        authority_manifest=authority_manifest,
        approval_nonce=approval_nonce,
        approved_scope=approved_scope,
    )
    if reason is not None:
        raise ValueError(reason.value)
    current_quarantine = cast(CommandQuarantineEnvelope, quarantine)
    current_identity = cast(OperatorIdentityClaim, operator_identity)
    current_manifest = cast(OperatorAuthorityManifest, authority_manifest)
    current_nonce = cast(OperatorApprovalNonce, approval_nonce)
    normalized_status = _normalize_approval_status(approval_status)
    normalized_scope = normalize_operator_approval_scopes(approved_scope)
    approval_id = authority_bound_approval_id(
        approval_status=normalized_status,
        quarantine_checksum=current_quarantine.quarantine_checksum,
        operator_identity_checksum=current_identity.identity_checksum,
        operator_authority_manifest_checksum=current_manifest.manifest_checksum,
        approval_nonce_checksum=current_nonce.nonce_checksum,
        approved_scope=normalized_scope,
        approval_epoch=current_quarantine.quarantine_epoch,
    )
    return AuthorityBoundApprovalReceipt(
        approval_id=approval_id,
        approval_status=normalized_status,
        quarantine_checksum=current_quarantine.quarantine_checksum,
        operator_identity_checksum=current_identity.identity_checksum,
        operator_authority_manifest_checksum=current_manifest.manifest_checksum,
        approval_nonce_checksum=current_nonce.nonce_checksum,
        approved_scope=normalized_scope,
        approval_epoch=current_quarantine.quarantine_epoch,
        _construction_token=_AUTHORITY_APPROVAL_CONSTRUCTION_TOKEN,
    )


def validate_approval_replay(
    *,
    quarantine: object,
    approval: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_backend_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> ApprovalReplayValidationResult:
    """Validate that an authority-bound approval is not replayed across evidence."""
    reason = approval_replay_block_reason(
        quarantine=quarantine,
        approval=approval,
        operator_identity=operator_identity,
        authority_manifest=authority_manifest,
        approval_nonce=approval_nonce,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_backend_manifest=authority_backend_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if reason is not None:
        return _blocked_result(
            reason=reason,
            approval=approval,
            quarantine=quarantine,
            operator_identity=operator_identity,
            authority_manifest=authority_manifest,
            approval_nonce=approval_nonce,
            context_authority_checksum=context_authority_checksum,
        )
    current_quarantine = cast(CommandQuarantineEnvelope, quarantine)
    current_approval = cast(AuthorityBoundApprovalReceipt, approval)
    current_identity = cast(OperatorIdentityClaim, operator_identity)
    current_manifest = cast(OperatorAuthorityManifest, authority_manifest)
    current_nonce = cast(OperatorApprovalNonce, approval_nonce)
    return ApprovalReplayValidationResult(
        status="VALID",
        reason_code=OperatorAuthorityReason.OPERATOR_AUTHORITY_REPLAY_VALID.value,
        approval_checksum=current_approval.authority_bound_checksum,
        quarantine_checksum=current_quarantine.quarantine_checksum,
        operator_identity_checksum=current_identity.identity_checksum,
        authority_manifest_checksum=current_manifest.manifest_checksum,
        nonce_checksum=current_nonce.nonce_checksum,
        context_authority_checksum=current_quarantine.context_authority_checksum,
        _validation_token=_APPROVAL_REPLAY_VALIDATION_TOKEN,
    )


def approval_replay_block_reason(
    *,
    quarantine: object,
    approval: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_backend_manifest: object,
    registry_checksum: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> OperatorAuthorityReason | None:
    """Return the first deterministic reason approval replay validation blocks."""
    source_reason = _source_shape_reason(
        quarantine=quarantine,
        approval=approval,
        operator_identity=operator_identity,
        authority_manifest=authority_manifest,
        approval_nonce=approval_nonce,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_backend_manifest=authority_backend_manifest,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
    )
    if source_reason is not None:
        return source_reason
    current_quarantine = cast(CommandQuarantineEnvelope, quarantine)
    current_approval = cast(AuthorityBoundApprovalReceipt, approval)
    current_identity = cast(OperatorIdentityClaim, operator_identity)
    current_manifest = cast(OperatorAuthorityManifest, authority_manifest)
    current_nonce = cast(OperatorApprovalNonce, approval_nonce)
    lease = cast(RuntimeCapabilityLease, capability_lease)
    plan = cast(RuntimeDispatchPlan, dispatch_plan)
    admission = cast(BackendAdmissionDecision, backend_admission_decision)
    descriptor = cast(RuntimeBackendDescriptor, backend_descriptor)
    backend_manifest = cast(BackendAuthorityManifest, authority_backend_manifest)
    certification = cast(BackendCertificationResult, backend_certification)
    replay_proof = cast(BackendReplayProofResult, backend_replay_proof)
    firewall = cast(DispatchFirewallDecision, firewall_decision)
    evidence_reason = _evidence_replay_reason(
        quarantine=current_quarantine,
        capability_lease=lease,
        dispatch_plan=plan,
        backend_admission_decision=admission,
        backend_descriptor=descriptor,
        authority_backend_manifest=backend_manifest,
        registry_checksum=registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        firewall_decision=firewall,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if evidence_reason is not None:
        return evidence_reason
    return _authority_replay_reason(
        quarantine=current_quarantine,
        approval=current_approval,
        operator_identity=current_identity,
        authority_manifest=current_manifest,
        approval_nonce=current_nonce,
        context_authority_checksum=context_authority_checksum,
    )


def authority_bound_approval_id(
    *,
    approval_status: OperatorApprovalStatus | str,
    quarantine_checksum: str,
    operator_identity_checksum: str,
    operator_authority_manifest_checksum: str,
    approval_nonce_checksum: str,
    approved_scope: Iterable[str],
    approval_epoch: int,
) -> str:
    """Return the deterministic identifier for an authority-bound approval receipt."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "approval_status": _approval_status_checksum_value(approval_status),
            "quarantine_checksum": quarantine_checksum,
            "operator_identity_checksum": operator_identity_checksum,
            "operator_authority_manifest_checksum": operator_authority_manifest_checksum,
            "approval_nonce_checksum": approval_nonce_checksum,
            "approved_scope": _canonical_string_sequence(sorted(approved_scope)),
            "approval_epoch": approval_epoch,
        }
    )


def authority_bound_approval_receipt_checksum(
    *,
    approval_id: str,
    approval_status: OperatorApprovalStatus | str,
    quarantine_checksum: str,
    operator_identity_checksum: str,
    operator_authority_manifest_checksum: str,
    approval_nonce_checksum: str,
    approved_scope: Iterable[str],
    approval_epoch: int,
) -> str:
    """Return the deterministic checksum for an authority-bound approval receipt."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "approval_id": approval_id,
            "approval_status": _approval_status_checksum_value(approval_status),
            "quarantine_checksum": quarantine_checksum,
            "operator_identity_checksum": operator_identity_checksum,
            "operator_authority_manifest_checksum": operator_authority_manifest_checksum,
            "approval_nonce_checksum": approval_nonce_checksum,
            "approved_scope": _canonical_string_sequence(sorted(approved_scope)),
            "approval_epoch": approval_epoch,
        }
    )


def recompute_authority_bound_approval_checksum(
    approval: AuthorityBoundApprovalReceipt,
) -> str:
    """Recompute an AuthorityBoundApprovalReceipt checksum from authoritative fields."""
    return authority_bound_approval_receipt_checksum(
        approval_id=approval.approval_id,
        approval_status=approval.approval_status,
        quarantine_checksum=approval.quarantine_checksum,
        operator_identity_checksum=approval.operator_identity_checksum,
        operator_authority_manifest_checksum=approval.operator_authority_manifest_checksum,
        approval_nonce_checksum=approval.approval_nonce_checksum,
        approved_scope=approval.approved_scope,
        approval_epoch=approval.approval_epoch,
    )


def approval_replay_validation_checksum(
    *,
    status: ApprovalReplayStatusValue,
    reason_code: str,
    approval_checksum: str,
    quarantine_checksum: str,
    operator_identity_checksum: str,
    authority_manifest_checksum: str,
    nonce_checksum: str,
    context_authority_checksum: str,
) -> str:
    """Return the deterministic checksum for an approval replay validation result."""
    return _sha256(
        {
            "operator_authority_contract_version": OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "approval_checksum": approval_checksum,
            "quarantine_checksum": quarantine_checksum,
            "operator_identity_checksum": operator_identity_checksum,
            "authority_manifest_checksum": authority_manifest_checksum,
            "nonce_checksum": nonce_checksum,
            "context_authority_checksum": context_authority_checksum,
        }
    )


def recompute_approval_replay_validation_checksum(
    result: ApprovalReplayValidationResult,
) -> str:
    """Recompute an ApprovalReplayValidationResult checksum from authoritative fields."""
    return approval_replay_validation_checksum(
        status=result.status,
        reason_code=result.reason_code,
        approval_checksum=result.approval_checksum,
        quarantine_checksum=result.quarantine_checksum,
        operator_identity_checksum=result.operator_identity_checksum,
        authority_manifest_checksum=result.authority_manifest_checksum,
        nonce_checksum=result.nonce_checksum,
        context_authority_checksum=result.context_authority_checksum,
    )


def authority_bound_approval_checksum_or_fallback(value: object) -> str:
    """Return a valid authority-bound approval checksum or the closed fallback checksum."""
    if type(value) is AuthorityBoundApprovalReceipt:
        return checksum_or_fallback(value.authority_bound_checksum)
    return checksum_or_fallback(getattr(value, "authority_bound_checksum", None))


def approval_replay_validation_checksum_or_fallback(value: object) -> str:
    """Return a valid replay validation checksum or the closed fallback checksum."""
    if type(value) is ApprovalReplayValidationResult:
        return checksum_or_fallback(value.replay_validation_checksum)
    return checksum_or_fallback(getattr(value, "replay_validation_checksum", None))


def _approval_build_block_reason(
    *,
    quarantine: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    approved_scope: Iterable[object],
) -> OperatorAuthorityReason | None:
    if type(quarantine) is not CommandQuarantineEnvelope:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(operator_identity) is not OperatorIdentityClaim:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(authority_manifest) is not OperatorAuthorityManifest:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST
    if type(approval_nonce) is not OperatorApprovalNonce:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    return _authority_replay_reason(
        quarantine=quarantine,
        approval=None,
        operator_identity=operator_identity,
        authority_manifest=authority_manifest,
        approval_nonce=approval_nonce,
        context_authority_checksum=quarantine.context_authority_checksum,
        approved_scope=approved_scope,
    )


def _source_shape_reason(
    *,
    quarantine: object,
    approval: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    capability_lease: object,
    dispatch_plan: object,
    backend_admission_decision: object,
    backend_descriptor: object,
    authority_backend_manifest: object,
    backend_certification: object,
    backend_replay_proof: object,
    firewall_decision: object,
) -> OperatorAuthorityReason | None:
    if type(quarantine) is not CommandQuarantineEnvelope:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(approval) is not AuthorityBoundApprovalReceipt:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(operator_identity) is not OperatorIdentityClaim:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(authority_manifest) is not OperatorAuthorityManifest:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST
    if type(approval_nonce) is not OperatorApprovalNonce:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if type(capability_lease) is not RuntimeCapabilityLease:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(dispatch_plan, RuntimeDispatchPlan):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_admission_decision, BackendAdmissionDecision):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(authority_backend_manifest, BackendAuthorityManifest):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_certification, BackendCertificationResult):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend_replay_proof, BackendReplayProofResult):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    if not isinstance(firewall_decision, DispatchFirewallDecision):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    return None


def _evidence_replay_reason(
    *,
    quarantine: CommandQuarantineEnvelope,
    capability_lease: RuntimeCapabilityLease,
    dispatch_plan: RuntimeDispatchPlan,
    backend_admission_decision: BackendAdmissionDecision,
    backend_descriptor: RuntimeBackendDescriptor,
    authority_backend_manifest: BackendAuthorityManifest,
    registry_checksum: object,
    backend_certification: BackendCertificationResult,
    backend_replay_proof: BackendReplayProofResult,
    firewall_decision: DispatchFirewallDecision,
    context_authority_checksum: object,
    current_lease_epoch: object,
) -> OperatorAuthorityReason | None:
    if quarantine.quarantine_status is not CommandQuarantineStatus.QUARANTINED:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_REPLAY
    if quarantine.quarantine_checksum != recompute_command_quarantine_checksum(quarantine):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_CHECKSUM_DRIFT
    expected_items = quarantine_items_from_dispatch_plan(dispatch_plan)
    if quarantine_item_checksums(quarantine) != frozenset(
        item.item_checksum for item in expected_items
    ):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_REPLAY
    drift_reason = command_quarantine_evidence_drift_reason(
        quarantine=quarantine,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_backend_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        context_authority_checksum=context_authority_checksum,
    )
    if drift_reason is not None:
        return _map_quarantine_drift_reason(drift_reason)
    validation = validate_runtime_capability_lease(
        lease=capability_lease,
        admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_backend_manifest,
        registry_checksum=registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        dispatch_plan=dispatch_plan,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )
    if validation.status != "VALID":
        if validation.reason_code == "CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT":
            return OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT
        if validation.reason_code == "CAPABILITY_LEASE_STALE_EPOCH":
            return OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_LEASE_INVALID
    return None


def _authority_replay_reason(
    *,
    quarantine: CommandQuarantineEnvelope,
    approval: AuthorityBoundApprovalReceipt | None,
    operator_identity: OperatorIdentityClaim,
    authority_manifest: OperatorAuthorityManifest,
    approval_nonce: OperatorApprovalNonce,
    context_authority_checksum: object,
    approved_scope: Iterable[object] | None = None,
) -> OperatorAuthorityReason | None:
    context_checksum = checksum_or_fallback(context_authority_checksum)
    if authority_manifest.manifest_checksum != recompute_operator_authority_manifest_checksum(
        authority_manifest
    ):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT
    if operator_identity.identity_checksum != recompute_operator_identity_claim_checksum(
        operator_identity
    ):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT
    if approval_nonce.nonce_checksum != recompute_operator_approval_nonce_checksum(approval_nonce):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT
    if authority_manifest.required_context_authority_checksum != context_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT
    if quarantine.context_authority_checksum != context_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT
    if operator_identity.context_authority_checksum != context_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT
    if (
        operator_identity.operator_authority_manifest_checksum
        != authority_manifest.manifest_checksum
    ):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT
    if operator_identity.operator_role not in authority_manifest.allowed_operator_roles:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_ROLE_REPLAY
    if approval_nonce.quarantine_checksum != quarantine.quarantine_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY
    if approval_nonce.operator_identity_checksum != operator_identity.identity_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_IDENTITY_REPLAY
    if approval_nonce.approval_epoch != quarantine.quarantine_epoch:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY
    if authority_manifest.approval_epoch != quarantine.quarantine_epoch:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY
    if operator_identity.identity_epoch != quarantine.quarantine_epoch:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY
    if approved_scope is not None:
        scope = normalize_operator_approval_scopes(approved_scope)
    elif approval is not None:
        scope = approval.approved_scope
    else:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION
    scope_reason = _scope_replay_reason(
        quarantine=quarantine,
        authority_manifest=authority_manifest,
        approved_scope=scope,
    )
    if scope_reason is not None:
        return scope_reason
    if approval is None:
        return None
    if approval.authority_bound_checksum != recompute_authority_bound_approval_checksum(approval):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_CHECKSUM_DRIFT
    if approval.quarantine_checksum != quarantine.quarantine_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_REPLAY
    if approval.operator_identity_checksum != operator_identity.identity_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_OPERATOR_IDENTITY_REPLAY
    if approval.operator_authority_manifest_checksum != authority_manifest.manifest_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT
    if approval.approval_nonce_checksum != approval_nonce.nonce_checksum:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT
    if approval.approval_epoch != quarantine.quarantine_epoch:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY
    if approval.approval_status is OperatorApprovalStatus.REJECTED:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_REJECTED_APPROVAL
    if approval.approval_status is not OperatorApprovalStatus.APPROVED:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID
    return None


def _scope_replay_reason(
    *,
    quarantine: CommandQuarantineEnvelope,
    authority_manifest: OperatorAuthorityManifest,
    approved_scope: frozenset[str],
) -> OperatorAuthorityReason | None:
    quarantine_scope = quarantine_item_checksums(quarantine)
    if "*" in approved_scope:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE
    if not approved_scope:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY
    if not approved_scope.issubset(authority_manifest.allowed_approval_scopes):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE
    if not approved_scope.issubset(quarantine_scope):
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE
    if approved_scope != quarantine_scope:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_PARTIAL_APPROVAL_SCOPE
    return None


def _blocked_result(
    *,
    reason: OperatorAuthorityReason,
    approval: object,
    quarantine: object,
    operator_identity: object,
    authority_manifest: object,
    approval_nonce: object,
    context_authority_checksum: object,
) -> ApprovalReplayValidationResult:
    return ApprovalReplayValidationResult(
        status="BLOCKED",
        reason_code=reason.value,
        approval_checksum=authority_bound_approval_checksum_or_fallback(approval),
        quarantine_checksum=_quarantine_checksum_or_fallback(quarantine),
        operator_identity_checksum=operator_identity_checksum_or_fallback(operator_identity),
        authority_manifest_checksum=operator_authority_manifest_checksum_or_fallback(
            authority_manifest
        ),
        nonce_checksum=operator_nonce_checksum_or_fallback(approval_nonce),
        context_authority_checksum=checksum_or_fallback(context_authority_checksum),
    )


def _quarantine_checksum_or_fallback(value: object) -> str:
    if type(value) is CommandQuarantineEnvelope:
        return checksum_or_fallback(value.quarantine_checksum)
    return checksum_or_fallback(getattr(value, "quarantine_checksum", None))


def _map_quarantine_drift_reason(reason: CommandQuarantineReason) -> OperatorAuthorityReason:
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_DISPATCH_PLAN_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_ADMISSION_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_DESCRIPTOR_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_REGISTRY_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_MANIFEST_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_CERTIFICATION_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_CERTIFICATION_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_REPLAY_PROOF_REPLAY
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT
    if reason is CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT:
        return OperatorAuthorityReason.OPERATOR_AUTHORITY_LEASE_REPLAY
    return OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_REPLAY


def _normalize_approval_status(value: object) -> OperatorApprovalStatus:
    if isinstance(value, OperatorApprovalStatus):
        return value
    if isinstance(value, str):
        try:
            return OperatorApprovalStatus(value)
        except ValueError:
            raise ValueError(
                OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID.value
            ) from None
    raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID.value)


def _normalize_replay_status(value: object) -> ApprovalReplayStatusValue:
    if value in {"VALID", "BLOCKED"}:
        return cast(ApprovalReplayStatusValue, value)
    raise ValueError("status must be VALID or BLOCKED")


def _normalize_reason_code(value: object) -> str:
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
        raise ValueError(OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value)
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


def _approval_status_checksum_value(value: OperatorApprovalStatus | str) -> str:
    if isinstance(value, OperatorApprovalStatus):
        return value.value
    return value


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalApprovalReplayValue]:
    return [value for value in values]


def _sha256(payload: Mapping[str, CanonicalApprovalReplayValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalApprovalReplayValue],
) -> dict[str, CanonicalApprovalReplayValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalApprovalReplayValue) -> CanonicalApprovalReplayValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalApprovalReplayValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "ApprovalReplayStatus",
    "ApprovalReplayStatusValue",
    "ApprovalReplayValidationResult",
    "AuthorityBoundApprovalReceipt",
    "AuthorityBoundApprovalStatusValue",
    "approval_replay_block_reason",
    "approval_replay_validation_checksum",
    "approval_replay_validation_checksum_or_fallback",
    "authority_bound_approval_checksum_or_fallback",
    "authority_bound_approval_id",
    "authority_bound_approval_receipt_checksum",
    "build_authority_bound_approval_receipt",
    "recompute_approval_replay_validation_checksum",
    "recompute_authority_bound_approval_checksum",
    "validate_approval_replay",
]
