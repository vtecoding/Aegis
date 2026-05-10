"""Replay attack tests for ADR-0023 approval validation."""

from __future__ import annotations

import pytest
from tests.operator_authority_fixtures import OperatorAuthorityParts, operator_authority_parts

from aegis.execution.aegis_approval_replay import (
    ApprovalReplayValidationResult,
    recompute_authority_bound_approval_checksum,
    validate_approval_replay,
)
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityReason,
    recompute_operator_authority_manifest_checksum,
)
from aegis.execution.aegis_operator_identity import (
    recompute_operator_approval_nonce_checksum,
    recompute_operator_identity_claim_checksum,
)


def _validate_with_parts(
    *,
    target_parts: OperatorAuthorityParts,
    approval_parts: OperatorAuthorityParts,
    identity_parts: OperatorAuthorityParts | None = None,
    nonce_parts: OperatorAuthorityParts | None = None,
    registry_checksum: object | None = None,
    context_authority_checksum: object | None = None,
    current_lease_epoch: int = 1,
) -> ApprovalReplayValidationResult:
    identity_source = approval_parts if identity_parts is None else identity_parts
    nonce_source = approval_parts if nonce_parts is None else nonce_parts
    return validate_approval_replay(
        quarantine=target_parts.quarantine,
        approval=approval_parts.approval,
        operator_identity=identity_source.operator_identity,
        authority_manifest=identity_source.operator_authority_manifest,
        approval_nonce=nonce_source.approval_nonce,
        capability_lease=target_parts.capability_lease,
        dispatch_plan=target_parts.dispatch_plan,
        backend_admission_decision=target_parts.backend_admission_decision,
        backend_descriptor=target_parts.backend_descriptor,
        authority_backend_manifest=target_parts.backend_authority_manifest,
        registry_checksum=target_parts.backend_registry.registry_checksum
        if registry_checksum is None
        else registry_checksum,
        backend_certification=target_parts.backend_certification,
        backend_replay_proof=target_parts.backend_replay_proof,
        firewall_decision=target_parts.firewall_decision,
        context_authority_checksum=target_parts.context_authority.context_checksum
        if context_authority_checksum is None
        else context_authority_checksum,
        current_lease_epoch=current_lease_epoch,
    )


def test_nonce_reused_across_quarantine_envelopes_blocks() -> None:
    target_parts = operator_authority_parts(
        request_id="approval-replay-nonce", lease_epoch=2, quarantine_epoch=1
    )
    replayed_parts = operator_authority_parts(
        request_id="approval-replay-nonce", lease_epoch=1, quarantine_epoch=1
    )

    result = _validate_with_parts(
        target_parts=target_parts, approval_parts=replayed_parts, current_lease_epoch=2
    )

    assert result.status == "BLOCKED"
    assert result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY.value
    )


def test_approval_replay_across_operator_identity_blocks() -> None:
    target_parts = operator_authority_parts(
        request_id="approval-replay-operator-target", operator_id="operator-001"
    )
    other_identity_parts = operator_authority_parts(
        request_id="approval-replay-operator-target", operator_id="operator-002"
    )

    result = _validate_with_parts(
        target_parts=target_parts,
        approval_parts=target_parts,
        identity_parts=other_identity_parts,
        nonce_parts=other_identity_parts,
    )

    assert result.status == "BLOCKED"
    assert result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_OPERATOR_IDENTITY_REPLAY.value
    )


def test_epoch_replay_blocks() -> None:
    parts = operator_authority_parts(request_id="approval-replay-epoch")

    result = _validate_with_parts(
        target_parts=parts,
        approval_parts=parts,
        current_lease_epoch=parts.quarantine.quarantine_epoch + 1,
    )

    assert result.status == "BLOCKED"
    assert result.reason_code == OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value


def test_replay_across_dispatch_lease_and_backend_admission_blocks() -> None:
    dispatch_parts = operator_authority_parts(request_id="approval-replay-dispatch")
    lease_parts = operator_authority_parts(request_id="approval-replay-lease")
    admission_parts = operator_authority_parts(request_id="approval-replay-admission")

    object.__setattr__(dispatch_parts.dispatch_plan, "plan_checksum", "1" * 64)
    object.__setattr__(lease_parts.capability_lease, "lease_checksum", "1" * 64)
    object.__setattr__(admission_parts.backend_admission_decision, "decision_checksum", "1" * 64)

    dispatch_result = _validate_with_parts(
        target_parts=dispatch_parts, approval_parts=dispatch_parts
    )
    lease_result = _validate_with_parts(target_parts=lease_parts, approval_parts=lease_parts)
    admission_result = _validate_with_parts(
        target_parts=admission_parts, approval_parts=admission_parts
    )

    assert dispatch_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_DISPATCH_PLAN_REPLAY.value
    )
    assert lease_result.reason_code == OperatorAuthorityReason.OPERATOR_AUTHORITY_LEASE_REPLAY.value
    assert admission_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_ADMISSION_REPLAY.value
    )


@pytest.mark.parametrize(
    ("field_name", "target_name", "reason_code"),
    (
        (
            "descriptor_checksum",
            "backend_descriptor",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_DESCRIPTOR_REPLAY.value,
        ),
        (
            "manifest_checksum",
            "backend_authority_manifest",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value,
        ),
        (
            "certification_checksum",
            "backend_certification",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_CERTIFICATION_REPLAY.value,
        ),
        (
            "proof_checksum",
            "backend_replay_proof",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_BACKEND_REPLAY_PROOF_REPLAY.value,
        ),
    ),
)
def test_replay_across_backend_evidence_drift_blocks(
    field_name: str, target_name: str, reason_code: str
) -> None:
    parts = operator_authority_parts(request_id=f"approval-replay-{field_name}")
    target = getattr(parts, target_name)
    object.__setattr__(target, field_name, "1" * 64)

    result = _validate_with_parts(target_parts=parts, approval_parts=parts)

    assert result.status == "BLOCKED"
    assert result.reason_code == reason_code


def test_replay_across_registry_and_context_evidence_blocks() -> None:
    registry_parts = operator_authority_parts(request_id="approval-replay-registry")
    context_parts = operator_authority_parts(request_id="approval-replay-context")

    registry_result = _validate_with_parts(
        target_parts=registry_parts, approval_parts=registry_parts, registry_checksum="1" * 64
    )
    context_result = _validate_with_parts(
        target_parts=context_parts,
        approval_parts=context_parts,
        context_authority_checksum="1" * 64,
    )

    assert registry_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_REGISTRY_REPLAY.value
    )
    assert context_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT.value
    )


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    (
        ("quarantine", OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value),
        ("approval", OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value),
        (
            "operator_identity",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "authority_manifest",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST.value,
        ),
        (
            "approval_nonce",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "capability_lease",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "dispatch_plan",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "backend_admission_decision",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "backend_descriptor",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "authority_backend_manifest",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "backend_certification",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "backend_replay_proof",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
        (
            "firewall_decision",
            OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value,
        ),
    ),
)
def test_approval_replay_rejects_runtime_object_injection_in_source_evidence(
    field_name: str, reason_code: str
) -> None:
    parts = operator_authority_parts(request_id=f"approval-replay-source-{field_name}")
    values: dict[str, object] = {
        "quarantine": parts.quarantine,
        "approval": parts.approval,
        "operator_identity": parts.operator_identity,
        "authority_manifest": parts.operator_authority_manifest,
        "approval_nonce": parts.approval_nonce,
        "capability_lease": parts.capability_lease,
        "dispatch_plan": parts.dispatch_plan,
        "backend_admission_decision": parts.backend_admission_decision,
        "backend_descriptor": parts.backend_descriptor,
        "authority_backend_manifest": parts.backend_authority_manifest,
        "registry_checksum": parts.backend_registry.registry_checksum,
        "backend_certification": parts.backend_certification,
        "backend_replay_proof": parts.backend_replay_proof,
        "firewall_decision": parts.firewall_decision,
        "context_authority_checksum": parts.context_authority.context_checksum,
    }
    values[field_name] = object()

    result = validate_approval_replay(
        quarantine=values["quarantine"],
        approval=values["approval"],
        operator_identity=values["operator_identity"],
        authority_manifest=values["authority_manifest"],
        approval_nonce=values["approval_nonce"],
        capability_lease=values["capability_lease"],
        dispatch_plan=values["dispatch_plan"],
        backend_admission_decision=values["backend_admission_decision"],
        backend_descriptor=values["backend_descriptor"],
        authority_backend_manifest=values["authority_backend_manifest"],
        registry_checksum=values["registry_checksum"],
        backend_certification=values["backend_certification"],
        backend_replay_proof=values["backend_replay_proof"],
        firewall_decision=values["firewall_decision"],
        context_authority_checksum=values["context_authority_checksum"],
        current_lease_epoch=1,
    )

    assert result.status == "BLOCKED"
    assert result.reason_code == reason_code


def test_identity_manifest_and_nonce_binding_drift_block_replay_validation() -> None:
    identity_parts = operator_authority_parts(request_id="approval-replay-identity-drift")
    nonce_parts = operator_authority_parts(request_id="approval-replay-nonce-drift")
    manifest_binding_parts = operator_authority_parts(request_id="approval-replay-manifest-bind")
    role_parts = operator_authority_parts(request_id="approval-replay-role")

    object.__setattr__(identity_parts.operator_identity, "identity_checksum", "1" * 64)
    object.__setattr__(nonce_parts.approval_nonce, "nonce_checksum", "1" * 64)
    object.__setattr__(
        manifest_binding_parts.operator_identity,
        "operator_authority_manifest_checksum",
        "1" * 64,
    )
    object.__setattr__(
        manifest_binding_parts.operator_identity,
        "identity_checksum",
        recompute_operator_identity_claim_checksum(manifest_binding_parts.operator_identity),
    )
    object.__setattr__(role_parts.operator_identity, "operator_role", "release.admin")
    object.__setattr__(
        role_parts.operator_identity,
        "identity_checksum",
        recompute_operator_identity_claim_checksum(role_parts.operator_identity),
    )

    identity_result = _validate_with_parts(
        target_parts=identity_parts, approval_parts=identity_parts
    )
    nonce_result = _validate_with_parts(target_parts=nonce_parts, approval_parts=nonce_parts)
    manifest_result = _validate_with_parts(
        target_parts=manifest_binding_parts, approval_parts=manifest_binding_parts
    )
    role_result = _validate_with_parts(target_parts=role_parts, approval_parts=role_parts)

    assert identity_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT.value
    )
    assert nonce_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT.value
    )
    assert manifest_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value
    )
    assert role_result.reason_code == OperatorAuthorityReason.OPERATOR_AUTHORITY_ROLE_REPLAY.value


def test_nonce_and_epoch_replay_dimension_drift_blocks_validation() -> None:
    nonce_quarantine_parts = operator_authority_parts(request_id="approval-replay-nonce-q")
    nonce_identity_parts = operator_authority_parts(request_id="approval-replay-nonce-i")
    manifest_epoch_parts = operator_authority_parts(request_id="approval-replay-manifest-epoch")
    identity_epoch_parts = operator_authority_parts(request_id="approval-replay-identity-epoch")

    object.__setattr__(nonce_quarantine_parts.approval_nonce, "quarantine_checksum", "1" * 64)
    object.__setattr__(
        nonce_quarantine_parts.approval_nonce,
        "nonce_checksum",
        recompute_operator_approval_nonce_checksum(nonce_quarantine_parts.approval_nonce),
    )
    object.__setattr__(nonce_identity_parts.approval_nonce, "operator_identity_checksum", "1" * 64)
    object.__setattr__(
        nonce_identity_parts.approval_nonce,
        "nonce_checksum",
        recompute_operator_approval_nonce_checksum(nonce_identity_parts.approval_nonce),
    )
    object.__setattr__(manifest_epoch_parts.operator_authority_manifest, "approval_epoch", 2)
    object.__setattr__(
        manifest_epoch_parts.operator_authority_manifest,
        "manifest_checksum",
        recompute_operator_authority_manifest_checksum(
            manifest_epoch_parts.operator_authority_manifest
        ),
    )
    object.__setattr__(
        manifest_epoch_parts.operator_identity,
        "operator_authority_manifest_checksum",
        manifest_epoch_parts.operator_authority_manifest.manifest_checksum,
    )
    object.__setattr__(
        manifest_epoch_parts.operator_identity,
        "identity_checksum",
        recompute_operator_identity_claim_checksum(manifest_epoch_parts.operator_identity),
    )
    object.__setattr__(
        manifest_epoch_parts.approval_nonce,
        "operator_identity_checksum",
        manifest_epoch_parts.operator_identity.identity_checksum,
    )
    object.__setattr__(
        manifest_epoch_parts.approval_nonce,
        "nonce_checksum",
        recompute_operator_approval_nonce_checksum(manifest_epoch_parts.approval_nonce),
    )
    object.__setattr__(identity_epoch_parts.operator_identity, "identity_epoch", 2)
    object.__setattr__(
        identity_epoch_parts.operator_identity,
        "identity_checksum",
        recompute_operator_identity_claim_checksum(identity_epoch_parts.operator_identity),
    )
    object.__setattr__(
        identity_epoch_parts.approval_nonce,
        "operator_identity_checksum",
        identity_epoch_parts.operator_identity.identity_checksum,
    )
    object.__setattr__(
        identity_epoch_parts.approval_nonce,
        "nonce_checksum",
        recompute_operator_approval_nonce_checksum(identity_epoch_parts.approval_nonce),
    )

    nonce_quarantine_result = _validate_with_parts(
        target_parts=nonce_quarantine_parts, approval_parts=nonce_quarantine_parts
    )
    nonce_identity_result = _validate_with_parts(
        target_parts=nonce_identity_parts, approval_parts=nonce_identity_parts
    )
    manifest_epoch_result = _validate_with_parts(
        target_parts=manifest_epoch_parts, approval_parts=manifest_epoch_parts
    )
    identity_epoch_result = _validate_with_parts(
        target_parts=identity_epoch_parts, approval_parts=identity_epoch_parts
    )

    assert nonce_quarantine_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY.value
    )
    assert nonce_identity_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_IDENTITY_REPLAY.value
    )
    assert manifest_epoch_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value
    )
    assert identity_epoch_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value
    )


def test_authority_bound_approval_field_drift_blocks_replay_validation() -> None:
    checksum_parts = operator_authority_parts(request_id="approval-replay-approval-checksum")
    quarantine_parts = operator_authority_parts(request_id="approval-replay-approval-quarantine")
    manifest_parts = operator_authority_parts(request_id="approval-replay-approval-manifest")
    nonce_parts = operator_authority_parts(request_id="approval-replay-approval-nonce")
    epoch_parts = operator_authority_parts(request_id="approval-replay-approval-epoch")
    status_parts = operator_authority_parts(request_id="approval-replay-approval-status")

    object.__setattr__(checksum_parts.approval, "authority_bound_checksum", "1" * 64)
    object.__setattr__(quarantine_parts.approval, "quarantine_checksum", "1" * 64)
    object.__setattr__(
        quarantine_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(quarantine_parts.approval),
    )
    object.__setattr__(manifest_parts.approval, "operator_authority_manifest_checksum", "1" * 64)
    object.__setattr__(
        manifest_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(manifest_parts.approval),
    )
    object.__setattr__(nonce_parts.approval, "approval_nonce_checksum", "1" * 64)
    object.__setattr__(
        nonce_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(nonce_parts.approval),
    )
    object.__setattr__(epoch_parts.approval, "approval_epoch", 2)
    object.__setattr__(
        epoch_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(epoch_parts.approval),
    )
    object.__setattr__(status_parts.approval, "approval_status", "MAYBE")
    object.__setattr__(
        status_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(status_parts.approval),
    )

    checksum_result = _validate_with_parts(
        target_parts=checksum_parts, approval_parts=checksum_parts
    )
    quarantine_result = _validate_with_parts(
        target_parts=quarantine_parts, approval_parts=quarantine_parts
    )
    manifest_result = _validate_with_parts(
        target_parts=manifest_parts, approval_parts=manifest_parts
    )
    nonce_result = _validate_with_parts(target_parts=nonce_parts, approval_parts=nonce_parts)
    epoch_result = _validate_with_parts(target_parts=epoch_parts, approval_parts=epoch_parts)
    status_result = _validate_with_parts(target_parts=status_parts, approval_parts=status_parts)

    assert checksum_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_CHECKSUM_DRIFT.value
    )
    assert quarantine_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_REPLAY.value
    )
    assert manifest_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value
    )
    assert nonce_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT.value
    )
    assert epoch_result.reason_code == OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value
    assert status_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID.value
    )
