"""Adversarial bypass tests for ADR-0022 quarantine release."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import (
    command_quarantine_parts,
    operator_approval_receipt,
)

from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineReason,
    quarantine_item_checksums,
    quarantine_runtime_command,
)
from aegis.execution.aegis_operator_approval import (
    OperatorApprovalReceipt,
    operator_approval_id,
    recompute_operator_approval_checksum,
)
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)

_DEFAULT_APPROVAL = object()


def _positive_release_parts(request_id: str):
    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id=request_id)
    quarantine = quarantine_runtime_command(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        quarantine_epoch=1,
        current_lease_epoch=1,
    )
    approval = operator_approval_receipt(quarantine=quarantine)
    return (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
        quarantine,
        approval,
    )


def _release_with_parts(
    parts,
    *,
    approval=_DEFAULT_APPROVAL,
    registry_checksum=None,
    context_checksum=None,
):
    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
        quarantine,
        default_approval,
    ) = parts
    return evaluate_quarantine_release(
        quarantine=quarantine,
        approval=default_approval if approval is _DEFAULT_APPROVAL else approval,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum
        if registry_checksum is None
        else registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum
        if context_checksum is None
        else context_checksum,
        current_lease_epoch=1,
    )


def test_missing_approval_blocks_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-missing-approval")

    release = _release_with_parts(parts, approval=None)

    assert release.status == "BLOCKED"
    assert release.reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL.value


def test_rejected_approval_blocks_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-rejected")
    rejected = operator_approval_receipt(quarantine=parts[10], approval_status="REJECTED")

    release = _release_with_parts(parts, approval=rejected)

    assert release.status == "BLOCKED"
    assert release.reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REJECTED.value


def test_wildcard_overbroad_and_partial_scope_block_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-scope")
    quarantine = parts[10]
    scope = quarantine_item_checksums(quarantine)
    overbroad_scope = scope.union({"f" * 64})
    overbroad_id = operator_approval_id(
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=overbroad_scope,
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="overbroad",
    )
    overbroad = OperatorApprovalReceipt(
        approval_id=overbroad_id,
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=overbroad_scope,
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="overbroad",
    )
    wildcard = operator_approval_receipt(quarantine=quarantine)
    object.__setattr__(wildcard, "approved_scope", frozenset({"*"}))
    partial = operator_approval_receipt(quarantine=quarantine)
    object.__setattr__(partial, "approved_scope", frozenset())

    wildcard_release = _release_with_parts(parts, approval=wildcard)
    overbroad_release = _release_with_parts(parts, approval=overbroad)
    partial_release = _release_with_parts(parts, approval=partial)

    assert wildcard_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE.value
    )
    assert overbroad_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE.value
    )
    assert partial_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY.value
    )


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    (
        ("quarantine_checksum", "COMMAND_QUARANTINE_CHECKSUM_DRIFT"),
        ("lease_checksum", "COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT"),
        ("plan_checksum", "COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT"),
        ("decision_checksum", "COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT"),
        ("manifest_checksum", "COMMAND_QUARANTINE_MANIFEST_DRIFT"),
        ("certification_checksum", "COMMAND_QUARANTINE_CERTIFICATION_DRIFT"),
        ("proof_checksum", "COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT"),
    ),
)
def test_evidence_drift_blocks_release(field_name: str, reason_code: str) -> None:
    parts = _positive_release_parts(f"quarantine-bypass-{field_name}")
    target_by_field = {
        "quarantine_checksum": parts[10],
        "lease_checksum": parts[9],
        "plan_checksum": parts[0],
        "decision_checksum": parts[7],
        "manifest_checksum": parts[5],
        "certification_checksum": parts[3],
        "proof_checksum": parts[4],
    }
    object.__setattr__(target_by_field[field_name], field_name, "1" * 64)

    release = _release_with_parts(parts)

    assert release.status == "BLOCKED"
    assert release.reason_code == reason_code


def test_registry_and_context_authority_drift_block_release() -> None:
    registry_release = _release_with_parts(
        _positive_release_parts("quarantine-bypass-registry"), registry_checksum="1" * 64
    )
    context_release = _release_with_parts(
        _positive_release_parts("quarantine-bypass-context"), context_checksum="1" * 64
    )

    assert (
        registry_release.reason_code
        == CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT.value
    )
    assert context_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT.value
    )


def test_stale_approval_epoch_and_malformed_operator_block_release() -> None:
    stale_parts = _positive_release_parts("quarantine-bypass-stale-approval")
    stale = operator_approval_receipt(quarantine=stale_parts[10], approval_epoch=2)
    malformed_parts = _positive_release_parts("quarantine-bypass-operator")
    malformed = malformed_parts[11]
    object.__setattr__(malformed, "operator_id", "")

    stale_release = _release_with_parts(stale_parts, approval=stale)
    malformed_release = _release_with_parts(malformed_parts, approval=malformed)

    assert stale_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH.value
    )
    assert malformed_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED.value
    )


def test_approval_checksum_and_quarantine_binding_drift_block_release() -> None:
    checksum_parts = _positive_release_parts("quarantine-bypass-approval-checksum")
    checksum_approval = checksum_parts[11]
    object.__setattr__(checksum_approval, "approval_checksum", "1" * 64)
    mismatch_parts = _positive_release_parts("quarantine-bypass-approval-mismatch")
    other_parts = _positive_release_parts("quarantine-bypass-approval-other")
    mismatch_approval = operator_approval_receipt(quarantine=other_parts[10])

    checksum_release = _release_with_parts(checksum_parts, approval=checksum_approval)
    mismatch_release = _release_with_parts(mismatch_parts, approval=mismatch_approval)

    assert checksum_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT.value
    )
    assert mismatch_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH.value
    )


def test_invalid_approval_status_and_partial_quarantine_block_release() -> None:
    status_parts = _positive_release_parts("quarantine-bypass-approval-status")
    invalid_status = status_parts[11]
    object.__setattr__(invalid_status, "approval_status", "MAYBE")
    object.__setattr__(
        invalid_status,
        "approval_checksum",
        recompute_operator_approval_checksum(invalid_status),
    )
    partial_parts = _positive_release_parts("quarantine-bypass-partial-quarantine")
    object.__setattr__(partial_parts[10], "quarantined_items", ())

    status_release = _release_with_parts(status_parts, approval=invalid_status)
    partial_release = _release_with_parts(partial_parts)

    assert status_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value
    )
    assert partial_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value
    )


def test_release_decision_rejects_malformed_direct_construction() -> None:
    release = _release_with_parts(_positive_release_parts("quarantine-bypass-release-shape"))

    with pytest.raises(ValueError, match="blocking reason"):
        QuarantineReleaseDecision(
            status="BLOCKED",
            reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            lease_checksum=release.lease_checksum,
            dispatch_plan_checksum=release.dispatch_plan_checksum,
            released_item_count=0,
        )
    with pytest.raises(ValueError, match="status"):
        QuarantineReleaseDecision(
            status="ALLOW",
            reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL.value,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            lease_checksum=release.lease_checksum,
            dispatch_plan_checksum=release.dispatch_plan_checksum,
            released_item_count=0,
        )
    with pytest.raises(
        ValueError,
        match=CommandQuarantineReason.DIRECT_QUARANTINE_RELEASE_CONSTRUCTION.value,
    ):
        QuarantineReleaseDecision(
            status="RELEASED_DRY_RUN",
            reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            lease_checksum=release.lease_checksum,
            dispatch_plan_checksum=release.dispatch_plan_checksum,
            released_item_count=release.released_item_count,
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "quarantine",
        "capability_lease",
        "dispatch_plan",
        "backend_admission_decision",
        "backend_descriptor",
        "authority_manifest",
        "backend_certification",
        "backend_replay_proof",
        "firewall_decision",
    ),
)
def test_release_rejects_runtime_object_injection_in_source_evidence(field_name: str) -> None:
    parts = _positive_release_parts(f"quarantine-bypass-source-shape-{field_name}")
    values: dict[str, object] = {
        "dispatch_plan": parts[0],
        "firewall_decision": parts[1],
        "backend_descriptor": parts[2],
        "backend_certification": parts[3],
        "backend_replay_proof": parts[4],
        "authority_manifest": parts[5],
        "registry_checksum": parts[6].registry_checksum,
        "backend_admission_decision": parts[7],
        "context_authority_checksum": parts[8].context_checksum,
        "capability_lease": parts[9],
        "quarantine": parts[10],
        "approval": parts[11],
    }
    values[field_name] = object()

    release = evaluate_quarantine_release(
        quarantine=values["quarantine"],
        approval=values["approval"],
        capability_lease=values["capability_lease"],
        dispatch_plan=values["dispatch_plan"],
        backend_admission_decision=values["backend_admission_decision"],
        backend_descriptor=values["backend_descriptor"],
        authority_manifest=values["authority_manifest"],
        registry_checksum=values["registry_checksum"],
        backend_certification=values["backend_certification"],
        backend_replay_proof=values["backend_replay_proof"],
        firewall_decision=values["firewall_decision"],
        context_authority_checksum=values["context_authority_checksum"],
        current_lease_epoch=1,
    )

    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    )
