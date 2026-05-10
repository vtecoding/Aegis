"""Adversarial bypass tests for ADR-0022/ADR-0023 quarantine release."""

from __future__ import annotations

import pytest
from tests.operator_authority_fixtures import OperatorAuthorityParts, operator_authority_parts

from aegis.execution.aegis_approval_replay import recompute_authority_bound_approval_checksum
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineReason,
    quarantine_item_checksums,
)
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)

_DEFAULT_APPROVAL = object()
_DEFAULT_REPLAY_VALIDATION = object()


def _positive_release_parts(request_id: str) -> OperatorAuthorityParts:
    return operator_authority_parts(request_id=request_id)


def _release_with_parts(
    parts: OperatorAuthorityParts,
    *,
    approval: object = _DEFAULT_APPROVAL,
    replay_validation: object = _DEFAULT_REPLAY_VALIDATION,
    registry_checksum: object | None = None,
    context_checksum: object | None = None,
) -> QuarantineReleaseDecision:
    return evaluate_quarantine_release(
        quarantine=parts.quarantine,
        approval=parts.approval if approval is _DEFAULT_APPROVAL else approval,
        approval_replay_validation=parts.replay_validation
        if replay_validation is _DEFAULT_REPLAY_VALIDATION
        else replay_validation,
        capability_lease=parts.capability_lease,
        dispatch_plan=parts.dispatch_plan,
        backend_admission_decision=parts.backend_admission_decision,
        backend_descriptor=parts.backend_descriptor,
        authority_manifest=parts.backend_authority_manifest,
        registry_checksum=parts.backend_registry.registry_checksum
        if registry_checksum is None
        else registry_checksum,
        backend_certification=parts.backend_certification,
        backend_replay_proof=parts.backend_replay_proof,
        firewall_decision=parts.firewall_decision,
        context_authority_checksum=parts.context_authority.context_checksum
        if context_checksum is None
        else context_checksum,
        current_lease_epoch=1,
    )


def test_missing_approval_blocks_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-missing-approval")

    release = _release_with_parts(parts, approval=None)

    assert release.status == "BLOCKED"
    assert release.reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL.value


def test_structural_approval_without_replay_validation_blocks_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-missing-replay-validation")

    release = _release_with_parts(parts, replay_validation=None)

    assert release.status == "BLOCKED"
    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_MISSING_APPROVAL_REPLAY_VALIDATION.value
    )


def test_rejected_approval_blocks_release() -> None:
    parts = operator_authority_parts(
        request_id="quarantine-bypass-rejected", approval_status="REJECTED"
    )

    release = _release_with_parts(parts)

    assert release.status == "BLOCKED"
    assert release.reason_code == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REJECTED.value


def test_wildcard_overbroad_and_partial_scope_block_release() -> None:
    wildcard_parts = _positive_release_parts("quarantine-bypass-scope-wildcard")
    object.__setattr__(wildcard_parts.approval, "approved_scope", frozenset({"*"}))

    overbroad_parts = _positive_release_parts("quarantine-bypass-scope-overbroad")
    object.__setattr__(
        overbroad_parts.approval,
        "approved_scope",
        quarantine_item_checksums(overbroad_parts.quarantine).union({"f" * 64}),
    )
    object.__setattr__(
        overbroad_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(overbroad_parts.approval),
    )

    partial_parts = _positive_release_parts("quarantine-bypass-scope-partial")
    object.__setattr__(partial_parts.approval, "approved_scope", frozenset())

    wildcard_release = _release_with_parts(wildcard_parts)
    overbroad_release = _release_with_parts(overbroad_parts)
    partial_release = _release_with_parts(partial_parts)

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
    target_by_field: dict[str, object] = {
        "quarantine_checksum": parts.quarantine,
        "lease_checksum": parts.capability_lease,
        "plan_checksum": parts.dispatch_plan,
        "decision_checksum": parts.backend_admission_decision,
        "manifest_checksum": parts.backend_authority_manifest,
        "certification_checksum": parts.backend_certification,
        "proof_checksum": parts.backend_replay_proof,
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


def test_stale_approval_epoch_blocks_release() -> None:
    parts = _positive_release_parts("quarantine-bypass-stale-approval")
    object.__setattr__(parts.approval, "approval_epoch", 2)
    object.__setattr__(
        parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(parts.approval),
    )

    release = _release_with_parts(parts)

    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH.value
    )


def test_approval_checksum_and_quarantine_binding_drift_block_release() -> None:
    checksum_parts = _positive_release_parts("quarantine-bypass-approval-checksum")
    object.__setattr__(checksum_parts.approval, "authority_bound_checksum", "1" * 64)
    mismatch_parts = _positive_release_parts("quarantine-bypass-approval-mismatch")
    other_parts = _positive_release_parts("quarantine-bypass-approval-other")

    checksum_release = _release_with_parts(checksum_parts)
    mismatch_release = _release_with_parts(mismatch_parts, approval=other_parts.approval)

    assert checksum_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT.value
    )
    assert mismatch_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH.value
    )


def test_invalid_approval_status_and_partial_quarantine_block_release() -> None:
    status_parts = _positive_release_parts("quarantine-bypass-approval-status")
    object.__setattr__(status_parts.approval, "approval_status", "MAYBE")
    object.__setattr__(
        status_parts.approval,
        "authority_bound_checksum",
        recompute_authority_bound_approval_checksum(status_parts.approval),
    )
    partial_parts = _positive_release_parts("quarantine-bypass-partial-quarantine")
    object.__setattr__(partial_parts.quarantine, "quarantined_items", ())

    status_release = _release_with_parts(status_parts)
    partial_release = _release_with_parts(partial_parts)

    assert status_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value
    )
    assert partial_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value
    )


def test_replay_validation_drift_and_binding_mismatch_block_release() -> None:
    drift_parts = _positive_release_parts("quarantine-bypass-replay-drift")
    object.__setattr__(drift_parts.replay_validation, "replay_validation_checksum", "1" * 64)
    mismatch_parts = _positive_release_parts("quarantine-bypass-replay-mismatch")
    other_parts = _positive_release_parts("quarantine-bypass-replay-other")

    drift_release = _release_with_parts(drift_parts)
    mismatch_release = _release_with_parts(
        mismatch_parts, replay_validation=other_parts.replay_validation
    )

    assert drift_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REPLAY_CHECKSUM_DRIFT.value
    )
    assert mismatch_release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_REPLAY_BINDING_MISMATCH.value
    )


def test_release_decision_rejects_malformed_direct_construction() -> None:
    release = _release_with_parts(_positive_release_parts("quarantine-bypass-release-shape"))

    with pytest.raises(ValueError, match="blocking reason"):
        QuarantineReleaseDecision(
            status="BLOCKED",
            reason_code=CommandQuarantineReason.COMMAND_QUARANTINE_RELEASED_DRY_RUN.value,
            quarantine_checksum=release.quarantine_checksum,
            approval_checksum=release.approval_checksum,
            approval_replay_validation_checksum=release.approval_replay_validation_checksum,
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
            approval_replay_validation_checksum=release.approval_replay_validation_checksum,
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
            approval_replay_validation_checksum=release.approval_replay_validation_checksum,
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
        "approval_replay_validation",
    ),
)
def test_release_rejects_runtime_object_injection_in_source_evidence(field_name: str) -> None:
    parts = _positive_release_parts(f"quarantine-bypass-source-shape-{field_name}")
    values: dict[str, object] = {
        "dispatch_plan": parts.dispatch_plan,
        "firewall_decision": parts.firewall_decision,
        "backend_descriptor": parts.backend_descriptor,
        "backend_certification": parts.backend_certification,
        "backend_replay_proof": parts.backend_replay_proof,
        "authority_manifest": parts.backend_authority_manifest,
        "registry_checksum": parts.backend_registry.registry_checksum,
        "backend_admission_decision": parts.backend_admission_decision,
        "context_authority_checksum": parts.context_authority.context_checksum,
        "capability_lease": parts.capability_lease,
        "quarantine": parts.quarantine,
        "approval": parts.approval,
        "approval_replay_validation": parts.replay_validation,
    }
    values[field_name] = object()

    release = evaluate_quarantine_release(
        quarantine=values["quarantine"],
        approval=values["approval"],
        approval_replay_validation=values["approval_replay_validation"],
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
