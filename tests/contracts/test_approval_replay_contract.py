"""Contract tests for ADR-0023 authority-bound approval replay validation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_approval_replay import (
    ApprovalReplayValidationResult,
    AuthorityBoundApprovalReceipt,
    authority_bound_approval_id,
    recompute_approval_replay_validation_checksum,
    recompute_authority_bound_approval_checksum,
)
from aegis.execution.aegis_operator_authority import OperatorAuthorityReason


def test_authority_bound_approval_receipt_binds_identity_manifest_nonce_and_scope() -> None:
    parts = operator_authority_parts(request_id="approval-replay-contract")
    approval = parts.approval

    assert approval.approval_status.value == "APPROVED"
    assert approval.quarantine_checksum == parts.quarantine.quarantine_checksum
    assert approval.operator_identity_checksum == parts.operator_identity.identity_checksum
    assert approval.operator_authority_manifest_checksum == (
        parts.operator_authority_manifest.manifest_checksum
    )
    assert approval.approval_nonce_checksum == parts.approval_nonce.nonce_checksum
    assert approval.approved_scope == parts.operator_authority_manifest.allowed_approval_scopes
    assert approval.authority_bound_checksum == recompute_authority_bound_approval_checksum(
        approval
    )


def test_approval_replay_validation_result_is_valid_and_immutable() -> None:
    parts = operator_authority_parts(request_id="approval-replay-valid")
    result = parts.replay_validation

    assert result.status == "VALID"
    assert result.reason_code == OperatorAuthorityReason.OPERATOR_AUTHORITY_REPLAY_VALID.value
    assert result.approval_checksum == parts.approval.authority_bound_checksum
    assert result.quarantine_checksum == parts.quarantine.quarantine_checksum
    assert result.replay_validation_checksum == recompute_approval_replay_validation_checksum(
        result
    )
    with pytest.raises(FrozenInstanceError):
        result.status = "BLOCKED"


def test_direct_authority_bound_approval_and_valid_result_construction_are_blocked() -> None:
    parts = operator_authority_parts(request_id="approval-replay-direct")

    with pytest.raises(
        ValueError,
        match=OperatorAuthorityReason.DIRECT_AUTHORITY_BOUND_APPROVAL_CONSTRUCTION.value,
    ):
        AuthorityBoundApprovalReceipt(
            approval_id=authority_bound_approval_id(
                approval_status="APPROVED",
                quarantine_checksum=parts.quarantine.quarantine_checksum,
                operator_identity_checksum=parts.operator_identity.identity_checksum,
                operator_authority_manifest_checksum=parts.operator_authority_manifest.manifest_checksum,
                approval_nonce_checksum=parts.approval_nonce.nonce_checksum,
                approved_scope=parts.approval.approved_scope,
                approval_epoch=parts.quarantine.quarantine_epoch,
            ),
            approval_status="APPROVED",
            quarantine_checksum=parts.quarantine.quarantine_checksum,
            operator_identity_checksum=parts.operator_identity.identity_checksum,
            operator_authority_manifest_checksum=parts.operator_authority_manifest.manifest_checksum,
            approval_nonce_checksum=parts.approval_nonce.nonce_checksum,
            approved_scope=parts.approval.approved_scope,
            approval_epoch=parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError,
        match=OperatorAuthorityReason.DIRECT_APPROVAL_REPLAY_VALIDATION_CONSTRUCTION.value,
    ):
        ApprovalReplayValidationResult(
            status="VALID",
            reason_code=OperatorAuthorityReason.OPERATOR_AUTHORITY_REPLAY_VALID.value,
            approval_checksum=parts.approval.authority_bound_checksum,
            quarantine_checksum=parts.quarantine.quarantine_checksum,
            operator_identity_checksum=parts.operator_identity.identity_checksum,
            authority_manifest_checksum=parts.operator_authority_manifest.manifest_checksum,
            nonce_checksum=parts.approval_nonce.nonce_checksum,
            context_authority_checksum=parts.context_authority.context_checksum,
        )


def test_rejected_authority_bound_approval_replay_blocks() -> None:
    parts = operator_authority_parts(
        request_id="approval-replay-rejected", approval_status="REJECTED"
    )

    assert parts.replay_validation.status == "BLOCKED"
    assert parts.replay_validation.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_REJECTED_APPROVAL.value
    )
