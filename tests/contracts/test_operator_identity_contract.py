"""Contract tests for ADR-0023 operator identity claims and approval nonces."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_operator_authority import OperatorAuthorityReason
from aegis.execution.aegis_operator_identity import (
    OperatorApprovalNonce,
    build_operator_approval_nonce,
    build_operator_identity_claim,
    operator_approval_nonce_id,
    recompute_operator_approval_nonce_checksum,
    recompute_operator_identity_claim_checksum,
)


def test_operator_identity_claim_binds_manifest_context_role_and_epoch() -> None:
    parts = operator_authority_parts(request_id="operator-identity-contract")
    identity = parts.operator_identity

    assert identity.operator_id == "operator-001"
    assert identity.operator_role == "release.operator"
    assert identity.operator_authority_manifest_checksum == (
        parts.operator_authority_manifest.manifest_checksum
    )
    assert identity.context_authority_checksum == parts.context_authority.context_checksum
    assert identity.identity_epoch == parts.quarantine.quarantine_epoch
    assert identity.identity_checksum == recompute_operator_identity_claim_checksum(identity)


def test_operator_identity_rejects_unknown_role_and_bad_operator_id() -> None:
    parts = operator_authority_parts(request_id="operator-identity-reject")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE.value
    ):
        build_operator_identity_claim(
            manifest=parts.operator_authority_manifest,
            operator_id="operator-001",
            operator_role="release.supervisor",
            context_authority_checksum=parts.context_authority.context_checksum,
            identity_epoch=parts.quarantine.quarantine_epoch,
        )


def test_operator_identity_rejects_manifest_context_and_epoch_drift() -> None:
    manifest_parts = operator_authority_parts(request_id="operator-identity-manifest-drift")
    context_parts = operator_authority_parts(request_id="operator-identity-context-drift")
    epoch_parts = operator_authority_parts(request_id="operator-identity-epoch-drift")
    object.__setattr__(manifest_parts.operator_authority_manifest, "manifest_checksum", "1" * 64)

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value
    ):
        build_operator_identity_claim(
            manifest=manifest_parts.operator_authority_manifest,
            operator_id="operator-001",
            operator_role="release.operator",
            context_authority_checksum=manifest_parts.context_authority.context_checksum,
            identity_epoch=manifest_parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT.value
    ):
        build_operator_identity_claim(
            manifest=context_parts.operator_authority_manifest,
            operator_id="operator-001",
            operator_role="release.operator",
            context_authority_checksum="1" * 64,
            identity_epoch=context_parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value
    ):
        build_operator_identity_claim(
            manifest=epoch_parts.operator_authority_manifest,
            operator_id="operator-001",
            operator_role="release.operator",
            context_authority_checksum=epoch_parts.context_authority.context_checksum,
            identity_epoch=epoch_parts.quarantine.quarantine_epoch + 1,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_OPERATOR_ID_MALFORMED.value
    ):
        build_operator_identity_claim(
            manifest=context_parts.operator_authority_manifest,
            operator_id="",
            operator_role="release.operator",
            context_authority_checksum=context_parts.context_authority.context_checksum,
            identity_epoch=context_parts.quarantine.quarantine_epoch,
        )


def test_operator_approval_nonce_binds_one_quarantine_and_identity() -> None:
    parts = operator_authority_parts(request_id="operator-nonce-contract")
    nonce = parts.approval_nonce

    assert nonce.quarantine_checksum == parts.quarantine.quarantine_checksum
    assert nonce.operator_identity_checksum == parts.operator_identity.identity_checksum
    assert nonce.approval_epoch == parts.quarantine.quarantine_epoch
    assert nonce.nonce_checksum == recompute_operator_approval_nonce_checksum(nonce)
    assert nonce.nonce_id == operator_approval_nonce_id(
        quarantine_checksum=parts.quarantine.quarantine_checksum,
        operator_identity_checksum=parts.operator_identity.identity_checksum,
        approval_epoch=parts.quarantine.quarantine_epoch,
    )


def test_operator_nonce_rejects_epoch_replay_and_is_immutable() -> None:
    parts = operator_authority_parts(request_id="operator-nonce-epoch")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_EPOCH_REPLAY.value
    ):
        build_operator_approval_nonce(
            quarantine=parts.quarantine,
            operator_identity=parts.operator_identity,
            approval_epoch=parts.quarantine.quarantine_epoch + 1,
        )
    with pytest.raises(FrozenInstanceError):
        parts.approval_nonce.approval_epoch = 2
    with pytest.raises(ValueError, match="nonce_checksum"):
        OperatorApprovalNonce(
            nonce_id=parts.approval_nonce.nonce_id,
            quarantine_checksum=parts.approval_nonce.quarantine_checksum,
            operator_identity_checksum=parts.approval_nonce.operator_identity_checksum,
            approval_epoch=parts.approval_nonce.approval_epoch,
            nonce_checksum="0" * 64,
        )


def test_operator_nonce_rejects_quarantine_and_identity_drift() -> None:
    quarantine_parts = operator_authority_parts(request_id="operator-nonce-quarantine-drift")
    identity_parts = operator_authority_parts(request_id="operator-nonce-identity-drift")
    object.__setattr__(quarantine_parts.quarantine, "quarantine_checksum", "1" * 64)
    object.__setattr__(identity_parts.operator_identity, "identity_checksum", "1" * 64)

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_QUARANTINE_CHECKSUM_DRIFT.value
    ):
        build_operator_approval_nonce(
            quarantine=quarantine_parts.quarantine,
            operator_identity=quarantine_parts.operator_identity,
            approval_epoch=quarantine_parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT.value
    ):
        build_operator_approval_nonce(
            quarantine=identity_parts.quarantine,
            operator_identity=identity_parts.operator_identity,
            approval_epoch=identity_parts.quarantine.quarantine_epoch,
        )
