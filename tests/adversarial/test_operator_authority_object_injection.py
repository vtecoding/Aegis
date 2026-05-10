"""Runtime object injection tests for ADR-0023 operator authority."""

from __future__ import annotations

import pytest
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_approval_replay import build_authority_bound_approval_receipt
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityReason,
    build_operator_authority_manifest,
)
from aegis.execution.aegis_operator_identity import (
    build_operator_approval_nonce,
    build_operator_identity_claim,
)


def test_runtime_object_injection_blocks_manifest_identity_nonce_and_approval() -> None:
    parts = operator_authority_parts(request_id="operator-authority-object")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
    ):
        build_operator_authority_manifest(
            allowed_operator_roles=("release.operator",),
            allowed_approval_scopes={"mutable": "scope"},
            required_context_authority_checksum=parts.context_authority.context_checksum,
            approval_epoch=parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError,
        match=OperatorAuthorityReason.OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST.value,
    ):
        build_operator_identity_claim(
            manifest=object(),
            operator_id="operator-001",
            operator_role="release.operator",
            context_authority_checksum=parts.context_authority.context_checksum,
            identity_epoch=parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
    ):
        build_operator_approval_nonce(
            quarantine=object(),
            operator_identity=parts.operator_identity,
            approval_epoch=parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
    ):
        build_authority_bound_approval_receipt(
            quarantine=parts.quarantine,
            operator_identity=object(),
            authority_manifest=parts.operator_authority_manifest,
            approval_nonce=parts.approval_nonce,
            approval_status="APPROVED",
            approved_scope=parts.approval.approved_scope,
        )
