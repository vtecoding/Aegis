"""Contract tests for ADR-0023 operator authority manifests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.aegis_constants import OPERATOR_AUTHORITY_CONTRACT_VERSION
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityManifest,
    OperatorAuthorityManifestStatus,
    OperatorAuthorityReason,
    build_operator_authority_manifest,
    normalize_operator_approval_scopes,
    normalize_operator_role,
    operator_authority_id,
    recompute_operator_authority_manifest_checksum,
)


def test_operator_authority_manifest_binds_roles_scopes_context_and_epoch() -> None:
    parts = operator_authority_parts(request_id="operator-authority-contract")
    manifest = parts.operator_authority_manifest

    assert manifest.authority_version == OPERATOR_AUTHORITY_CONTRACT_VERSION
    assert manifest.manifest_status is OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY
    assert manifest.allowed_operator_roles == frozenset({"release.operator"})
    assert manifest.allowed_approval_scopes == parts.approval.approved_scope
    assert manifest.required_context_authority_checksum == parts.context_authority.context_checksum
    assert manifest.approval_epoch == parts.quarantine.quarantine_epoch
    assert manifest.manifest_checksum == recompute_operator_authority_manifest_checksum(manifest)


def test_operator_authority_manifest_is_immutable() -> None:
    parts = operator_authority_parts(request_id="operator-authority-immutable")

    with pytest.raises(FrozenInstanceError):
        parts.operator_authority_manifest.approval_epoch = 2


def test_operator_authority_rejects_wildcard_roles_and_scopes() -> None:
    parts = operator_authority_parts(request_id="operator-authority-wildcards")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE.value
    ):
        normalize_operator_role("*")
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE.value
    ):
        normalize_operator_approval_scopes(("*",))
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY.value
    ):
        normalize_operator_approval_scopes(())
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE.value
    ):
        build_operator_authority_manifest(
            allowed_operator_roles=("*",),
            allowed_approval_scopes=parts.approval.approved_scope,
            required_context_authority_checksum=parts.context_authority.context_checksum,
            approval_epoch=parts.quarantine.quarantine_epoch,
        )


def test_operator_authority_rejects_mutable_and_callable_injection() -> None:
    parts = operator_authority_parts(request_id="operator-authority-object-injection")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
    ):
        normalize_operator_approval_scopes({"mutable": "scope"})
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION.value
    ):
        normalize_operator_approval_scopes((lambda: "scope",))
    with pytest.raises(ValueError, match="manifest_checksum"):
        OperatorAuthorityManifest(
            authority_id=operator_authority_id(
                authority_version=OPERATOR_AUTHORITY_CONTRACT_VERSION,
                allowed_operator_roles=parts.operator_authority_manifest.allowed_operator_roles,
                allowed_approval_scopes=parts.operator_authority_manifest.allowed_approval_scopes,
                required_context_authority_checksum=parts.context_authority.context_checksum,
                approval_epoch=parts.quarantine.quarantine_epoch,
                manifest_status=OperatorAuthorityManifestStatus.ACTIVE_STRUCTURAL_ONLY,
            ),
            authority_version=OPERATOR_AUTHORITY_CONTRACT_VERSION,
            allowed_operator_roles=parts.operator_authority_manifest.allowed_operator_roles,
            allowed_approval_scopes=parts.operator_authority_manifest.allowed_approval_scopes,
            required_context_authority_checksum=parts.context_authority.context_checksum,
            approval_epoch=parts.quarantine.quarantine_epoch,
            manifest_status="ACTIVE_STRUCTURAL_ONLY",
            manifest_checksum="0" * 64,
        )
