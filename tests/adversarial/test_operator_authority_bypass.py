"""Adversarial bypass tests for ADR-0023 operator authority."""

from __future__ import annotations

import pytest
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_approval_replay import (
    build_authority_bound_approval_receipt,
    validate_approval_replay,
)
from aegis.execution.aegis_operator_authority import (
    OperatorAuthorityReason,
    build_operator_authority_manifest,
)
from aegis.execution.aegis_operator_identity import build_operator_identity_claim


def test_unknown_role_and_wildcard_role_fail_closed() -> None:
    parts = operator_authority_parts(request_id="operator-authority-bypass-role")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE.value
    ):
        build_operator_identity_claim(
            manifest=parts.operator_authority_manifest,
            operator_id="operator-001",
            operator_role="release.admin",
            context_authority_checksum=parts.context_authority.context_checksum,
            identity_epoch=parts.quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE.value
    ):
        build_operator_authority_manifest(
            allowed_operator_roles=("*",),
            allowed_approval_scopes=parts.operator_authority_manifest.allowed_approval_scopes,
            required_context_authority_checksum=parts.context_authority.context_checksum,
            approval_epoch=parts.quarantine.quarantine_epoch,
        )


def test_overbroad_scope_blocks_authority_bound_approval() -> None:
    parts = operator_authority_parts(request_id="operator-authority-bypass-scope")

    with pytest.raises(
        ValueError, match=OperatorAuthorityReason.OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE.value
    ):
        build_authority_bound_approval_receipt(
            quarantine=parts.quarantine,
            operator_identity=parts.operator_identity,
            authority_manifest=parts.operator_authority_manifest,
            approval_nonce=parts.approval_nonce,
            approval_status="APPROVED",
            approved_scope=parts.approval.approved_scope.union({"f" * 64}),
        )


def test_manifest_and_context_drift_block_replay_validation() -> None:
    manifest_parts = operator_authority_parts(request_id="operator-authority-manifest-drift")
    context_parts = operator_authority_parts(request_id="operator-authority-context-drift")
    object.__setattr__(manifest_parts.operator_authority_manifest, "manifest_checksum", "1" * 64)

    manifest_result = validate_approval_replay(
        quarantine=manifest_parts.quarantine,
        approval=manifest_parts.approval,
        operator_identity=manifest_parts.operator_identity,
        authority_manifest=manifest_parts.operator_authority_manifest,
        approval_nonce=manifest_parts.approval_nonce,
        capability_lease=manifest_parts.capability_lease,
        dispatch_plan=manifest_parts.dispatch_plan,
        backend_admission_decision=manifest_parts.backend_admission_decision,
        backend_descriptor=manifest_parts.backend_descriptor,
        authority_backend_manifest=manifest_parts.backend_authority_manifest,
        registry_checksum=manifest_parts.backend_registry.registry_checksum,
        backend_certification=manifest_parts.backend_certification,
        backend_replay_proof=manifest_parts.backend_replay_proof,
        firewall_decision=manifest_parts.firewall_decision,
        context_authority_checksum=manifest_parts.context_authority.context_checksum,
        current_lease_epoch=1,
    )
    context_result = validate_approval_replay(
        quarantine=context_parts.quarantine,
        approval=context_parts.approval,
        operator_identity=context_parts.operator_identity,
        authority_manifest=context_parts.operator_authority_manifest,
        approval_nonce=context_parts.approval_nonce,
        capability_lease=context_parts.capability_lease,
        dispatch_plan=context_parts.dispatch_plan,
        backend_admission_decision=context_parts.backend_admission_decision,
        backend_descriptor=context_parts.backend_descriptor,
        authority_backend_manifest=context_parts.backend_authority_manifest,
        registry_checksum=context_parts.backend_registry.registry_checksum,
        backend_certification=context_parts.backend_certification,
        backend_replay_proof=context_parts.backend_replay_proof,
        firewall_decision=context_parts.firewall_decision,
        context_authority_checksum="1" * 64,
        current_lease_epoch=1,
    )

    assert manifest_result.status == "BLOCKED"
    assert manifest_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_MANIFEST_DRIFT.value
    )
    assert context_result.status == "BLOCKED"
    assert context_result.reason_code == (
        OperatorAuthorityReason.OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT.value
    )
