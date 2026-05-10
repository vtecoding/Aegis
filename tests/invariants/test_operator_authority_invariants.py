"""Invariant tests for ADR-0023 operator authority and replay validation."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_approval_replay import (
    recompute_approval_replay_validation_checksum,
    recompute_authority_bound_approval_checksum,
)
from aegis.execution.aegis_operator_authority import recompute_operator_authority_manifest_checksum
from aegis.execution.aegis_operator_identity import (
    recompute_operator_approval_nonce_checksum,
    recompute_operator_identity_claim_checksum,
)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_operator_authority_replay_is_deterministic(request_number: int) -> None:
    first = operator_authority_parts(request_id=f"operator-authority-invariant-{request_number}")
    second = operator_authority_parts(request_id=f"operator-authority-invariant-{request_number}")

    assert first.operator_authority_manifest == second.operator_authority_manifest
    assert first.operator_identity == second.operator_identity
    assert first.approval_nonce == second.approval_nonce
    assert first.approval == second.approval
    assert first.replay_validation == second.replay_validation


def test_invariant_operator_authority_checksums_recompute() -> None:
    parts = operator_authority_parts(request_id="operator-authority-invariant-recompute")

    assert parts.operator_authority_manifest.manifest_checksum == (
        recompute_operator_authority_manifest_checksum(parts.operator_authority_manifest)
    )
    assert parts.operator_identity.identity_checksum == recompute_operator_identity_claim_checksum(
        parts.operator_identity
    )
    assert parts.approval_nonce.nonce_checksum == recompute_operator_approval_nonce_checksum(
        parts.approval_nonce
    )
    assert parts.approval.authority_bound_checksum == recompute_authority_bound_approval_checksum(
        parts.approval
    )
    assert parts.replay_validation.replay_validation_checksum == (
        recompute_approval_replay_validation_checksum(parts.replay_validation)
    )


def test_invariant_approval_checksum_changes_on_bound_field_change() -> None:
    first = operator_authority_parts(
        request_id="operator-authority-invariant-checksum", operator_id="operator-001"
    )
    second = operator_authority_parts(
        request_id="operator-authority-invariant-checksum", operator_id="operator-002"
    )

    assert first.operator_identity.identity_checksum != second.operator_identity.identity_checksum
    assert first.approval_nonce.nonce_checksum != second.approval_nonce.nonce_checksum
    assert first.approval.authority_bound_checksum != second.approval.authority_bound_checksum
    assert first.replay_validation.replay_validation_checksum != (
        second.replay_validation.replay_validation_checksum
    )
