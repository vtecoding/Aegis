"""Invariant tests for ADR-0022 command quarantine."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.command_quarantine_fixtures import (
    command_quarantine_envelope,
    command_quarantine_parts,
    operator_approval_receipt,
    quarantine_release_decision,
)

from aegis.execution.aegis_command_quarantine import recompute_command_quarantine_checksum
from aegis.execution.aegis_operator_approval import recompute_operator_approval_checksum
from aegis.execution.aegis_quarantine_release import (
    evaluate_quarantine_release,
    recompute_quarantine_release_decision_checksum,
)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_command_quarantine_is_deterministic(request_number: int) -> None:
    first = command_quarantine_envelope(request_id=f"quarantine-invariant-{request_number}")
    second = command_quarantine_envelope(request_id=f"quarantine-invariant-{request_number}")

    assert first == second
    assert first.quarantine_checksum == second.quarantine_checksum


def test_invariant_quarantine_release_is_deterministic() -> None:
    first = quarantine_release_decision(request_id="quarantine-invariant-release")
    second = quarantine_release_decision(request_id="quarantine-invariant-release")

    assert first == second
    assert first.decision_checksum == second.decision_checksum


def test_invariant_missing_approval_never_releases() -> None:
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
    ) = command_quarantine_parts(request_id="quarantine-invariant-missing")
    quarantine = command_quarantine_envelope(request_id="quarantine-invariant-missing")

    release = evaluate_quarantine_release(
        quarantine=quarantine,
        approval=None,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert release.status == "BLOCKED"
    assert release.released_item_count == 0


def test_invariant_release_checksum_changes_on_bound_field_change() -> None:
    first = quarantine_release_decision(
        request_id="quarantine-invariant-checksum", quarantine_epoch=1
    )
    second = quarantine_release_decision(
        request_id="quarantine-invariant-checksum", quarantine_epoch=2
    )

    assert first.decision_checksum == recompute_quarantine_release_decision_checksum(first)
    assert second.decision_checksum == recompute_quarantine_release_decision_checksum(second)
    assert first.decision_checksum != second.decision_checksum


def test_invariant_quarantine_and_approval_checksums_recompute() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-invariant-recompute")
    approval = operator_approval_receipt(quarantine=quarantine)

    assert quarantine.quarantine_checksum == recompute_command_quarantine_checksum(quarantine)
    assert approval.approval_checksum == recompute_operator_approval_checksum(approval)


def test_invariant_quarantine_release_does_not_mutate_source_evidence() -> None:
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
    ) = command_quarantine_parts(request_id="quarantine-invariant-no-mutation")
    source_checksums = (
        dispatch_plan.plan_checksum,
        firewall_decision.decision_checksum,
        backend_descriptor.descriptor_checksum,
        backend_certification.certification_checksum,
        backend_replay_proof.proof_checksum,
        authority_manifest.manifest_checksum,
        backend_registry.registry_checksum,
        backend_admission_decision.decision_checksum,
        context_authority.context_checksum,
        capability_lease.lease_checksum,
    )

    quarantine_release_decision(request_id="quarantine-invariant-no-mutation")

    assert source_checksums == (
        dispatch_plan.plan_checksum,
        firewall_decision.decision_checksum,
        backend_descriptor.descriptor_checksum,
        backend_certification.certification_checksum,
        backend_replay_proof.proof_checksum,
        authority_manifest.manifest_checksum,
        backend_registry.registry_checksum,
        backend_admission_decision.decision_checksum,
        context_authority.context_checksum,
        capability_lease.lease_checksum,
    )
