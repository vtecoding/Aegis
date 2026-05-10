"""Invariant tests for ADR-0021 runtime capability leases."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.execution.aegis_capability_lease import recompute_runtime_capability_lease_checksum
from aegis.execution.aegis_lease_revocation import evaluate_runtime_lease_revocation
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_capability_lease_issue_is_deterministic(request_number: int) -> None:
    first = runtime_capability_lease(request_id=f"lease-invariant-{request_number}")
    second = runtime_capability_lease(request_id=f"lease-invariant-{request_number}")

    assert first == second
    assert first.lease_checksum == second.lease_checksum


def test_invariant_lease_validation_and_revocation_are_deterministic() -> None:
    lease = runtime_capability_lease(request_id="lease-invariant-validation")
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id="lease-invariant-validation")

    first_validation = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )
    second_validation = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )
    first_revocation = evaluate_runtime_lease_revocation(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )
    second_revocation = evaluate_runtime_lease_revocation(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert first_validation == second_validation
    assert first_revocation == second_revocation


def test_invariant_no_stale_lease_validates_after_epoch_change() -> None:
    lease = runtime_capability_lease(request_id="lease-invariant-stale", lease_epoch=1)
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id="lease-invariant-stale")

    result = validate_runtime_capability_lease(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=2,
    )

    assert result.status != "VALID"


def test_invariant_lease_checksum_changes_on_bound_field_change() -> None:
    lease = runtime_capability_lease(request_id="lease-invariant-checksum", lease_epoch=1)
    changed = runtime_capability_lease(request_id="lease-invariant-checksum", lease_epoch=2)

    assert lease.lease_checksum == recompute_runtime_capability_lease_checksum(lease)
    assert changed.lease_checksum == recompute_runtime_capability_lease_checksum(changed)
    assert lease.lease_checksum != changed.lease_checksum


def test_invariant_lease_issue_does_not_mutate_source_evidence() -> None:
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        registry,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id="lease-invariant-no-mutation")
    source_checksums = (
        plan.plan_checksum,
        decision.decision_checksum,
        descriptor.descriptor_checksum,
        certification.certification_checksum,
        replay_proof.proof_checksum,
        manifest.manifest_checksum,
        registry.registry_checksum,
        admission_decision.decision_checksum,
        context_authority.context_checksum,
    )

    runtime_capability_lease(request_id="lease-invariant-no-mutation")

    assert source_checksums == (
        plan.plan_checksum,
        decision.decision_checksum,
        descriptor.descriptor_checksum,
        certification.certification_checksum,
        replay_proof.proof_checksum,
        manifest.manifest_checksum,
        registry.registry_checksum,
        admission_decision.decision_checksum,
        context_authority.context_checksum,
    )
