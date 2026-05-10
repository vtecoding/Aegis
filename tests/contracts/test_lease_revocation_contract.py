"""Contract tests for ADR-0021 lease revocation decisions."""

from __future__ import annotations

import pytest
from tests.capability_lease_fixtures import capability_lease_parts, runtime_capability_lease

from aegis.execution.aegis_capability_lease import CapabilityLeaseReason
from aegis.execution.aegis_lease_revocation import (
    LeaseRevocationDecision,
    evaluate_runtime_lease_revocation,
    recompute_lease_revocation_decision_checksum,
)


def _revocation_decision(request_id: str = "lease-revocation-positive") -> LeaseRevocationDecision:
    lease = runtime_capability_lease(request_id=request_id)
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
    ) = capability_lease_parts(request_id=request_id)
    return evaluate_runtime_lease_revocation(
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


def test_lease_revocation_not_revoked_for_valid_lease() -> None:
    decision = _revocation_decision()

    assert decision.status == "NOT_REVOKED"
    assert decision.reason_code == CapabilityLeaseReason.CAPABILITY_LEASE_NOT_REVOKED.value
    assert decision.revocation_stage == "none"
    assert decision.revocation_checksum == recompute_lease_revocation_decision_checksum(decision)


def test_lease_revocation_decision_rejects_contradictory_fields() -> None:
    decision = _revocation_decision(request_id="lease-revocation-contract")

    with pytest.raises(ValueError, match="NOT_REVOKED"):
        LeaseRevocationDecision(
            status="NOT_REVOKED",
            reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_CHECKSUM_DRIFT.value,
            lease_checksum=decision.lease_checksum,
            revoked_evidence_checksum=decision.revoked_evidence_checksum,
            revocation_stage="lease_checksum",
        )
    with pytest.raises(ValueError, match="REVOKED"):
        LeaseRevocationDecision(
            status="REVOKED",
            reason_code=CapabilityLeaseReason.CAPABILITY_LEASE_CHECKSUM_DRIFT.value,
            lease_checksum=decision.lease_checksum,
            revoked_evidence_checksum=decision.revoked_evidence_checksum,
            revocation_stage="none",
        )


def test_lease_revocation_registry_drift_is_reason_coded() -> None:
    lease = runtime_capability_lease(request_id="lease-revocation-registry")
    (
        plan,
        decision,
        descriptor,
        certification,
        replay_proof,
        manifest,
        _,
        admission_decision,
        context_authority,
    ) = capability_lease_parts(request_id="lease-revocation-registry")

    revoked = evaluate_runtime_lease_revocation(
        lease=lease,
        admission_decision=admission_decision,
        backend_descriptor=descriptor,
        authority_manifest=manifest,
        registry_checksum="1" * 64,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        dispatch_plan=plan,
        firewall_decision=decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert revoked.status == "REVOKED"
    assert (
        revoked.reason_code == CapabilityLeaseReason.CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT.value
    )
    assert revoked.revocation_stage == "registry"


def test_lease_revocation_is_deterministic() -> None:
    first = _revocation_decision(request_id="lease-revocation-deterministic")
    second = _revocation_decision(request_id="lease-revocation-deterministic")

    assert first == second
    assert first.revocation_checksum == second.revocation_checksum
