"""Integration tests for ADR-0019 backend replay proof harness."""

from __future__ import annotations

from tests.backend_replay_fixtures import backend_replay_parts, backend_replay_request

from aegis.contracts.backend_replay import BackendReplayMutationProfile, BackendReplayRequest
from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
)
from aegis.contracts.runtime_dispatch import DispatchFirewallDecision, DispatchFirewallReason
from aegis.execution import prove_backend_replay, replay_runtime_backend
from aegis.execution.backend_replay_mutations import mutate_backend_replay_request_in_place


def test_valid_null_backend_certification_replays_to_passed() -> None:
    request = backend_replay_request(request_id="backend-replay-positive")

    proof = prove_backend_replay(request)

    assert proof.status == "PASSED"
    assert proof.reason_code == "BACKEND_REPLAY_PASSED"
    assert proof.zero_execution_verified is True
    assert proof.certification_match is True
    assert proof.receipt_match is True


def test_backend_replay_reconstructs_certification_and_receipt_independently() -> None:
    request = backend_replay_request(request_id="backend-replay-reconstruct")

    replayed = replay_runtime_backend(request)

    assert replayed.certification == request.expected_certification
    assert replayed.receipt == request.expected_receipt
    assert replayed.receipt.executed_count == 0


def test_invalid_firewall_decision_blocks_backend_replay() -> None:
    plan, _, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-blocked-firewall"
    )
    blocked_decision = DispatchFirewallDecision(
        status="BLOCKED",
        reason_code=DispatchFirewallReason.RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH.value,
        plan_checksum=plan.plan_checksum,
        source_replay_proof_checksum=plan.source_replay_proof_checksum,
        blocked_stage="dispatch_firewall",
    )
    request = BackendReplayRequest(
        dispatch_plan=plan,
        firewall_decision=blocked_decision,
        backend_descriptor=backend.descriptor,
        expected_certification=certification,
        expected_receipt=receipt,
    )

    proof = prove_backend_replay(request)

    assert proof.status == "BLOCKED"
    assert proof.reason_code == "BACKEND_REPLAY_FIREWALL_DECISION_NOT_ALLOWED"


def test_non_null_backend_descriptor_blocks_backend_replay() -> None:
    request = backend_replay_request(request_id="backend-replay-non-null")
    mutate_backend_replay_request_in_place(request, BackendReplayMutationProfile.BACKEND_KIND_DRIFT)

    proof = prove_backend_replay(request)

    assert proof.status == "BLOCKED"
    assert proof.reason_code == "BACKEND_REPLAY_BACKEND_KIND_NOT_NULL"


def test_backend_replay_requires_certified_null_expected_certification() -> None:
    plan, decision, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-cert-required"
    )
    blocked_certification = BackendCertificationResult(
        status=BackendCertificationStatus.BLOCKED,
        reason_code=BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED.value,
        dispatch_plan_checksum=certification.dispatch_plan_checksum,
        firewall_decision_checksum=certification.firewall_decision_checksum,
        backend_descriptor_checksum=certification.backend_descriptor_checksum,
        no_execution_guarantee=certification.no_execution_guarantee,
        no_io_guarantee=False,
        no_async_guarantee=certification.no_async_guarantee,
        capability_scope_match=certification.capability_scope_match,
        runtime_kind_scope_match=certification.runtime_kind_scope_match,
    )
    request = BackendReplayRequest(
        dispatch_plan=plan,
        firewall_decision=decision,
        backend_descriptor=backend.descriptor,
        expected_certification=blocked_certification,
        expected_receipt=receipt,
    )

    proof = prove_backend_replay(request)

    assert proof.status == "BLOCKED"
    assert proof.reason_code == "BACKEND_REPLAY_EXPECTED_CERTIFICATION_NOT_CERTIFIED_NULL"


def test_repeated_backend_replay_is_deterministic() -> None:
    request = backend_replay_request(request_id="backend-replay-repeat")

    first = prove_backend_replay(request)
    second = prove_backend_replay(request)

    assert first == second
    assert first.proof_checksum == second.proof_checksum
