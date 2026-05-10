"""Invariant tests for deterministic backend replay proofs."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.backend_replay_fixtures import backend_replay_request

from aegis.contracts.backend_replay import BackendReplayProofResult
from aegis.execution import prove_backend_replay


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_backend_replay_proof_is_deterministic(request_number: int) -> None:
    request = backend_replay_request(request_id=f"backend-replay-determinism-{request_number}")

    first = prove_backend_replay(request)
    second = prove_backend_replay(request)

    assert first == second
    assert first.proof_checksum == second.proof_checksum


def test_invariant_passed_backend_replay_verifies_zero_execution() -> None:
    proof = prove_backend_replay(backend_replay_request(request_id="backend-replay-zero"))

    assert proof.status == "PASSED"
    assert proof.zero_execution_verified is True
    assert proof.receipt_match is True


def test_invariant_backend_replay_does_not_mutate_request_evidence() -> None:
    request = backend_replay_request(request_id="backend-replay-non-mutating")
    plan_checksum = request.dispatch_plan.plan_checksum
    decision_checksum = request.firewall_decision.decision_checksum
    descriptor_checksum = request.backend_descriptor.descriptor_checksum
    certification_checksum = request.expected_certification.certification_checksum
    receipt_checksum = request.expected_receipt.receipt_checksum

    prove_backend_replay(request)

    assert request.dispatch_plan.plan_checksum == plan_checksum
    assert request.firewall_decision.decision_checksum == decision_checksum
    assert request.backend_descriptor.descriptor_checksum == descriptor_checksum
    assert request.expected_certification.certification_checksum == certification_checksum
    assert request.expected_receipt.receipt_checksum == receipt_checksum


def test_invariant_backend_replay_proof_checksum_changes_when_bound_field_changes() -> None:
    proof = prove_backend_replay(backend_replay_request(request_id="backend-replay-bound-field"))
    changed = BackendReplayProofResult(
        status="FAILED",
        reason_code="BACKEND_REPLAY_RECEIPT_MISMATCH",
        dispatch_plan_checksum=proof.dispatch_plan_checksum,
        firewall_decision_checksum=proof.firewall_decision_checksum,
        backend_descriptor_checksum=proof.backend_descriptor_checksum,
        expected_certification_checksum=proof.expected_certification_checksum,
        replayed_certification_checksum=proof.replayed_certification_checksum,
        expected_receipt_checksum=proof.expected_receipt_checksum,
        replayed_receipt_checksum="1" * 64,
        zero_execution_verified=True,
        scope_match_verified=True,
        certification_match=True,
        receipt_match=False,
        mutation_detected=True,
        failure_stage="receipt",
    )

    assert proof.proof_checksum != changed.proof_checksum
