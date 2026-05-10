"""Invariant tests for deterministic adapter replay proofs."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.adapter_replay import AdapterReplayProofResult
from aegis.execution import prove_adapter_replay


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_adapter_replay_proof_is_deterministic(request_number: int) -> None:
    request = adapter_replay_request(request_id=f"adapter-replay-determinism-{request_number}")

    first = prove_adapter_replay(request)
    second = prove_adapter_replay(request)

    assert first == second
    assert first.proof_checksum == second.proof_checksum


def test_invariant_passed_replay_has_no_nullable_proof_critical_fields() -> None:
    proof = prove_adapter_replay(adapter_replay_request(request_id="adapter-replay-non-null"))

    assert proof.status == "PASSED"
    assert proof.expected_envelope_checksum is not None
    assert proof.replayed_envelope_checksum is not None
    assert proof.expected_receipt_checksum is not None
    assert proof.replayed_receipt_checksum is not None


def test_invariant_adapter_replay_does_not_mutate_request_evidence() -> None:
    request = adapter_replay_request(request_id="adapter-replay-non-mutating")
    envelope_checksum = request.expected_envelope.envelope_checksum
    receipt_checksum = request.expected_adapter_receipt.adapter_receipt_checksum

    prove_adapter_replay(request)

    assert request.expected_envelope.envelope_checksum == envelope_checksum
    assert request.expected_adapter_receipt.adapter_receipt_checksum == receipt_checksum


def test_invariant_replay_proof_checksum_changes_when_bound_field_changes() -> None:
    proof = prove_adapter_replay(adapter_replay_request(request_id="adapter-replay-bound-field"))
    changed = AdapterReplayProofResult(
        status="FAILED",
        reason="ADAPTER_REPLAY_NAMESPACE_MISMATCH",
        source_pipeline_checksum=proof.source_pipeline_checksum,
        expected_envelope_checksum=proof.expected_envelope_checksum,
        replayed_envelope_checksum=proof.replayed_envelope_checksum,
        expected_receipt_checksum=proof.expected_receipt_checksum,
        replayed_receipt_checksum=proof.replayed_receipt_checksum,
        mapping_checksum_match=True,
        runtime_target_checksum_match=True,
        qos_checksum_match=True,
        namespace_match=False,
        receipt_chain_match=True,
        mutation_detected=True,
        failure_stage="adapter_replay_proof",
    )

    assert proof.proof_checksum != changed.proof_checksum
