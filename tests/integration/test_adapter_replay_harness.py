"""Integration tests for the ADR-0016 adapter replay harness."""

from __future__ import annotations

from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.adapter_replay import AdapterReplayRequest
from aegis.execution import prove_adapter_replay, replay_execution_adapter


def test_positive_adapter_replay_passes_from_valid_pipeline_evidence() -> None:
    request = adapter_replay_request(request_id="adapter-replay-positive")

    proof = prove_adapter_replay(request)

    assert proof.status == "PASSED"
    assert proof.mapping_checksum_match is True
    assert proof.runtime_target_checksum_match is True
    assert proof.qos_checksum_match is True
    assert proof.namespace_match is True
    assert proof.receipt_chain_match is True
    assert proof.mutation_detected is False


def test_replay_reconstructs_envelope_and_receipt_checksums() -> None:
    request = adapter_replay_request(request_id="adapter-replay-reconstruct")

    output = replay_execution_adapter(request)

    proof = prove_adapter_replay(request)

    assert output.envelope.envelope_checksum == request.expected_envelope.envelope_checksum
    assert output.adapter_receipt.adapter_receipt_checksum == proof.replayed_receipt_checksum


def test_missing_replay_critical_mapping_evidence_blocks_before_comparison() -> None:
    request = adapter_replay_request(request_id="adapter-replay-missing-evidence")
    object.__setattr__(request.expected_envelope, "adapter_mapping", None)

    proof = prove_adapter_replay(request)

    assert proof.status == "BLOCKED"
    assert proof.reason == "ADAPTER_REPLAY_MAPPING_EVIDENCE_MISSING"
    assert proof.replayed_envelope_checksum is None
    assert proof.failure_stage == "mapping_evidence"


def test_forged_ready_envelope_checksum_fails_replay_proof() -> None:
    request = adapter_replay_request(request_id="adapter-replay-forged-ready")
    object.__setattr__(request.expected_envelope, "envelope_checksum", "0" * 64)

    proof = prove_adapter_replay(request)
    assert proof.status == "FAILED"
    assert proof.reason == "ADAPTER_REPLAY_RECEIPT_CHAIN_MISMATCH"
    assert proof.mutation_detected is True


def test_valid_envelope_with_wrong_source_pipeline_result_fails() -> None:
    expected = adapter_replay_request(request_id="adapter-replay-source-a")
    wrong_source = adapter_replay_request(request_id="adapter-replay-source-b")
    request = AdapterReplayRequest(
        pipeline_result=wrong_source.pipeline_result,
        expected_envelope=expected.expected_envelope,
        expected_adapter_receipt=expected.expected_adapter_receipt,
    )

    proof = prove_adapter_replay(request)
    assert proof.status == "FAILED"
    assert proof.mutation_detected is True


def test_separately_valid_envelopes_swapped_across_pipeline_results_fail() -> None:
    move_request = adapter_replay_request(command="move", request_id="adapter-replay-move")
    stop_request = adapter_replay_request(command="stop", request_id="adapter-replay-stop")
    swapped = AdapterReplayRequest(
        pipeline_result=move_request.pipeline_result,
        expected_envelope=stop_request.expected_envelope,
        expected_adapter_receipt=stop_request.expected_adapter_receipt,
    )

    proof = prove_adapter_replay(swapped)
    assert proof.status == "FAILED"
    assert proof.reason == "ADAPTER_REPLAY_REPLAYED_ENVELOPE_NOT_READY"
    assert proof.mutation_detected is True
