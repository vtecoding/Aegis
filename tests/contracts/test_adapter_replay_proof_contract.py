"""Contract tests for ADR-0016 adapter replay proof results."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.aegis_adapter_replay import (
    AdapterReplayProofResult,
    adapter_replay_proof_checksum,
    recompute_adapter_replay_proof_checksum,
)
from aegis.execution import prove_adapter_replay


def test_adapter_replay_proof_result_binds_positive_replay() -> None:
    proof = prove_adapter_replay(adapter_replay_request())

    assert proof.status == "PASSED"
    assert proof.reason == "ADAPTER_REPLAY_PASSED"
    assert proof.expected_envelope_checksum == proof.replayed_envelope_checksum
    assert proof.expected_receipt_checksum == proof.replayed_receipt_checksum
    assert proof.proof_checksum == recompute_adapter_replay_proof_checksum(proof)


def test_adapter_replay_proof_checksum_helper_is_canonical() -> None:
    proof = prove_adapter_replay(adapter_replay_request(request_id="adapter-replay-proof-helper"))

    assert proof.proof_checksum == adapter_replay_proof_checksum(
        status=proof.status,
        reason=proof.reason,
        source_pipeline_checksum=proof.source_pipeline_checksum,
        expected_envelope_checksum=proof.expected_envelope_checksum,
        replayed_envelope_checksum=proof.replayed_envelope_checksum,
        expected_receipt_checksum=proof.expected_receipt_checksum,
        replayed_receipt_checksum=proof.replayed_receipt_checksum,
        mapping_checksum_match=proof.mapping_checksum_match,
        runtime_target_checksum_match=proof.runtime_target_checksum_match,
        qos_checksum_match=proof.qos_checksum_match,
        namespace_match=proof.namespace_match,
        receipt_chain_match=proof.receipt_chain_match,
        mutation_detected=proof.mutation_detected,
        failure_stage=proof.failure_stage,
    )


def test_passed_adapter_replay_proof_rejects_unknown_subchecks() -> None:
    with pytest.raises(ValueError, match="sub-check"):
        AdapterReplayProofResult(
            status="PASSED",
            reason="ADAPTER_REPLAY_PASSED",
            source_pipeline_checksum="a" * 64,
            expected_envelope_checksum="b" * 64,
            replayed_envelope_checksum="b" * 64,
            expected_receipt_checksum="c" * 64,
            replayed_receipt_checksum="c" * 64,
            mapping_checksum_match=False,
            runtime_target_checksum_match=True,
            qos_checksum_match=True,
            namespace_match=True,
            receipt_chain_match=True,
            mutation_detected=False,
            failure_stage=None,
        )


def test_passed_adapter_replay_proof_rejects_nullable_critical_checksums() -> None:
    with pytest.raises(ValueError, match="proof-critical"):
        AdapterReplayProofResult(
            status="PASSED",
            reason="ADAPTER_REPLAY_PASSED",
            source_pipeline_checksum="a" * 64,
            expected_envelope_checksum=None,
            replayed_envelope_checksum="b" * 64,
            expected_receipt_checksum="c" * 64,
            replayed_receipt_checksum="c" * 64,
            mapping_checksum_match=True,
            runtime_target_checksum_match=True,
            qos_checksum_match=True,
            namespace_match=True,
            receipt_chain_match=True,
            mutation_detected=False,
            failure_stage=None,
        )


def test_adapter_replay_proof_checksum_changes_when_bound_field_changes() -> None:
    baseline = AdapterReplayProofResult(
        status="FAILED",
        reason="ADAPTER_REPLAY_MAPPING_CHECKSUM_MISMATCH",
        source_pipeline_checksum="a" * 64,
        expected_envelope_checksum="b" * 64,
        replayed_envelope_checksum="c" * 64,
        expected_receipt_checksum="d" * 64,
        replayed_receipt_checksum="e" * 64,
        mapping_checksum_match=False,
        runtime_target_checksum_match=True,
        qos_checksum_match=True,
        namespace_match=True,
        receipt_chain_match=True,
        mutation_detected=True,
        failure_stage="adapter_replay_proof",
    )
    changed = AdapterReplayProofResult(
        status="FAILED",
        reason="ADAPTER_REPLAY_NAMESPACE_MISMATCH",
        source_pipeline_checksum="a" * 64,
        expected_envelope_checksum="b" * 64,
        replayed_envelope_checksum="c" * 64,
        expected_receipt_checksum="d" * 64,
        replayed_receipt_checksum="e" * 64,
        mapping_checksum_match=True,
        runtime_target_checksum_match=True,
        qos_checksum_match=True,
        namespace_match=False,
        receipt_chain_match=True,
        mutation_detected=True,
        failure_stage="adapter_replay_proof",
    )

    assert baseline.proof_checksum != changed.proof_checksum


def test_adapter_replay_proof_rejects_forged_proof_checksum() -> None:
    with pytest.raises(ValueError, match="proof_checksum"):
        AdapterReplayProofResult(
            status="FAILED",
            reason="ADAPTER_REPLAY_MAPPING_CHECKSUM_MISMATCH",
            source_pipeline_checksum="a" * 64,
            expected_envelope_checksum="b" * 64,
            replayed_envelope_checksum="c" * 64,
            expected_receipt_checksum="d" * 64,
            replayed_receipt_checksum="e" * 64,
            mapping_checksum_match=False,
            runtime_target_checksum_match=True,
            qos_checksum_match=True,
            namespace_match=True,
            receipt_chain_match=True,
            mutation_detected=True,
            failure_stage="adapter_replay_proof",
            proof_checksum="0" * 64,
        )
