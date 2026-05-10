"""Contract tests for ADR-0019 backend replay proof results."""

from __future__ import annotations

import pytest
from tests.backend_replay_fixtures import backend_replay_request

from aegis.contracts.aegis_backend_replay import (
    BackendReplayProofResult,
    backend_replay_proof_checksum,
    recompute_backend_replay_proof_checksum,
)
from aegis.execution import prove_backend_replay


def test_backend_replay_proof_result_binds_positive_replay() -> None:
    proof = prove_backend_replay(backend_replay_request())

    assert proof.status == "PASSED"
    assert proof.reason_code == "BACKEND_REPLAY_PASSED"
    assert proof.expected_certification_checksum == proof.replayed_certification_checksum
    assert proof.expected_receipt_checksum == proof.replayed_receipt_checksum
    assert proof.zero_execution_verified is True
    assert proof.scope_match_verified is True
    assert proof.certification_match is True
    assert proof.receipt_match is True
    assert proof.proof_checksum == recompute_backend_replay_proof_checksum(proof)


def test_backend_replay_proof_checksum_helper_is_canonical() -> None:
    proof = prove_backend_replay(backend_replay_request(request_id="backend-replay-proof-helper"))

    assert proof.proof_checksum == backend_replay_proof_checksum(
        status=proof.status,
        reason_code=proof.reason_code,
        dispatch_plan_checksum=proof.dispatch_plan_checksum,
        firewall_decision_checksum=proof.firewall_decision_checksum,
        backend_descriptor_checksum=proof.backend_descriptor_checksum,
        expected_certification_checksum=proof.expected_certification_checksum,
        replayed_certification_checksum=proof.replayed_certification_checksum,
        expected_receipt_checksum=proof.expected_receipt_checksum,
        replayed_receipt_checksum=proof.replayed_receipt_checksum,
        zero_execution_verified=proof.zero_execution_verified,
        scope_match_verified=proof.scope_match_verified,
        certification_match=proof.certification_match,
        receipt_match=proof.receipt_match,
        mutation_detected=proof.mutation_detected,
        failure_stage=proof.failure_stage,
    )


def test_passed_backend_replay_proof_rejects_failed_subchecks() -> None:
    with pytest.raises(ValueError, match="sub-check"):
        BackendReplayProofResult(
            status="PASSED",
            reason_code="BACKEND_REPLAY_PASSED",
            dispatch_plan_checksum="a" * 64,
            firewall_decision_checksum="b" * 64,
            backend_descriptor_checksum="c" * 64,
            expected_certification_checksum="d" * 64,
            replayed_certification_checksum="d" * 64,
            expected_receipt_checksum="e" * 64,
            replayed_receipt_checksum="e" * 64,
            zero_execution_verified=False,
            scope_match_verified=True,
            certification_match=True,
            receipt_match=True,
            mutation_detected=False,
            failure_stage=None,
        )


def test_passed_backend_replay_proof_rejects_nullable_replayed_checksums() -> None:
    with pytest.raises(ValueError, match="replayed checksums"):
        BackendReplayProofResult(
            status="PASSED",
            reason_code="BACKEND_REPLAY_PASSED",
            dispatch_plan_checksum="a" * 64,
            firewall_decision_checksum="b" * 64,
            backend_descriptor_checksum="c" * 64,
            expected_certification_checksum="d" * 64,
            replayed_certification_checksum=None,
            expected_receipt_checksum="e" * 64,
            replayed_receipt_checksum="e" * 64,
            zero_execution_verified=True,
            scope_match_verified=True,
            certification_match=True,
            receipt_match=True,
            mutation_detected=False,
            failure_stage=None,
        )


def test_backend_replay_proof_checksum_changes_when_bound_field_changes() -> None:
    baseline = BackendReplayProofResult(
        status="FAILED",
        reason_code="BACKEND_REPLAY_CERTIFICATION_MISMATCH",
        dispatch_plan_checksum="a" * 64,
        firewall_decision_checksum="b" * 64,
        backend_descriptor_checksum="c" * 64,
        expected_certification_checksum="d" * 64,
        replayed_certification_checksum="e" * 64,
        expected_receipt_checksum="f" * 64,
        replayed_receipt_checksum="1" * 64,
        zero_execution_verified=True,
        scope_match_verified=True,
        certification_match=False,
        receipt_match=True,
        mutation_detected=True,
        failure_stage="certification",
    )
    changed = BackendReplayProofResult(
        status="FAILED",
        reason_code="BACKEND_REPLAY_RECEIPT_MISMATCH",
        dispatch_plan_checksum="a" * 64,
        firewall_decision_checksum="b" * 64,
        backend_descriptor_checksum="c" * 64,
        expected_certification_checksum="d" * 64,
        replayed_certification_checksum="d" * 64,
        expected_receipt_checksum="f" * 64,
        replayed_receipt_checksum="1" * 64,
        zero_execution_verified=True,
        scope_match_verified=True,
        certification_match=True,
        receipt_match=False,
        mutation_detected=True,
        failure_stage="receipt",
    )

    assert baseline.proof_checksum != changed.proof_checksum


def test_backend_replay_proof_rejects_forged_proof_checksum() -> None:
    with pytest.raises(ValueError, match="proof_checksum"):
        BackendReplayProofResult(
            status="FAILED",
            reason_code="BACKEND_REPLAY_RECEIPT_MISMATCH",
            dispatch_plan_checksum="a" * 64,
            firewall_decision_checksum="b" * 64,
            backend_descriptor_checksum="c" * 64,
            expected_certification_checksum="d" * 64,
            replayed_certification_checksum="e" * 64,
            expected_receipt_checksum="f" * 64,
            replayed_receipt_checksum="1" * 64,
            zero_execution_verified=True,
            scope_match_verified=True,
            certification_match=False,
            receipt_match=False,
            mutation_detected=True,
            failure_stage="receipt",
            proof_checksum="0" * 64,
        )
