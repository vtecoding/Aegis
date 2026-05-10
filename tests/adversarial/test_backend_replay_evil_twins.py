"""Adversarial tests for ADR-0019 backend replay evil twins."""

from __future__ import annotations

import pytest
from tests.backend_replay_fixtures import backend_replay_request

from aegis.contracts.aegis_backend_replay import BackendReplayMutationProfile
from aegis.execution import mutate_backend_replay_request_in_place, prove_backend_replay


@pytest.mark.parametrize(
    ("mutation_profile", "expected_status", "expected_reason"),
    (
        (
            BackendReplayMutationProfile.DISPATCH_PLAN_CHECKSUM_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_DISPATCH_PLAN_CHECKSUM_DRIFT",
        ),
        (
            BackendReplayMutationProfile.FIREWALL_DECISION_CHECKSUM_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_FIREWALL_DECISION_CHECKSUM_DRIFT",
        ),
        (
            BackendReplayMutationProfile.BACKEND_DESCRIPTOR_CHECKSUM_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_DESCRIPTOR_CHECKSUM_DRIFT",
        ),
        (
            BackendReplayMutationProfile.BACKEND_MODE_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY",
        ),
        (
            BackendReplayMutationProfile.EXECUTION_FLAG_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_EXECUTION_CAPABILITY_CLAIMED",
        ),
        (
            BackendReplayMutationProfile.IO_FLAG_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_IO_CAPABILITY_CLAIMED",
        ),
        (
            BackendReplayMutationProfile.ASYNC_FLAG_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_ASYNC_CAPABILITY_CLAIMED",
        ),
        (
            BackendReplayMutationProfile.CAPABILITY_SCOPE_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_CAPABILITY_SCOPE_DRIFT",
        ),
        (
            BackendReplayMutationProfile.RUNTIME_KIND_SCOPE_DRIFT,
            "BLOCKED",
            "BACKEND_REPLAY_RUNTIME_KIND_SCOPE_DRIFT",
        ),
        (
            BackendReplayMutationProfile.CERTIFICATION_CHECKSUM_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_CERTIFICATION_CHECKSUM_DRIFT",
        ),
        (
            BackendReplayMutationProfile.RECEIPT_CHECKSUM_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_RECEIPT_CHECKSUM_DRIFT",
        ),
        (
            BackendReplayMutationProfile.RECEIPT_EXECUTED_COUNT_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO",
        ),
        (
            BackendReplayMutationProfile.RECEIPT_ITEM_COUNT_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT",
        ),
        (
            BackendReplayMutationProfile.RECEIPT_PLAN_LINK_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_RECEIPT_PLAN_MISMATCH",
        ),
        (
            BackendReplayMutationProfile.CERTIFICATION_FIREWALL_LINK_DRIFT,
            "FAILED",
            "BACKEND_REPLAY_CERTIFICATION_FIREWALL_DECISION_MISMATCH",
        ),
        (
            BackendReplayMutationProfile.CROSS_PLAN_CERTIFICATION_SWAP,
            "FAILED",
            "BACKEND_REPLAY_CERTIFICATION_DISPATCH_PLAN_MISMATCH",
        ),
        (
            BackendReplayMutationProfile.CROSS_BACKEND_RECEIPT_SWAP,
            "FAILED",
            "BACKEND_REPLAY_RECEIPT_BACKEND_DESCRIPTOR_MISMATCH",
        ),
    ),
)
def test_backend_replay_mutation_profiles_fail_closed(
    mutation_profile: BackendReplayMutationProfile,
    expected_status: str,
    expected_reason: str,
) -> None:
    request = backend_replay_request(request_id=f"backend-replay-{mutation_profile.value.lower()}")
    mutate_backend_replay_request_in_place(request, mutation_profile)

    proof = prove_backend_replay(request)

    assert proof.status == expected_status
    assert proof.reason_code == expected_reason
    assert proof.status != "PASSED"


def test_backend_replay_proof_checksum_changes_under_mutation() -> None:
    clean = prove_backend_replay(backend_replay_request(request_id="backend-replay-clean"))
    mutated_request = backend_replay_request(request_id="backend-replay-mutated")
    mutate_backend_replay_request_in_place(
        mutated_request,
        BackendReplayMutationProfile.CERTIFICATION_CHECKSUM_DRIFT,
    )

    mutated = prove_backend_replay(mutated_request)

    assert clean.proof_checksum != mutated.proof_checksum
