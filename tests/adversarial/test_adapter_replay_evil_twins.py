"""Adversarial ADR-0016 adapter replay evil-twin coverage."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.adapter_replay import (
    AdapterReplayMutationProfile,
    recompute_adapter_replay_proof_checksum,
)
from aegis.execution import mutate_adapter_replay_request_in_place, prove_adapter_replay


@pytest.mark.parametrize(
    "mutation_profile",
    tuple(
        profile
        for profile in AdapterReplayMutationProfile
        if profile is not AdapterReplayMutationProfile.NONE
    ),
)
def test_adapter_replay_mutation_profiles_fail_closed(
    mutation_profile: AdapterReplayMutationProfile,
) -> None:
    request = adapter_replay_request(
        request_id=f"adapter-replay-{mutation_profile.value.lower().replace('_', '-')}"
    )
    mutate_adapter_replay_request_in_place(request, mutation_profile)

    proof = prove_adapter_replay(request)

    assert proof.status in {"FAILED", "BLOCKED"}
    assert proof.reason != "ADAPTER_REPLAY_PASSED"
    assert proof.failure_stage is not None
    assert proof.proof_checksum == recompute_adapter_replay_proof_checksum(proof)


def test_adapter_replay_qos_mutation_fails_with_qos_or_replay_reason() -> None:
    request = adapter_replay_request(request_id="adapter-replay-qos-specific")
    mutate_adapter_replay_request_in_place(request, AdapterReplayMutationProfile.QOS_MUTATION)

    proof = prove_adapter_replay(request)
    assert proof.status == "FAILED"
    assert proof.reason in {
        "ADAPTER_REPLAY_QOS_CHECKSUM_MISMATCH",
        "ADAPTER_REPLAY_REPLAYED_ENVELOPE_NOT_READY",
    }


def test_adapter_replay_receipt_checksum_mutation_fails_receipt_chain() -> None:
    request = adapter_replay_request(request_id="adapter-replay-receipt-specific")
    mutate_adapter_replay_request_in_place(
        request,
        AdapterReplayMutationProfile.ADAPTER_RECEIPT_CHECKSUM_MUTATION,
    )

    proof = prove_adapter_replay(request)
    assert proof.status == "FAILED"
    assert proof.receipt_chain_match is False
