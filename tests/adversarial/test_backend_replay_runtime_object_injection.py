"""Runtime object injection tests for ADR-0019 backend replay."""

from __future__ import annotations

import pytest
from tests.backend_replay_fixtures import backend_replay_parts, backend_replay_request

from aegis.contracts.aegis_backend_replay import BackendReplayMutationProfile, BackendReplayRequest
from aegis.execution import mutate_backend_replay_request_in_place, prove_backend_replay


@pytest.mark.parametrize(
    "mutation_profile",
    (
        BackendReplayMutationProfile.RUNTIME_OBJECT_INJECTION,
        BackendReplayMutationProfile.CALLABLE_CLIENT_INJECTION,
        BackendReplayMutationProfile.MUTABLE_BACKEND_DESCRIPTOR_INJECTION,
    ),
)
def test_backend_replay_runtime_object_injection_blocks(
    mutation_profile: BackendReplayMutationProfile,
) -> None:
    request = backend_replay_request(request_id=f"backend-replay-{mutation_profile.value.lower()}")
    mutate_backend_replay_request_in_place(request, mutation_profile)

    proof = prove_backend_replay(request)

    assert proof.status == "BLOCKED"
    assert proof.reason_code == "BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION"


def test_backend_replay_request_constructor_rejects_runtime_object_injection() -> None:
    plan, decision, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-constructor-injection"
    )

    with pytest.raises(ValueError, match="backend_descriptor"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision=decision,
            backend_descriptor=backend,
            expected_certification=certification,
            expected_receipt=receipt,
        )
    with pytest.raises(ValueError, match="backend_descriptor"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision=decision,
            backend_descriptor={"client": object()},
            expected_certification=certification,
            expected_receipt=receipt,
        )
