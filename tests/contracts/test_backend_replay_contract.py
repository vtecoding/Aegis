"""Contract tests for ADR-0019 backend replay requests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.backend_replay_fixtures import backend_replay_parts, backend_replay_request

from aegis.contracts.backend_replay import (
    BackendReplayMutationProfile,
    BackendReplayProfile,
    BackendReplayRequest,
    backend_replay_request_source_checksum,
)


def test_backend_replay_request_binds_source_evidence_and_profiles() -> None:
    request = backend_replay_request(request_id="backend-replay-contract")

    assert request.replay_profile is BackendReplayProfile.STRICT_BACKEND_REPLAY_V1
    assert request.mutation_profile is BackendReplayMutationProfile.NONE
    assert (
        request.backend_descriptor.descriptor_checksum
        == request.expected_certification.backend_descriptor_checksum
    )
    assert (
        request.expected_receipt.backend_certification_checksum
        == request.expected_certification.certification_checksum
    )
    assert len(backend_replay_request_source_checksum(request)) == 64


def test_backend_replay_request_is_immutable() -> None:
    request = backend_replay_request(request_id="backend-replay-immutable")

    with pytest.raises(FrozenInstanceError):
        request.replay_profile = BackendReplayProfile.STRICT_BACKEND_REPLAY_V1


def test_backend_replay_request_rejects_raw_dict_escape_hatches() -> None:
    plan, decision, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-raw-dict"
    )

    with pytest.raises(ValueError, match="dispatch_plan"):
        BackendReplayRequest(
            dispatch_plan={},
            firewall_decision=decision,
            backend_descriptor=backend.descriptor,
            expected_certification=certification,
            expected_receipt=receipt,
        )
    with pytest.raises(ValueError, match="firewall_decision"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision={},
            backend_descriptor=backend.descriptor,
            expected_certification=certification,
            expected_receipt=receipt,
        )
    with pytest.raises(ValueError, match="backend_descriptor"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision=decision,
            backend_descriptor={},
            expected_certification=certification,
            expected_receipt=receipt,
        )


def test_backend_replay_request_rejects_backend_objects_and_callables() -> None:
    plan, decision, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-backend-object"
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
            backend_descriptor=lambda: None,
            expected_certification=certification,
            expected_receipt=receipt,
        )


def test_backend_replay_request_rejects_unknown_profiles() -> None:
    plan, decision, backend, certification, receipt = backend_replay_parts(
        request_id="backend-replay-profile"
    )

    with pytest.raises(ValueError, match="replay_profile"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision=decision,
            backend_descriptor=backend.descriptor,
            expected_certification=certification,
            expected_receipt=receipt,
            replay_profile="RELAXED_BACKEND_REPLAY",
        )
    with pytest.raises(ValueError, match="mutation_profile"):
        BackendReplayRequest(
            dispatch_plan=plan,
            firewall_decision=decision,
            backend_descriptor=backend.descriptor,
            expected_certification=certification,
            expected_receipt=receipt,
            mutation_profile="UNKNOWN_MUTATION",
        )
