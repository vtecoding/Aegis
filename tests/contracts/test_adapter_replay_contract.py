"""Contract tests for ADR-0016 adapter replay requests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.aegis_adapter_replay import (
    AdapterReplayMutationProfile,
    AdapterReplayProfile,
    AdapterReplayRequest,
    adapter_replay_source_pipeline_checksum,
)
from aegis.contracts.aegis_execution_adapter import ExecutionAdapterEnvelopeStatus


def test_adapter_replay_request_binds_pipeline_envelope_receipt_and_profiles() -> None:
    request = adapter_replay_request()

    assert request.replay_profile is AdapterReplayProfile.STRICT_ADAPTER_REPLAY_V1
    assert request.mutation_profile is AdapterReplayMutationProfile.NONE
    assert request.expected_envelope.status is ExecutionAdapterEnvelopeStatus.READY
    assert (
        request.expected_adapter_receipt.envelope_checksum
        == request.expected_envelope.envelope_checksum
    )
    assert len(adapter_replay_source_pipeline_checksum(request.pipeline_result)) == 64


def test_adapter_replay_request_is_immutable() -> None:
    request = adapter_replay_request(request_id="adapter-replay-immutable")

    with pytest.raises(FrozenInstanceError):
        request.replay_profile = AdapterReplayProfile.STRICT_ADAPTER_REPLAY_V1


def test_adapter_replay_request_rejects_raw_dict_escape_hatches() -> None:
    request = adapter_replay_request(request_id="adapter-replay-raw-dict")

    with pytest.raises(ValueError, match="pipeline_result"):
        AdapterReplayRequest(
            pipeline_result={},
            expected_envelope=request.expected_envelope,
            expected_adapter_receipt=request.expected_adapter_receipt,
        )
    with pytest.raises(ValueError, match="expected_envelope"):
        AdapterReplayRequest(
            pipeline_result=request.pipeline_result,
            expected_envelope={},
            expected_adapter_receipt=request.expected_adapter_receipt,
        )
    with pytest.raises(ValueError, match="expected_adapter_receipt"):
        AdapterReplayRequest(
            pipeline_result=request.pipeline_result,
            expected_envelope=request.expected_envelope,
            expected_adapter_receipt={},
        )


def test_adapter_replay_request_rejects_unknown_profiles() -> None:
    request = adapter_replay_request(request_id="adapter-replay-profile")

    with pytest.raises(ValueError, match="replay_profile"):
        AdapterReplayRequest(
            pipeline_result=request.pipeline_result,
            expected_envelope=request.expected_envelope,
            expected_adapter_receipt=request.expected_adapter_receipt,
            replay_profile="RELAXED_REPLAY",
        )
    with pytest.raises(ValueError, match="mutation_profile"):
        AdapterReplayRequest(
            pipeline_result=request.pipeline_result,
            expected_envelope=request.expected_envelope,
            expected_adapter_receipt=request.expected_adapter_receipt,
            mutation_profile="UNKNOWN_MUTATION",
        )
