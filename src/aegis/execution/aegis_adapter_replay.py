"""Deterministically replay ADR-0015 adapter envelopes without runtime I/O."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.aegis_adapter_receipt import AdapterReceipt, build_adapter_receipt
from aegis.contracts.aegis_adapter_replay import AdapterReplayRequest
from aegis.contracts.aegis_execution_adapter import ExecutionAdapterEnvelope
from aegis.execution.aegis_adapter_envelope import build_execution_adapter_envelope


@dataclass(frozen=True, slots=True)
class AdapterReplayOutput:
    """Reconstructed adapter envelope and receipt for one replay request."""

    envelope: ExecutionAdapterEnvelope
    adapter_receipt: AdapterReceipt


def replay_execution_adapter(request: AdapterReplayRequest) -> AdapterReplayOutput:
    """Rebuild adapter output from a replay request's source pipeline evidence."""
    mapping = request.expected_envelope.adapter_mapping
    target_runtime = request.expected_envelope.target_runtime
    if mapping is None or target_runtime is None:
        raise ValueError("ADAPTER_REPLAY_MAPPING_EVIDENCE_MISSING")
    envelope = build_execution_adapter_envelope(
        request.pipeline_result,
        mapping,
        target_runtime,
    )
    return AdapterReplayOutput(envelope=envelope, adapter_receipt=build_adapter_receipt(envelope))


__all__ = ["AdapterReplayOutput", "replay_execution_adapter"]
