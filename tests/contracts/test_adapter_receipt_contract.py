"""Contract tests for ADR-0015 adapter receipts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_mapping, allowed_pipeline_result

from aegis.contracts.adapter_receipt import (
    AdapterReceipt,
    adapter_receipt_checksum_value,
    build_adapter_receipt,
    recompute_adapter_receipt_checksum,
)
from aegis.contracts.execution_adapter import ExecutionAdapterEnvelopeStatus
from aegis.execution import build_execution_adapter_envelope


def test_adapter_receipt_binds_ready_envelope() -> None:
    mapping = adapter_mapping()
    envelope = build_execution_adapter_envelope(
        allowed_pipeline_result(),
        mapping,
        mapping.runtime_target,
    )
    receipt = build_adapter_receipt(envelope)

    assert receipt.status is ExecutionAdapterEnvelopeStatus.READY
    assert receipt.reason == "EXECUTION_ADAPTER_READY"
    assert receipt.envelope_checksum == envelope.envelope_checksum
    assert receipt.adapter_receipt_checksum == recompute_adapter_receipt_checksum(receipt)


def test_adapter_receipt_rejects_forged_checksum() -> None:
    mapping = adapter_mapping()
    envelope = build_execution_adapter_envelope(
        allowed_pipeline_result(),
        mapping,
        mapping.runtime_target,
    )

    with pytest.raises(ValueError, match="checksum"):
        AdapterReceipt(
            status=envelope.status,
            reason="EXECUTION_ADAPTER_READY",
            pipeline_receipt_checksum=envelope.pipeline_receipt_checksum,
            decision_trace_checksum=envelope.decision_trace_checksum,
            adapter_mapping_checksum=envelope.adapter_mapping_checksum,
            runtime_target_checksum=envelope.runtime_target_checksum,
            ros2_mapping_checksum=envelope.ros2_mapping_checksum,
            envelope_checksum=envelope.envelope_checksum,
            adapter_receipt_checksum="0" * 64,
        )


def test_adapter_receipt_rejects_invalid_status_and_reason() -> None:
    mapping = adapter_mapping()
    envelope = build_execution_adapter_envelope(
        allowed_pipeline_result(request_id="adapter-receipt-invalid"),
        mapping,
        mapping.runtime_target,
    )

    with pytest.raises(ValueError, match="status"):
        AdapterReceipt(
            status="ready ",
            reason="EXECUTION_ADAPTER_READY",
            pipeline_receipt_checksum=envelope.pipeline_receipt_checksum,
            decision_trace_checksum=envelope.decision_trace_checksum,
            adapter_mapping_checksum=envelope.adapter_mapping_checksum,
            runtime_target_checksum=envelope.runtime_target_checksum,
            ros2_mapping_checksum=envelope.ros2_mapping_checksum,
            envelope_checksum=envelope.envelope_checksum,
        )
    with pytest.raises(ValueError, match="reason"):
        AdapterReceipt(
            status=envelope.status,
            reason="ready",
            pipeline_receipt_checksum=envelope.pipeline_receipt_checksum,
            decision_trace_checksum=envelope.decision_trace_checksum,
            adapter_mapping_checksum=envelope.adapter_mapping_checksum,
            runtime_target_checksum=envelope.runtime_target_checksum,
            ros2_mapping_checksum=envelope.ros2_mapping_checksum,
            envelope_checksum=envelope.envelope_checksum,
        )


def test_adapter_receipt_checksum_helper_is_canonical() -> None:
    mapping = adapter_mapping()
    envelope = build_execution_adapter_envelope(
        allowed_pipeline_result(),
        mapping,
        mapping.runtime_target,
    )
    receipt = build_adapter_receipt(envelope)

    assert receipt.adapter_receipt_checksum == adapter_receipt_checksum_value(
        status=receipt.status,
        reason=receipt.reason,
        pipeline_receipt_checksum=receipt.pipeline_receipt_checksum,
        decision_trace_checksum=receipt.decision_trace_checksum,
        adapter_mapping_checksum=receipt.adapter_mapping_checksum,
        runtime_target_checksum=receipt.runtime_target_checksum,
        ros2_mapping_checksum=receipt.ros2_mapping_checksum,
        envelope_checksum=receipt.envelope_checksum,
    )
