"""Checksum proof harness for deterministic adapter replay."""

from __future__ import annotations

from aegis.contracts.adapter_receipt import (
    AdapterReceipt,
    recompute_adapter_receipt_checksum,
)
from aegis.contracts.adapter_replay import (
    AdapterReplayProofResult,
    AdapterReplayRequest,
    adapter_replay_source_pipeline_checksum,
)
from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterReason,
    recompute_execution_adapter_envelope_checksum,
    recompute_execution_adapter_mapping_checksum,
)
from aegis.contracts.ros2_mapping import (
    recompute_ros2_message_mapping_checksum,
    recompute_ros2_qos_profile_checksum,
    recompute_runtime_target_checksum,
)
from aegis.execution.adapter_replay import replay_execution_adapter


def prove_adapter_replay(request: AdapterReplayRequest) -> AdapterReplayProofResult:
    """Prove whether expected adapter evidence exactly replays from its PipelineResult."""
    source_checksum = adapter_replay_source_pipeline_checksum(request.pipeline_result)
    expected_envelope = request.expected_envelope
    expected_receipt = request.expected_adapter_receipt
    if expected_envelope.status is not ExecutionAdapterEnvelopeStatus.READY:
        return _blocked_result(
            source_pipeline_checksum=source_checksum,
            expected_envelope_checksum=expected_envelope.envelope_checksum,
            expected_receipt_checksum=expected_receipt.adapter_receipt_checksum,
            reason="ADAPTER_REPLAY_EXPECTED_ENVELOPE_NOT_READY",
            failure_stage="expected_envelope",
        )
    if expected_envelope.adapter_mapping is None or expected_envelope.target_runtime is None:
        return _blocked_result(
            source_pipeline_checksum=source_checksum,
            expected_envelope_checksum=expected_envelope.envelope_checksum,
            expected_receipt_checksum=expected_receipt.adapter_receipt_checksum,
            reason="ADAPTER_REPLAY_MAPPING_EVIDENCE_MISSING",
            failure_stage="mapping_evidence",
        )

    replayed = replay_execution_adapter(request)
    replayed_envelope = replayed.envelope
    replayed_receipt = replayed.adapter_receipt
    if _source_pipeline_blocked_replay(replayed_envelope):
        return _blocked_result(
            source_pipeline_checksum=source_checksum,
            expected_envelope_checksum=expected_envelope.envelope_checksum,
            expected_receipt_checksum=expected_receipt.adapter_receipt_checksum,
            replayed_envelope_checksum=replayed_envelope.envelope_checksum,
            replayed_receipt_checksum=replayed_receipt.adapter_receipt_checksum,
            reason="ADAPTER_REPLAY_SOURCE_PIPELINE_BLOCKED",
            failure_stage="pipeline_receipt",
        )

    mapping_match = _mapping_checksum_match(expected_envelope, replayed_envelope)
    runtime_match = _runtime_target_checksum_match(expected_envelope, replayed_envelope)
    qos_match = _qos_checksum_match(expected_envelope, replayed_envelope)
    namespace_match = _namespace_match(expected_envelope, replayed_envelope)
    receipt_chain_match = _receipt_chain_match(
        expected_envelope,
        expected_receipt,
        replayed_envelope,
        replayed_receipt,
    )
    envelope_checksum_match = (
        expected_envelope.envelope_checksum == replayed_envelope.envelope_checksum
        and expected_envelope.envelope_checksum
        == recompute_execution_adapter_envelope_checksum(expected_envelope)
        and replayed_envelope.envelope_checksum
        == recompute_execution_adapter_envelope_checksum(replayed_envelope)
    )
    receipt_checksum_match = (
        expected_receipt.adapter_receipt_checksum == replayed_receipt.adapter_receipt_checksum
        and expected_receipt.adapter_receipt_checksum
        == recompute_adapter_receipt_checksum(expected_receipt)
        and replayed_receipt.adapter_receipt_checksum
        == recompute_adapter_receipt_checksum(replayed_receipt)
    )
    replay_ready = replayed_envelope.status is ExecutionAdapterEnvelopeStatus.READY
    passed = all(
        (
            replay_ready,
            envelope_checksum_match,
            receipt_checksum_match,
            mapping_match,
            runtime_match,
            qos_match,
            namespace_match,
            receipt_chain_match,
        )
    )
    if passed:
        return AdapterReplayProofResult(
            status="PASSED",
            reason="ADAPTER_REPLAY_PASSED",
            source_pipeline_checksum=source_checksum,
            expected_envelope_checksum=expected_envelope.envelope_checksum,
            replayed_envelope_checksum=replayed_envelope.envelope_checksum,
            expected_receipt_checksum=expected_receipt.adapter_receipt_checksum,
            replayed_receipt_checksum=replayed_receipt.adapter_receipt_checksum,
            mapping_checksum_match=True,
            runtime_target_checksum_match=True,
            qos_checksum_match=True,
            namespace_match=True,
            receipt_chain_match=True,
            mutation_detected=False,
            failure_stage=None,
        )
    return AdapterReplayProofResult(
        status="FAILED",
        reason=_failure_reason(
            replay_ready=replay_ready,
            envelope_checksum_match=envelope_checksum_match,
            receipt_checksum_match=receipt_checksum_match,
            mapping_checksum_match=mapping_match,
            runtime_target_checksum_match=runtime_match,
            qos_checksum_match=qos_match,
            namespace_match=namespace_match,
            receipt_chain_match=receipt_chain_match,
        ),
        source_pipeline_checksum=source_checksum,
        expected_envelope_checksum=expected_envelope.envelope_checksum,
        replayed_envelope_checksum=replayed_envelope.envelope_checksum,
        expected_receipt_checksum=expected_receipt.adapter_receipt_checksum,
        replayed_receipt_checksum=replayed_receipt.adapter_receipt_checksum,
        mapping_checksum_match=mapping_match,
        runtime_target_checksum_match=runtime_match,
        qos_checksum_match=qos_match,
        namespace_match=namespace_match,
        receipt_chain_match=receipt_chain_match,
        mutation_detected=True,
        failure_stage=_failure_stage(replayed_envelope),
    )


def _blocked_result(
    *,
    source_pipeline_checksum: str,
    expected_envelope_checksum: str | None,
    expected_receipt_checksum: str | None,
    reason: str,
    failure_stage: str,
    replayed_envelope_checksum: str | None = None,
    replayed_receipt_checksum: str | None = None,
) -> AdapterReplayProofResult:
    return AdapterReplayProofResult(
        status="BLOCKED",
        reason=reason,
        source_pipeline_checksum=source_pipeline_checksum,
        expected_envelope_checksum=expected_envelope_checksum,
        replayed_envelope_checksum=replayed_envelope_checksum,
        expected_receipt_checksum=expected_receipt_checksum,
        replayed_receipt_checksum=replayed_receipt_checksum,
        mapping_checksum_match=False,
        runtime_target_checksum_match=False,
        qos_checksum_match=False,
        namespace_match=False,
        receipt_chain_match=False,
        mutation_detected=False,
        failure_stage=failure_stage,
    )


def _source_pipeline_blocked_replay(envelope: ExecutionAdapterEnvelope) -> bool:
    return any(
        reason in envelope.blocked_reasons
        for reason in (
            ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED.value,
            ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID.value,
        )
    )


def _mapping_checksum_match(
    expected_envelope: ExecutionAdapterEnvelope,
    replayed_envelope: ExecutionAdapterEnvelope,
) -> bool:
    mapping = expected_envelope.adapter_mapping
    if mapping is None:
        return False
    return (
        expected_envelope.adapter_mapping_checksum == replayed_envelope.adapter_mapping_checksum
        and mapping.adapter_mapping_checksum == expected_envelope.adapter_mapping_checksum
        and mapping.adapter_mapping_checksum
        == recompute_execution_adapter_mapping_checksum(mapping)
        and mapping.ros2_mapping.mapping_checksum
        == recompute_ros2_message_mapping_checksum(mapping.ros2_mapping)
    )


def _runtime_target_checksum_match(
    expected_envelope: ExecutionAdapterEnvelope,
    replayed_envelope: ExecutionAdapterEnvelope,
) -> bool:
    target_runtime = expected_envelope.target_runtime
    if target_runtime is None:
        return False
    return (
        expected_envelope.runtime_target_checksum == replayed_envelope.runtime_target_checksum
        and target_runtime.runtime_target_checksum == expected_envelope.runtime_target_checksum
        and target_runtime.runtime_target_checksum
        == recompute_runtime_target_checksum(target_runtime)
    )


def _qos_checksum_match(
    expected_envelope: ExecutionAdapterEnvelope,
    replayed_envelope: ExecutionAdapterEnvelope,
) -> bool:
    mapping = expected_envelope.adapter_mapping
    if mapping is None:
        return False
    return (
        expected_envelope.qos_profile_checksum == replayed_envelope.qos_profile_checksum
        and mapping.ros2_mapping.qos.qos_checksum == expected_envelope.qos_profile_checksum
        and mapping.ros2_mapping.qos.qos_checksum
        == recompute_ros2_qos_profile_checksum(mapping.ros2_mapping.qos)
    )


def _namespace_match(
    expected_envelope: ExecutionAdapterEnvelope,
    replayed_envelope: ExecutionAdapterEnvelope,
) -> bool:
    mapping = expected_envelope.adapter_mapping
    target_runtime = expected_envelope.target_runtime
    replayed_mapping = replayed_envelope.adapter_mapping
    replayed_target = replayed_envelope.target_runtime
    if (
        mapping is None
        or target_runtime is None
        or replayed_mapping is None
        or replayed_target is None
    ):
        return False
    return (
        mapping.ros2_mapping.namespace == target_runtime.target_namespace
        and replayed_mapping.ros2_mapping.namespace == replayed_target.target_namespace
        and mapping.ros2_mapping.namespace == replayed_mapping.ros2_mapping.namespace
    )


def _receipt_chain_match(
    expected_envelope: ExecutionAdapterEnvelope,
    expected_receipt: AdapterReceipt,
    replayed_envelope: ExecutionAdapterEnvelope,
    replayed_receipt: AdapterReceipt,
) -> bool:
    return (
        _receipt_binds_envelope(expected_receipt, expected_envelope)
        and _receipt_binds_envelope(replayed_receipt, replayed_envelope)
        and expected_receipt.adapter_receipt_checksum == replayed_receipt.adapter_receipt_checksum
        and expected_receipt.adapter_receipt_checksum
        == recompute_adapter_receipt_checksum(expected_receipt)
        and replayed_receipt.adapter_receipt_checksum
        == recompute_adapter_receipt_checksum(replayed_receipt)
    )


def _receipt_binds_envelope(
    receipt: AdapterReceipt,
    envelope: ExecutionAdapterEnvelope,
) -> bool:
    return (
        receipt.status is envelope.status
        and receipt.pipeline_receipt_checksum == envelope.pipeline_receipt_checksum
        and receipt.decision_trace_checksum == envelope.decision_trace_checksum
        and receipt.adapter_mapping_checksum == envelope.adapter_mapping_checksum
        and receipt.runtime_target_checksum == envelope.runtime_target_checksum
        and receipt.ros2_mapping_checksum == envelope.ros2_mapping_checksum
        and receipt.envelope_checksum == envelope.envelope_checksum
    )


def _failure_reason(
    *,
    replay_ready: bool,
    envelope_checksum_match: bool,
    receipt_checksum_match: bool,
    mapping_checksum_match: bool,
    runtime_target_checksum_match: bool,
    qos_checksum_match: bool,
    namespace_match: bool,
    receipt_chain_match: bool,
) -> str:
    if not replay_ready:
        return "ADAPTER_REPLAY_REPLAYED_ENVELOPE_NOT_READY"
    if not mapping_checksum_match:
        return "ADAPTER_REPLAY_MAPPING_CHECKSUM_MISMATCH"
    if not runtime_target_checksum_match:
        return "ADAPTER_REPLAY_RUNTIME_TARGET_CHECKSUM_MISMATCH"
    if not qos_checksum_match:
        return "ADAPTER_REPLAY_QOS_CHECKSUM_MISMATCH"
    if not namespace_match:
        return "ADAPTER_REPLAY_NAMESPACE_MISMATCH"
    if not receipt_chain_match:
        return "ADAPTER_REPLAY_RECEIPT_CHAIN_MISMATCH"
    if not receipt_checksum_match:
        return "ADAPTER_REPLAY_RECEIPT_CHECKSUM_MISMATCH"
    if not envelope_checksum_match:
        return "ADAPTER_REPLAY_ENVELOPE_CHECKSUM_MISMATCH"
    return "ADAPTER_REPLAY_CHECKSUM_MISMATCH"


def _failure_stage(envelope: ExecutionAdapterEnvelope) -> str:
    if envelope.status is not ExecutionAdapterEnvelopeStatus.READY:
        return envelope.terminal_adapter_stage
    return "adapter_replay_proof"


__all__ = ["prove_adapter_replay"]
