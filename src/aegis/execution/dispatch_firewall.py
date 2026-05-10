"""Fail-closed runtime dispatch firewall for ADR-0017 dry-run plans."""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from aegis.constants import MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES
from aegis.contracts.adapter_replay import (
    AdapterReplayProofResult,
    recompute_adapter_replay_proof_checksum,
)
from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterEnvelopeStatus,
    recompute_execution_adapter_envelope_checksum,
)
from aegis.contracts.runtime_dispatch import (
    DispatchFirewallDecision,
    DispatchFirewallReason,
    RuntimeDispatchItem,
    RuntimeDispatchKind,
    RuntimeDispatchMode,
    RuntimeDispatchPlan,
    make_dispatch_firewall_allow_authorization,
    make_runtime_dispatch_item,
    recompute_runtime_dispatch_plan_checksum,
)

_FALLBACK_CHECKSUM = "0" * 64


def evaluate_dispatch_firewall(
    plan: RuntimeDispatchPlan,
    envelope: ExecutionAdapterEnvelope,
    replay_proof: AdapterReplayProofResult,
) -> DispatchFirewallDecision:
    """Evaluate whether a dry-run dispatch plan is admissible as inert data.

    Args:
        plan: Runtime dispatch plan produced after replay proof.
        envelope: Source adapter envelope the plan claims to bind.
        replay_proof: Current replay proof the plan claims to bind.

    Returns:
        ALLOWED_DRY_RUN only when every proof, checksum, mapping, sequence, and
        dry-run-mode check matches; otherwise BLOCKED.
    """
    reason = _first_block_reason(plan, envelope, replay_proof)
    if reason is not None:
        return _blocked_decision(plan, replay_proof, reason)
    return DispatchFirewallDecision(
        status="ALLOWED_DRY_RUN",
        reason_code=DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value,
        plan_checksum=plan.plan_checksum,
        source_replay_proof_checksum=replay_proof.proof_checksum,
        blocked_stage=None,
        authorization=make_dispatch_firewall_allow_authorization(
            plan=plan,
            replay_proof=replay_proof,
        ),
    )


def _first_block_reason(
    plan: RuntimeDispatchPlan,
    envelope: ExecutionAdapterEnvelope,
    replay_proof: AdapterReplayProofResult,
) -> DispatchFirewallReason | None:
    if plan.dispatch_mode is not RuntimeDispatchMode.DRY_RUN_ONLY:
        return DispatchFirewallReason.RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY
    if replay_proof.status != "PASSED":
        return DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED
    if not _proof_checksum_matches(replay_proof):
        return DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH
    if envelope.status is not ExecutionAdapterEnvelopeStatus.READY:
        return DispatchFirewallReason.RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH
    if not _envelope_checksum_matches(envelope):
        return DispatchFirewallReason.RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH
    if (
        replay_proof.expected_envelope_checksum != envelope.envelope_checksum
        or replay_proof.replayed_envelope_checksum != envelope.envelope_checksum
        or plan.source_envelope_checksum != envelope.envelope_checksum
    ):
        return DispatchFirewallReason.RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP
    if plan.source_replay_proof_checksum != replay_proof.proof_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH
    if plan.runtime_target_checksum != envelope.runtime_target_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_RUNTIME_TARGET_MISMATCH
    if plan.mapping_checksum != envelope.adapter_mapping_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_MAPPING_MISMATCH
    sequence_reason = _sequence_reason(plan.dispatch_items)
    if sequence_reason is not None:
        return sequence_reason
    expected_item = make_runtime_dispatch_item(envelope)
    item_reason = _dispatch_item_reason(plan.dispatch_items, expected_item)
    if item_reason is not None:
        return item_reason
    if not _plan_checksum_matches(plan):
        return DispatchFirewallReason.RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH
    return None


def _proof_checksum_matches(replay_proof: AdapterReplayProofResult) -> bool:
    try:
        return replay_proof.proof_checksum == recompute_adapter_replay_proof_checksum(replay_proof)
    except ValueError:
        return False


def _envelope_checksum_matches(envelope: ExecutionAdapterEnvelope) -> bool:
    try:
        return envelope.envelope_checksum == recompute_execution_adapter_envelope_checksum(envelope)
    except ValueError:
        return False


def _plan_checksum_matches(plan: RuntimeDispatchPlan) -> bool:
    try:
        return plan.plan_checksum == recompute_runtime_dispatch_plan_checksum(plan)
    except ValueError:
        return False


def _sequence_reason(
    dispatch_items: Iterable[object],
) -> DispatchFirewallReason | None:
    items = tuple(dispatch_items)
    if not items:
        return DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP
    runtime_items: list[RuntimeDispatchItem] = []
    for item in items:
        if not isinstance(item, RuntimeDispatchItem):
            return DispatchFirewallReason.RUNTIME_DISPATCH_OBJECT_INJECTION
        runtime_items.append(item)
    sequences = [item.sequence for item in runtime_items]
    if len(set(sequences)) != len(sequences):
        return DispatchFirewallReason.RUNTIME_DISPATCH_DUPLICATE_SEQUENCE
    if sequences != list(range(len(runtime_items))):
        return DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP
    return None


def _dispatch_item_reason(
    dispatch_items: Iterable[object],
    expected_item: RuntimeDispatchItem,
) -> DispatchFirewallReason | None:
    items = tuple(dispatch_items)
    if len(items) != 1:
        return DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP
    item = items[0]
    if _has_runtime_object_injection(item):
        return DispatchFirewallReason.RUNTIME_DISPATCH_OBJECT_INJECTION
    if not isinstance(item, RuntimeDispatchItem):
        return DispatchFirewallReason.RUNTIME_DISPATCH_OBJECT_INJECTION
    runtime_kind = cast(object, item.runtime_kind)
    runtime_name = cast(object, item.runtime_name)
    capability = cast(object, item.capability)
    namespace = cast(object, item.namespace)
    qos_profile_checksum = cast(object, item.qos_profile_checksum)
    message_type = cast(object, item.message_type)
    payload_size_bytes = cast(object, item.payload_size_bytes)
    payload_checksum = cast(object, item.payload_checksum)
    field_map_checksum = cast(object, item.field_map_checksum)
    if runtime_kind not in tuple(RuntimeDispatchKind):
        return DispatchFirewallReason.RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND
    if runtime_kind is not expected_item.runtime_kind or runtime_name != expected_item.runtime_name:
        return DispatchFirewallReason.RUNTIME_DISPATCH_MAPPING_MISMATCH
    if capability != expected_item.capability:
        return DispatchFirewallReason.RUNTIME_DISPATCH_MAPPING_MISMATCH
    if namespace != expected_item.namespace:
        return DispatchFirewallReason.RUNTIME_DISPATCH_NAMESPACE_MISMATCH
    if qos_profile_checksum != expected_item.qos_profile_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_QOS_MISMATCH
    if message_type != expected_item.message_type:
        return DispatchFirewallReason.RUNTIME_DISPATCH_MESSAGE_TYPE_MISMATCH
    if (
        not isinstance(payload_size_bytes, int)
        or payload_size_bytes > MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES
    ):
        return DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED
    if payload_checksum != expected_item.payload_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_MISMATCH
    if payload_size_bytes != expected_item.payload_size_bytes:
        return DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED
    if field_map_checksum != expected_item.field_map_checksum:
        return DispatchFirewallReason.RUNTIME_DISPATCH_FIELD_MAP_DRIFT
    return None


def _has_runtime_object_injection(item: object) -> bool:
    if not isinstance(item, RuntimeDispatchItem):
        return True
    sequence = cast(object, item.sequence)
    capability = cast(object, item.capability)
    runtime_kind = cast(object, item.runtime_kind)
    runtime_name = cast(object, item.runtime_name)
    namespace = cast(object, item.namespace)
    message_type = cast(object, item.message_type)
    qos_profile_checksum = cast(object, item.qos_profile_checksum)
    payload_checksum = cast(object, item.payload_checksum)
    payload_size_bytes = cast(object, item.payload_size_bytes)
    field_map_checksum = cast(object, item.field_map_checksum)
    runtime_kind_is_inert = isinstance(runtime_kind, (RuntimeDispatchKind, str))
    return not (
        isinstance(sequence, int)
        and not isinstance(sequence, bool)
        and isinstance(capability, str)
        and runtime_kind_is_inert
        and isinstance(runtime_name, str)
        and isinstance(namespace, str)
        and isinstance(message_type, str)
        and isinstance(qos_profile_checksum, str)
        and isinstance(payload_checksum, str)
        and isinstance(payload_size_bytes, int)
        and not isinstance(payload_size_bytes, bool)
        and isinstance(field_map_checksum, str)
    )


def _blocked_decision(
    plan: RuntimeDispatchPlan,
    replay_proof: AdapterReplayProofResult,
    reason: DispatchFirewallReason,
) -> DispatchFirewallDecision:
    plan_checksum = plan.plan_checksum if _is_checksum(plan.plan_checksum) else _FALLBACK_CHECKSUM
    proof_checksum = (
        replay_proof.proof_checksum
        if _is_checksum(replay_proof.proof_checksum)
        else _FALLBACK_CHECKSUM
    )
    return DispatchFirewallDecision(
        status="BLOCKED",
        reason_code=reason.value,
        plan_checksum=plan_checksum,
        source_replay_proof_checksum=proof_checksum,
        blocked_stage="dispatch_firewall",
    )


def _is_checksum(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = ["evaluate_dispatch_firewall"]
