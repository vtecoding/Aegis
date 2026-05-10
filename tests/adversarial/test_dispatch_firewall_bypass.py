"""Adversarial tests for ADR-0017 dispatch firewall bypass attempts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.constants import MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES
from aegis.contracts.adapter_replay import AdapterReplayProofResult
from aegis.contracts.execution_adapter import ExecutionAdapterEnvelope
from aegis.contracts.runtime_dispatch import (
    DispatchFirewallReason,
    RuntimeDispatchItem,
    RuntimeDispatchPlan,
    recompute_runtime_dispatch_plan_checksum,
)
from aegis.execution import (
    build_runtime_dispatch_plan,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def _plan_tuple() -> tuple[RuntimeDispatchPlan, ExecutionAdapterEnvelope, AdapterReplayProofResult]:
    request = adapter_replay_request(request_id="runtime-dispatch-bypass")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    return plan, request.expected_envelope, proof


def test_direct_public_dispatch_plan_construction_cannot_bypass_replay_proof() -> None:
    plan, _, _ = _plan_tuple()

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.DIRECT_RUNTIME_DISPATCH_BYPASS.value,
    ):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=plan.dispatch_items,
            resource_bounds=plan.resource_bounds,
        )


def test_dispatch_firewall_blocks_forged_plan_checksum() -> None:
    plan, envelope, proof = _plan_tuple()
    object.__setattr__(plan, "plan_checksum", "0" * 64)

    decision = evaluate_dispatch_firewall(plan, envelope, proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH


def test_dispatch_firewall_blocks_source_binding_mutations() -> None:
    source_plan, source_envelope, source_proof = _plan_tuple()
    object.__setattr__(source_plan, "source_envelope_checksum", "1" * 64)
    object.__setattr__(
        source_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(source_plan),
    )

    proof_plan, proof_envelope, proof_proof = _plan_tuple()
    object.__setattr__(proof_plan, "source_replay_proof_checksum", "1" * 64)
    object.__setattr__(
        proof_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(proof_plan),
    )

    target_plan, target_envelope, target_proof = _plan_tuple()
    object.__setattr__(target_plan, "runtime_target_checksum", "1" * 64)
    object.__setattr__(
        target_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(target_plan),
    )

    mapping_plan, mapping_envelope, mapping_proof = _plan_tuple()
    object.__setattr__(mapping_plan, "mapping_checksum", "1" * 64)
    object.__setattr__(
        mapping_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(mapping_plan),
    )

    assert evaluate_dispatch_firewall(source_plan, source_envelope, source_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP
    )
    assert evaluate_dispatch_firewall(proof_plan, proof_envelope, proof_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH
    )
    assert evaluate_dispatch_firewall(target_plan, target_envelope, target_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_RUNTIME_TARGET_MISMATCH
    )
    assert evaluate_dispatch_firewall(
        mapping_plan, mapping_envelope, mapping_proof
    ).reason_code == (DispatchFirewallReason.RUNTIME_DISPATCH_MAPPING_MISMATCH)


def test_dispatch_firewall_blocks_payload_size_abuse() -> None:
    plan, envelope, proof = _plan_tuple()
    item = plan.dispatch_items[0]
    object.__setattr__(item, "payload_size_bytes", MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES + 1)
    object.__setattr__(plan, "plan_checksum", recompute_runtime_dispatch_plan_checksum(plan))

    decision = evaluate_dispatch_firewall(plan, envelope, proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED


def test_dispatch_firewall_blocks_payload_checksum_and_empty_items() -> None:
    payload_plan, payload_envelope, payload_proof = _plan_tuple()
    object.__setattr__(payload_plan.dispatch_items[0], "payload_checksum", "1" * 64)
    object.__setattr__(
        payload_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(payload_plan),
    )

    empty_plan, empty_envelope, empty_proof = _plan_tuple()
    object.__setattr__(empty_plan, "dispatch_items", ())
    object.__setattr__(
        empty_plan, "plan_checksum", recompute_runtime_dispatch_plan_checksum(empty_plan)
    )

    assert evaluate_dispatch_firewall(
        payload_plan, payload_envelope, payload_proof
    ).reason_code == (DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_MISMATCH)
    assert evaluate_dispatch_firewall(empty_plan, empty_envelope, empty_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP
    )


def test_dispatch_firewall_blocks_sequence_gaps_and_duplicates() -> None:
    gap_plan, gap_envelope, gap_proof = _plan_tuple()
    item = gap_plan.dispatch_items[0]
    gap_item = RuntimeDispatchItem(
        sequence=1,
        capability=item.capability,
        runtime_kind=item.runtime_kind,
        runtime_name=item.runtime_name,
        namespace=item.namespace,
        message_type=item.message_type,
        qos_profile_checksum=item.qos_profile_checksum,
        payload_checksum=item.payload_checksum,
        payload_size_bytes=item.payload_size_bytes,
        field_map_checksum=item.field_map_checksum,
    )
    object.__setattr__(gap_plan, "dispatch_items", (gap_item,))
    object.__setattr__(
        gap_plan, "plan_checksum", recompute_runtime_dispatch_plan_checksum(gap_plan)
    )

    duplicate_plan, duplicate_envelope, duplicate_proof = _plan_tuple()
    duplicate_item = duplicate_plan.dispatch_items[0]
    object.__setattr__(duplicate_plan, "dispatch_items", (duplicate_item, duplicate_item))
    object.__setattr__(
        duplicate_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(duplicate_plan),
    )

    gap_decision = evaluate_dispatch_firewall(gap_plan, gap_envelope, gap_proof)
    duplicate_decision = evaluate_dispatch_firewall(
        duplicate_plan,
        duplicate_envelope,
        duplicate_proof,
    )

    assert gap_decision.status == "BLOCKED"
    assert gap_decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP
    assert duplicate_decision.status == "BLOCKED"
    assert (
        duplicate_decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_DUPLICATE_SEQUENCE
    )


def test_dispatch_firewall_blocks_dispatch_mode_mutation() -> None:
    plan, envelope, proof = _plan_tuple()
    object.__setattr__(plan, "dispatch_mode", "EXECUTE")

    decision = evaluate_dispatch_firewall(plan, envelope, proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY


def test_dispatch_firewall_blocks_qos_namespace_and_field_map_drift() -> None:
    qos_plan, qos_envelope, qos_proof = _plan_tuple()
    object.__setattr__(qos_plan.dispatch_items[0], "qos_profile_checksum", "1" * 64)
    object.__setattr__(
        qos_plan, "plan_checksum", recompute_runtime_dispatch_plan_checksum(qos_plan)
    )

    namespace_plan, namespace_envelope, namespace_proof = _plan_tuple()
    object.__setattr__(namespace_plan.dispatch_items[0], "namespace", "other_arm")
    object.__setattr__(
        namespace_plan,
        "plan_checksum",
        recompute_runtime_dispatch_plan_checksum(namespace_plan),
    )

    field_plan, field_envelope, field_proof = _plan_tuple()
    object.__setattr__(field_plan.dispatch_items[0], "field_map_checksum", "2" * 64)
    object.__setattr__(
        field_plan, "plan_checksum", recompute_runtime_dispatch_plan_checksum(field_plan)
    )

    assert evaluate_dispatch_firewall(qos_plan, qos_envelope, qos_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_QOS_MISMATCH
    )
    assert evaluate_dispatch_firewall(
        namespace_plan, namespace_envelope, namespace_proof
    ).reason_code == (DispatchFirewallReason.RUNTIME_DISPATCH_NAMESPACE_MISMATCH)
    assert evaluate_dispatch_firewall(field_plan, field_envelope, field_proof).reason_code == (
        DispatchFirewallReason.RUNTIME_DISPATCH_FIELD_MAP_DRIFT
    )
