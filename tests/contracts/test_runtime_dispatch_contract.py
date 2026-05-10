"""Contract tests for ADR-0017 runtime dispatch dry-run plans."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.aegis_constants import MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES
from aegis.contracts.aegis_runtime_dispatch import (
    RUNTIME_DISPATCH_RESOURCE_BOUNDS,
    DispatchFirewallReason,
    RuntimeDispatchItem,
    RuntimeDispatchKind,
    RuntimeDispatchMode,
    RuntimeDispatchPlan,
    make_runtime_dispatch_item,
    make_runtime_dispatch_plan_authorization,
    recompute_runtime_dispatch_plan_checksum,
)
from aegis.execution import build_runtime_dispatch_plan, prove_adapter_replay


def test_runtime_dispatch_plan_binds_replay_verified_envelope() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-contract")
    proof = prove_adapter_replay(request)

    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)

    assert proof.status == "PASSED"
    assert plan.dispatch_mode is RuntimeDispatchMode.DRY_RUN_ONLY
    assert plan.source_envelope_checksum == request.expected_envelope.envelope_checksum
    assert plan.source_replay_proof_checksum == proof.proof_checksum
    assert plan.runtime_target_checksum == request.expected_envelope.runtime_target_checksum
    assert plan.mapping_checksum == request.expected_envelope.adapter_mapping_checksum
    assert len(plan.dispatch_items) == 1
    assert plan.dispatch_items[0].runtime_kind is RuntimeDispatchKind.TOPIC
    assert plan.plan_checksum == recompute_runtime_dispatch_plan_checksum(plan)


def test_runtime_dispatch_plan_is_immutable() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-immutable")
    plan = build_runtime_dispatch_plan(request.expected_envelope, prove_adapter_replay(request))

    with pytest.raises(FrozenInstanceError):
        plan.dispatch_mode = RuntimeDispatchMode.DRY_RUN_ONLY


def test_runtime_dispatch_plan_requires_passed_replay_proof() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-proof-required")
    object.__setattr__(request.expected_envelope, "envelope_checksum", "0" * 64)
    proof = prove_adapter_replay(request)

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED.value,
    ):
        build_runtime_dispatch_plan(request.expected_envelope, proof)


def test_runtime_dispatch_plan_rejects_cross_envelope_replay_proof() -> None:
    first = adapter_replay_request(request_id="runtime-dispatch-cross-a")
    second = adapter_replay_request(request_id="runtime-dispatch-cross-b")
    second_proof = prove_adapter_replay(second)

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP.value,
    ):
        build_runtime_dispatch_plan(first.expected_envelope, second_proof)


def test_direct_runtime_dispatch_plan_construction_is_rejected() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-direct")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)

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


def test_runtime_dispatch_item_rejects_unknown_kind_and_runtime_objects() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-item-boundary")
    item = build_runtime_dispatch_plan(
        request.expected_envelope,
        prove_adapter_replay(request),
    ).dispatch_items[0]

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND.value,
    ):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind="publisher",
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )
    with pytest.raises(ValueError, match="runtime_name"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind=item.runtime_kind,
            runtime_name=object(),
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )


def test_runtime_dispatch_item_rejects_malformed_fields() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-item-malformed")
    item = build_runtime_dispatch_plan(
        request.expected_envelope,
        prove_adapter_replay(request),
    ).dispatch_items[0]

    with pytest.raises(ValueError, match="sequence"):
        RuntimeDispatchItem(
            sequence=True,
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
    with pytest.raises(ValueError, match="capability"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability="Locomotion.Translation",
            runtime_kind=item.runtime_kind,
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )
    with pytest.raises(ValueError, match="runtime_kind"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind="topic ",
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )
    with pytest.raises(ValueError, match="message_type"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind=item.runtime_kind,
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type="std_msgs/String",
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )
    with pytest.raises(ValueError, match="payload_size_bytes"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind=item.runtime_kind,
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=MAX_RUNTIME_DISPATCH_PAYLOAD_BYTES + 1,
            field_map_checksum=item.field_map_checksum,
        )


def test_runtime_dispatch_plan_rejects_malformed_dispatch_items_and_bounds() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-plan-malformed")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    item = plan.dispatch_items[0]
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

    with pytest.raises(ValueError, match="non-empty"):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=(),
            resource_bounds=plan.resource_bounds,
        )
    with pytest.raises(ValueError, match="RuntimeDispatchItem"):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=(object(),),
            resource_bounds=plan.resource_bounds,
        )
    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.RUNTIME_DISPATCH_SEQUENCE_GAP.value,
    ):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=(gap_item,),
            resource_bounds=plan.resource_bounds,
        )
    with pytest.raises(ValueError, match="resource_bounds"):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=plan.dispatch_items,
            resource_bounds=object(),
        )
    assert RUNTIME_DISPATCH_RESOURCE_BOUNDS.max_sequence_length >= 1


def test_runtime_dispatch_plan_authorization_rejects_mismatched_plan_fields() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-auth-mismatch")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    authorization = make_runtime_dispatch_plan_authorization(
        envelope=request.expected_envelope,
        replay_proof=proof,
    )
    changed_item = RuntimeDispatchItem(
        sequence=0,
        capability=plan.dispatch_items[0].capability,
        runtime_kind=plan.dispatch_items[0].runtime_kind,
        runtime_name=plan.dispatch_items[0].runtime_name,
        namespace=plan.dispatch_items[0].namespace,
        message_type=plan.dispatch_items[0].message_type,
        qos_profile_checksum=plan.dispatch_items[0].qos_profile_checksum,
        payload_checksum="1" * 64,
        payload_size_bytes=plan.dispatch_items[0].payload_size_bytes,
        field_map_checksum=plan.dispatch_items[0].field_map_checksum,
    )

    with pytest.raises(ValueError, match="dispatch items"):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum=plan.mapping_checksum,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=(changed_item,),
            resource_bounds=plan.resource_bounds,
            authorization=authorization,
        )
    with pytest.raises(ValueError, match="evidence"):
        RuntimeDispatchPlan(
            plan_id=plan.plan_id,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=plan.source_replay_proof_checksum,
            runtime_target_checksum=plan.runtime_target_checksum,
            mapping_checksum="1" * 64,
            dispatch_mode=plan.dispatch_mode,
            dispatch_items=plan.dispatch_items,
            resource_bounds=plan.resource_bounds,
            authorization=authorization,
        )


def test_runtime_dispatch_item_requires_adapter_mapping_evidence() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-missing-mapping")
    object.__setattr__(request.expected_envelope, "adapter_mapping", None)

    with pytest.raises(ValueError, match="mapping evidence"):
        make_runtime_dispatch_item(request.expected_envelope)
