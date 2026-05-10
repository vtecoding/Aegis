"""Adversarial tests for runtime object injection into ADR-0017 dry-run data."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.aegis_runtime_dispatch import DispatchFirewallReason, RuntimeDispatchItem
from aegis.execution import (
    build_runtime_dispatch_plan,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


class RuntimeClientHandle:
    """Test-only stand-in for a runtime backend object."""


def test_runtime_dispatch_item_rejects_callable_or_object_fields() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-object-constructor")
    item = build_runtime_dispatch_plan(
        request.expected_envelope,
        prove_adapter_replay(request),
    ).dispatch_items[0]

    with pytest.raises(ValueError, match="runtime_name"):
        RuntimeDispatchItem(
            sequence=item.sequence,
            capability=item.capability,
            runtime_kind=item.runtime_kind,
            runtime_name=RuntimeClientHandle(),
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
            capability=lambda: "execute",
            runtime_kind=item.runtime_kind,
            runtime_name=item.runtime_name,
            namespace=item.namespace,
            message_type=item.message_type,
            qos_profile_checksum=item.qos_profile_checksum,
            payload_checksum=item.payload_checksum,
            payload_size_bytes=item.payload_size_bytes,
            field_map_checksum=item.field_map_checksum,
        )


def test_dispatch_firewall_blocks_runtime_object_injected_after_construction() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-object-firewall")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    object.__setattr__(plan.dispatch_items[0], "runtime_kind", RuntimeClientHandle())

    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_OBJECT_INJECTION
