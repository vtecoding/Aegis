"""Integration tests for ADR-0016 replay proof to ADR-0017 dry-run dispatch."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_dispatch import DispatchFirewallReason, RuntimeDispatchMode
from aegis.execution import (
    build_runtime_dispatch_plan,
    build_runtime_dispatch_receipt,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def test_valid_replay_proof_creates_allowed_dry_run_dispatch_plan() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-positive")
    proof = prove_adapter_replay(request)

    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    receipt = build_runtime_dispatch_receipt(plan, decision)

    assert proof.status == "PASSED"
    assert plan.dispatch_mode is RuntimeDispatchMode.DRY_RUN_ONLY
    assert decision.status == "ALLOWED_DRY_RUN"
    assert receipt.status == "ALLOWED_DRY_RUN"


def test_invalid_replay_proof_cannot_build_dispatch_plan() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-invalid-proof")
    object.__setattr__(request.expected_envelope, "envelope_checksum", "0" * 64)
    proof = prove_adapter_replay(request)

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED.value,
    ):
        build_runtime_dispatch_plan(request.expected_envelope, proof)


def test_firewall_blocks_replay_proof_status_mutation() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-proof-status")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    object.__setattr__(proof, "status", "FAILED")

    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED


def test_firewall_blocks_swapped_replay_proof() -> None:
    first = adapter_replay_request(request_id="runtime-dispatch-swap-a")
    second = adapter_replay_request(request_id="runtime-dispatch-swap-b")
    first_proof = prove_adapter_replay(first)
    second_proof = prove_adapter_replay(second)
    plan = build_runtime_dispatch_plan(first.expected_envelope, first_proof)

    decision = evaluate_dispatch_firewall(plan, first.expected_envelope, second_proof)

    assert decision.status == "BLOCKED"
    assert decision.reason_code in {
        DispatchFirewallReason.RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH.value,
        DispatchFirewallReason.RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP.value,
    }


def test_firewall_blocks_mutated_mapping_and_runtime_target() -> None:
    mapping_request = adapter_replay_request(request_id="runtime-dispatch-mapping-drift")
    mapping_proof = prove_adapter_replay(mapping_request)
    mapping_plan = build_runtime_dispatch_plan(mapping_request.expected_envelope, mapping_proof)
    assert mapping_request.expected_envelope.adapter_mapping is not None
    object.__setattr__(
        mapping_request.expected_envelope.adapter_mapping.ros2_mapping,
        "message_type",
        "msg/TamperedCommand",
    )

    mapping_decision = evaluate_dispatch_firewall(
        mapping_plan,
        mapping_request.expected_envelope,
        mapping_proof,
    )

    target_request = adapter_replay_request(request_id="runtime-dispatch-target-drift")
    target_proof = prove_adapter_replay(target_request)
    target_plan = build_runtime_dispatch_plan(target_request.expected_envelope, target_proof)
    object.__setattr__(target_request.expected_envelope, "runtime_target_checksum", "1" * 64)
    target_decision = evaluate_dispatch_firewall(
        target_plan,
        target_request.expected_envelope,
        target_proof,
    )

    assert mapping_decision.status == "BLOCKED"
    assert (
        mapping_decision.reason_code
        == DispatchFirewallReason.RUNTIME_DISPATCH_MESSAGE_TYPE_MISMATCH
    )
    assert target_decision.status == "BLOCKED"
    assert (
        target_decision.reason_code
        == DispatchFirewallReason.RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH
    )
