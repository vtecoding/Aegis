"""Invariant tests for ADR-0017 runtime dispatch dry-run planning."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_dispatch import recompute_runtime_dispatch_plan_checksum
from aegis.execution import (
    build_runtime_dispatch_plan,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_runtime_dispatch_planning_is_deterministic(request_number: int) -> None:
    request = adapter_replay_request(request_id=f"runtime-dispatch-determinism-{request_number}")
    proof = prove_adapter_replay(request)

    first = build_runtime_dispatch_plan(request.expected_envelope, proof)
    second = build_runtime_dispatch_plan(request.expected_envelope, proof)

    assert first == second
    assert first.plan_checksum == second.plan_checksum


def test_invariant_firewall_decision_is_deterministic() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-firewall-determinism")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)

    first = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    second = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    assert first == second
    assert first.decision_checksum == second.decision_checksum


def test_invariant_plan_checksum_changes_when_bound_field_changes() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-bound-field")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    baseline = plan.plan_checksum
    object.__setattr__(plan.dispatch_items[0], "payload_checksum", "1" * 64)

    assert baseline != recompute_runtime_dispatch_plan_checksum(plan)


def test_invariant_allowed_firewall_decision_requires_dry_run_mode() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-dry-run-only")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    object.__setattr__(plan, "dispatch_mode", "EXECUTE")

    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    assert decision.status == "BLOCKED"


def test_invariant_runtime_dispatch_plan_does_not_mutate_source_evidence() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-no-mutation")
    proof = prove_adapter_replay(request)
    envelope_checksum = request.expected_envelope.envelope_checksum
    proof_checksum = proof.proof_checksum

    build_runtime_dispatch_plan(request.expected_envelope, proof)

    assert request.expected_envelope.envelope_checksum == envelope_checksum
    assert proof.proof_checksum == proof_checksum
