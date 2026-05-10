"""Invariant tests for ADR-0018 null backend certification."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    recompute_backend_certification_checksum,
)
from aegis.execution import (
    build_backend_dry_run_receipt,
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_null_backend_certification_is_deterministic(request_number: int) -> None:
    request = adapter_replay_request(request_id=f"null-backend-determinism-{request_number}")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)

    first = certify_runtime_backend(plan, decision, backend)
    second = certify_runtime_backend(plan, decision, backend)

    assert first == second
    assert first.certification_checksum == second.certification_checksum


def test_invariant_backend_certification_checksum_changes_on_bound_field_change() -> None:
    request = adapter_replay_request(request_id="null-backend-cert-bound-field")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    certification = certify_runtime_backend(plan, decision, backend)
    changed = BackendCertificationResult(
        status=BackendCertificationStatus.BLOCKED,
        reason_code=BackendCertificationReason.BACKEND_ASYNC_CAPABILITY_CLAIMED.value,
        dispatch_plan_checksum=certification.dispatch_plan_checksum,
        firewall_decision_checksum=certification.firewall_decision_checksum,
        backend_descriptor_checksum=certification.backend_descriptor_checksum,
        no_execution_guarantee=certification.no_execution_guarantee,
        no_io_guarantee=certification.no_io_guarantee,
        no_async_guarantee=False,
        capability_scope_match=certification.capability_scope_match,
        runtime_kind_scope_match=certification.runtime_kind_scope_match,
    )

    assert certification.certification_checksum != changed.certification_checksum
    assert certification.certification_checksum == recompute_backend_certification_checksum(
        certification
    )


def test_invariant_null_backend_never_mutates_dispatch_plan() -> None:
    request = adapter_replay_request(request_id="null-backend-no-plan-mutation")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    plan_checksum = plan.plan_checksum
    dispatch_items = plan.dispatch_items
    backend = build_null_runtime_backend(plan)

    certification = certify_runtime_backend(plan, decision, backend)
    build_backend_dry_run_receipt(plan, decision, backend, certification)

    assert plan.plan_checksum == plan_checksum
    assert plan.dispatch_items == dispatch_items


def test_invariant_backend_receipt_always_reports_zero_execution() -> None:
    request = adapter_replay_request(request_id="null-backend-zero-execution")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    certification = certify_runtime_backend(plan, decision, backend)

    receipt = build_backend_dry_run_receipt(plan, decision, backend, certification)

    assert receipt.executed_count == 0
