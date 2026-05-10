"""Integration tests for ADR-0017 dispatch plans to ADR-0018 null backend receipts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import BackendCertificationReason, BackendCertificationStatus
from aegis.contracts.runtime_dispatch import DispatchFirewallDecision, DispatchFirewallReason
from aegis.execution import (
    build_backend_dry_run_receipt,
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def test_firewall_allowed_dispatch_plan_produces_certified_null_backend_receipt() -> None:
    request = adapter_replay_request(request_id="dispatch-to-null-backend")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)

    certification = certify_runtime_backend(plan, decision, backend)
    receipt = build_backend_dry_run_receipt(plan, decision, backend, certification)

    assert decision.status == "ALLOWED_DRY_RUN"
    assert certification.status is BackendCertificationStatus.CERTIFIED_NULL
    assert receipt.executed_count == 0
    assert receipt.blocked_execution_count == len(plan.dispatch_items)


def test_invalid_firewall_decision_cannot_produce_null_backend_receipt() -> None:
    request = adapter_replay_request(request_id="dispatch-to-null-backend-blocked")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    blocked_decision = DispatchFirewallDecision(
        status="BLOCKED",
        reason_code=DispatchFirewallReason.RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH.value,
        plan_checksum=plan.plan_checksum,
        source_replay_proof_checksum=proof.proof_checksum,
        blocked_stage="dispatch_firewall",
    )

    certification = certify_runtime_backend(plan, blocked_decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert (
        certification.reason_code
        == BackendCertificationReason.BACKEND_FIREWALL_DECISION_NOT_ALLOWED.value
    )
    with pytest.raises(ValueError, match="BACKEND_FIREWALL_DECISION_NOT_ALLOWED"):
        build_backend_dry_run_receipt(plan, blocked_decision, backend, certification)
