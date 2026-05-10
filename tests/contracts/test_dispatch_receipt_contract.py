"""Contract tests for ADR-0017 runtime dispatch dry-run receipts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_dispatch import (
    DispatchFirewallDecision,
    DispatchFirewallReason,
    RuntimeDispatchReceipt,
    make_dispatch_firewall_allow_authorization,
    recompute_dispatch_firewall_decision_checksum,
    recompute_runtime_dispatch_receipt_checksum,
    runtime_dispatch_receipt_checksum,
)
from aegis.execution import (
    build_runtime_dispatch_plan,
    build_runtime_dispatch_receipt,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def test_runtime_dispatch_receipt_binds_allowed_dry_run_decision() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-receipt")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    receipt = build_runtime_dispatch_receipt(plan, decision)

    assert decision.status == "ALLOWED_DRY_RUN"
    assert decision.decision_checksum == recompute_dispatch_firewall_decision_checksum(decision)
    assert receipt.status == "ALLOWED_DRY_RUN"
    assert receipt.reason_code == DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value
    assert receipt.plan_checksum == plan.plan_checksum
    assert receipt.source_envelope_checksum == plan.source_envelope_checksum
    assert receipt.source_replay_proof_checksum == proof.proof_checksum
    assert receipt.dry_run_receipt_checksum == recompute_runtime_dispatch_receipt_checksum(receipt)


def test_runtime_dispatch_receipt_checksum_helper_is_canonical() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-receipt-helper")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    receipt = build_runtime_dispatch_receipt(plan, decision)

    assert receipt.dry_run_receipt_checksum == runtime_dispatch_receipt_checksum(
        status=receipt.status,
        reason_code=receipt.reason_code,
        plan_checksum=receipt.plan_checksum,
        source_envelope_checksum=receipt.source_envelope_checksum,
        source_replay_proof_checksum=receipt.source_replay_proof_checksum,
        decision_checksum=receipt.decision_checksum,
        dispatch_mode=receipt.dispatch_mode,
    )


def test_runtime_dispatch_receipt_rejects_forged_checksum() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-receipt-forged")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)

    with pytest.raises(ValueError, match="dry_run_receipt_checksum"):
        RuntimeDispatchReceipt(
            status=decision.status,
            reason_code=decision.reason_code,
            plan_checksum=plan.plan_checksum,
            source_envelope_checksum=plan.source_envelope_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            decision_checksum=decision.decision_checksum,
            dispatch_mode=plan.dispatch_mode,
            dry_run_receipt_checksum="0" * 64,
        )


def test_direct_allowed_firewall_decision_construction_is_rejected() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-direct-decision")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)

    with pytest.raises(
        ValueError,
        match=DispatchFirewallReason.DIRECT_DISPATCH_FIREWALL_BYPASS.value,
    ):
        DispatchFirewallDecision(
            status="ALLOWED_DRY_RUN",
            reason_code=DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value,
            plan_checksum=plan.plan_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage=None,
        )


def test_firewall_decision_rejects_inconsistent_status_reason_and_authority() -> None:
    request = adapter_replay_request(request_id="runtime-dispatch-decision-invalid")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    authorization = make_dispatch_firewall_allow_authorization(plan=plan, replay_proof=proof)

    with pytest.raises(ValueError, match="allowed reason"):
        DispatchFirewallDecision(
            status="ALLOWED_DRY_RUN",
            reason_code=DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_MISMATCH.value,
            plan_checksum=plan.plan_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage=None,
            authorization=authorization,
        )
    with pytest.raises(ValueError, match="blocked_stage"):
        DispatchFirewallDecision(
            status="ALLOWED_DRY_RUN",
            reason_code=DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value,
            plan_checksum=plan.plan_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage="dispatch_firewall",
            authorization=authorization,
        )
    with pytest.raises(ValueError, match="plan_checksum"):
        DispatchFirewallDecision(
            status="ALLOWED_DRY_RUN",
            reason_code=DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value,
            plan_checksum="1" * 64,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage=None,
            authorization=authorization,
        )
    with pytest.raises(ValueError, match="allowed reason"):
        DispatchFirewallDecision(
            status="BLOCKED",
            reason_code=DispatchFirewallReason.DISPATCH_FIREWALL_ALLOWED_DRY_RUN.value,
            plan_checksum=plan.plan_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage="dispatch_firewall",
        )
    with pytest.raises(ValueError, match="blocked_stage"):
        DispatchFirewallDecision(
            status="BLOCKED",
            reason_code=DispatchFirewallReason.RUNTIME_DISPATCH_PAYLOAD_MISMATCH.value,
            plan_checksum=plan.plan_checksum,
            source_replay_proof_checksum=proof.proof_checksum,
            blocked_stage=None,
        )
