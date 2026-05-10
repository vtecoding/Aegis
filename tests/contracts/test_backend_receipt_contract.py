"""Contract tests for ADR-0018 null backend dry-run receipts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import (
    BackendDryRunReceipt,
    backend_dry_run_receipt_checksum,
    recompute_backend_dry_run_receipt_checksum,
)
from aegis.execution import (
    build_backend_dry_run_receipt,
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    is_backend_dry_run_receipt_valid,
    prove_adapter_replay,
)


def _receipt_tuple() -> tuple[BackendDryRunReceipt, object, object, object, object]:
    request = adapter_replay_request(request_id="backend-receipt-contract")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    certification = certify_runtime_backend(plan, decision, backend)
    receipt = build_backend_dry_run_receipt(plan, decision, backend, certification)
    return receipt, plan, decision, backend, certification


def test_backend_dry_run_receipt_binds_certified_null_backend() -> None:
    receipt, plan, decision, backend, certification = _receipt_tuple()

    assert receipt.dispatch_plan_checksum == plan.plan_checksum
    assert receipt.firewall_decision_checksum == decision.decision_checksum
    assert receipt.backend_certification_checksum == certification.certification_checksum
    assert receipt.backend_descriptor_checksum == backend.descriptor.descriptor_checksum
    assert receipt.executed_count == 0
    assert receipt.blocked_execution_count == len(plan.dispatch_items)
    assert receipt.receipt_checksum == recompute_backend_dry_run_receipt_checksum(receipt)
    assert is_backend_dry_run_receipt_valid(receipt, plan, decision, backend, certification)


def test_backend_dry_run_receipt_checksum_helper_is_canonical() -> None:
    receipt, _, _, _, _ = _receipt_tuple()

    assert receipt.receipt_checksum == backend_dry_run_receipt_checksum(
        receipt_id=receipt.receipt_id,
        dispatch_plan_checksum=receipt.dispatch_plan_checksum,
        firewall_decision_checksum=receipt.firewall_decision_checksum,
        backend_certification_checksum=receipt.backend_certification_checksum,
        backend_descriptor_checksum=receipt.backend_descriptor_checksum,
        observed_dispatch_items=receipt.observed_dispatch_items,
        executed_count=receipt.executed_count,
        blocked_execution_count=receipt.blocked_execution_count,
    )


def test_backend_dry_run_receipt_rejects_nonzero_execution_count() -> None:
    receipt, _, _, _, _ = _receipt_tuple()

    with pytest.raises(ValueError, match="BACKEND_RECEIPT_EXECUTED_COUNT_NONZERO"):
        BackendDryRunReceipt(
            receipt_id=receipt.receipt_id,
            dispatch_plan_checksum=receipt.dispatch_plan_checksum,
            firewall_decision_checksum=receipt.firewall_decision_checksum,
            backend_certification_checksum=receipt.backend_certification_checksum,
            backend_descriptor_checksum=receipt.backend_descriptor_checksum,
            observed_dispatch_items=receipt.observed_dispatch_items,
            executed_count=1,
            blocked_execution_count=receipt.blocked_execution_count,
        )


def test_backend_dry_run_receipt_validation_blocks_execution_drift() -> None:
    receipt, plan, decision, backend, certification = _receipt_tuple()
    object.__setattr__(receipt, "executed_count", 1)

    assert not is_backend_dry_run_receipt_valid(receipt, plan, decision, backend, certification)


@pytest.mark.parametrize(
    "field_name",
    (
        "dispatch_plan_checksum",
        "firewall_decision_checksum",
        "backend_certification_checksum",
        "backend_descriptor_checksum",
    ),
)
def test_backend_dry_run_receipt_validation_blocks_binding_drift(field_name: str) -> None:
    receipt, plan, decision, backend, certification = _receipt_tuple()
    object.__setattr__(receipt, field_name, "3" * 64)

    assert not is_backend_dry_run_receipt_valid(receipt, plan, decision, backend, certification)


def test_backend_dry_run_receipt_validation_blocks_observed_item_drift() -> None:
    receipt, plan, decision, backend, certification = _receipt_tuple()
    object.__setattr__(receipt, "observed_dispatch_items", ("4" * 64,))

    assert not is_backend_dry_run_receipt_valid(receipt, plan, decision, backend, certification)


def test_backend_dry_run_receipt_validation_blocks_count_and_checksum_drift() -> None:
    count_receipt, plan, decision, backend, certification = _receipt_tuple()
    object.__setattr__(count_receipt, "blocked_execution_count", 99)
    checksum_receipt, checksum_plan, checksum_decision, checksum_backend, checksum_certification = (
        _receipt_tuple()
    )
    object.__setattr__(checksum_receipt, "receipt_checksum", "5" * 64)

    assert not is_backend_dry_run_receipt_valid(
        count_receipt, plan, decision, backend, certification
    )
    assert not is_backend_dry_run_receipt_valid(
        checksum_receipt,
        checksum_plan,
        checksum_decision,
        checksum_backend,
        checksum_certification,
    )


def test_backend_dry_run_receipt_rejects_forged_checksum() -> None:
    receipt, _, _, _, _ = _receipt_tuple()

    with pytest.raises(ValueError, match="receipt_checksum"):
        BackendDryRunReceipt(
            receipt_id=receipt.receipt_id,
            dispatch_plan_checksum=receipt.dispatch_plan_checksum,
            firewall_decision_checksum=receipt.firewall_decision_checksum,
            backend_certification_checksum=receipt.backend_certification_checksum,
            backend_descriptor_checksum=receipt.backend_descriptor_checksum,
            observed_dispatch_items=receipt.observed_dispatch_items,
            executed_count=0,
            blocked_execution_count=receipt.blocked_execution_count,
            receipt_checksum="0" * 64,
        )
