"""Adversarial tests for ADR-0018 backend certification bypass attempts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationStatus,
    recompute_backend_certification_checksum,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.runtime_dispatch import recompute_dispatch_firewall_decision_checksum
from aegis.execution import (
    build_backend_dry_run_receipt,
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def _backend_tuple() -> tuple[object, object, object, object]:
    request = adapter_replay_request(request_id="backend-certification-bypass")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    return plan, decision, backend, proof


def test_backend_certification_rejects_non_null_backend_kind() -> None:
    plan, decision, backend, _ = _backend_tuple()
    object.__setattr__(backend.descriptor, "backend_kind", "ROS_BACKEND_V1")
    object.__setattr__(
        backend.descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(backend.descriptor),
    )

    certification = certify_runtime_backend(plan, decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert certification.reason_code == BackendCertificationReason.BACKEND_KIND_NOT_NULL


def test_backend_certification_rejects_execution_io_and_async_claims() -> None:
    for field_name, reason in (
        ("allows_execution", BackendCertificationReason.BACKEND_EXECUTION_CAPABILITY_CLAIMED),
        ("allows_io", BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED),
        ("allows_async", BackendCertificationReason.BACKEND_ASYNC_CAPABILITY_CLAIMED),
    ):
        plan, decision, backend, _ = _backend_tuple()
        object.__setattr__(backend.descriptor, field_name, True)
        object.__setattr__(
            backend.descriptor,
            "descriptor_checksum",
            recompute_runtime_backend_descriptor_checksum(backend.descriptor),
        )

        certification = certify_runtime_backend(plan, decision, backend)

        assert certification.status is BackendCertificationStatus.BLOCKED
        assert certification.reason_code == reason


def test_backend_certification_rejects_runtime_kind_scope_drift() -> None:
    plan, decision, backend, _ = _backend_tuple()
    object.__setattr__(backend.descriptor, "supported_runtime_kinds", frozenset())
    object.__setattr__(
        backend.descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(backend.descriptor),
    )

    certification = certify_runtime_backend(plan, decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert certification.reason_code == BackendCertificationReason.BACKEND_RUNTIME_KIND_SCOPE_DRIFT


def test_backend_certification_rejects_dry_run_plan_and_decision_drift() -> None:
    plan, decision, backend, _ = _backend_tuple()
    object.__setattr__(plan, "dispatch_mode", "EXECUTE")
    mode_certification = certify_runtime_backend(plan, decision, backend)

    plan_checksum_plan, plan_checksum_decision, plan_checksum_backend, _ = _backend_tuple()
    object.__setattr__(plan_checksum_plan, "plan_checksum", "6" * 64)
    plan_checksum_certification = certify_runtime_backend(
        plan_checksum_plan, plan_checksum_decision, plan_checksum_backend
    )

    decision_plan, decision, decision_backend, _ = _backend_tuple()
    object.__setattr__(decision, "plan_checksum", "7" * 64)
    object.__setattr__(
        decision,
        "decision_checksum",
        recompute_dispatch_firewall_decision_checksum(decision),
    )
    decision_plan_certification = certify_runtime_backend(decision_plan, decision, decision_backend)

    forged_decision_plan, forged_decision, forged_decision_backend, _ = _backend_tuple()
    object.__setattr__(forged_decision, "decision_checksum", "8" * 64)
    forged_decision_certification = certify_runtime_backend(
        forged_decision_plan,
        forged_decision,
        forged_decision_backend,
    )

    assert (
        mode_certification.reason_code
        == BackendCertificationReason.BACKEND_DISPATCH_MODE_NOT_DRY_RUN_ONLY
    )
    assert (
        plan_checksum_certification.reason_code
        == BackendCertificationReason.BACKEND_FIREWALL_PLAN_MISMATCH
    )
    assert (
        decision_plan_certification.reason_code
        == BackendCertificationReason.BACKEND_FIREWALL_PLAN_MISMATCH
    )
    assert (
        forged_decision_certification.reason_code
        == BackendCertificationReason.BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH
    )


def test_backend_certification_rejects_descriptor_checksum_and_mode_drift() -> None:
    checksum_plan, checksum_decision, checksum_backend, _ = _backend_tuple()
    object.__setattr__(checksum_backend.descriptor, "descriptor_checksum", "9" * 64)
    checksum_certification = certify_runtime_backend(
        checksum_plan, checksum_decision, checksum_backend
    )

    mode_plan, mode_decision, mode_backend, _ = _backend_tuple()
    object.__setattr__(mode_backend.descriptor, "backend_mode", "EXECUTE")
    object.__setattr__(
        mode_backend.descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(mode_backend.descriptor),
    )
    mode_certification = certify_runtime_backend(mode_plan, mode_decision, mode_backend)

    assert (
        checksum_certification.reason_code
        == BackendCertificationReason.BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH
    )
    assert (
        mode_certification.reason_code
        == BackendCertificationReason.BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY
    )


def test_backend_certification_rejects_missing_or_unsupported_backend() -> None:
    plan, decision, _, _ = _backend_tuple()
    missing = certify_runtime_backend(plan, decision, object())

    class DescriptorOnlyBackend:
        """Backend-shaped object that is not a certified implementation."""

        def __init__(self, descriptor: object) -> None:
            self.descriptor = descriptor

    descriptor_backend = build_null_runtime_backend(plan)
    unsupported = certify_runtime_backend(
        plan,
        decision,
        DescriptorOnlyBackend(descriptor_backend.descriptor),
    )

    assert missing.reason_code == BackendCertificationReason.BACKEND_UNSUPPORTED_IMPLEMENTATION
    assert unsupported.reason_code == BackendCertificationReason.BACKEND_UNSUPPORTED_IMPLEMENTATION


def test_backend_descriptor_recompute_rejects_unserializable_mutations() -> None:
    _, _, backend, _ = _backend_tuple()
    object.__setattr__(backend.descriptor, "backend_mode", object())

    with pytest.raises(ValueError, match="backend_mode"):
        recompute_runtime_backend_descriptor_checksum(backend.descriptor)

    clean_backend = build_null_runtime_backend(_backend_tuple()[0])
    object.__setattr__(clean_backend.descriptor, "supported_runtime_kinds", frozenset({object()}))
    with pytest.raises(ValueError, match="runtime kind"):
        recompute_runtime_backend_descriptor_checksum(clean_backend.descriptor)


def test_backend_dry_run_receipt_rejects_certification_checksum_drift() -> None:
    plan, decision, backend, _ = _backend_tuple()
    certification = certify_runtime_backend(plan, decision, backend)
    object.__setattr__(certification, "certification_checksum", "0" * 64)

    assert recompute_backend_certification_checksum(certification) != "0" * 64
    with pytest.raises(ValueError, match="BACKEND_CERTIFICATION_CHECKSUM_DRIFT"):
        build_backend_dry_run_receipt(plan, decision, backend, certification)


def test_backend_dry_run_receipt_rejects_source_checksum_drift() -> None:
    plan, decision, backend, _ = _backend_tuple()
    certification = certify_runtime_backend(plan, decision, backend)
    object.__setattr__(plan, "plan_checksum", "a" * 64)
    with pytest.raises(ValueError, match="BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(plan, decision, backend, certification)

    decision_plan, decision, decision_backend, _ = _backend_tuple()
    decision_certification = certify_runtime_backend(decision_plan, decision, decision_backend)
    object.__setattr__(decision, "decision_checksum", "b" * 64)
    with pytest.raises(ValueError, match="BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(
            decision_plan,
            decision,
            decision_backend,
            decision_certification,
        )

    descriptor_plan, descriptor_decision, descriptor_backend, _ = _backend_tuple()
    descriptor_certification = certify_runtime_backend(
        descriptor_plan,
        descriptor_decision,
        descriptor_backend,
    )
    object.__setattr__(descriptor_backend.descriptor, "descriptor_checksum", "c" * 64)
    with pytest.raises(ValueError, match="BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(
            descriptor_plan,
            descriptor_decision,
            descriptor_backend,
            descriptor_certification,
        )


def test_backend_dry_run_receipt_rejects_certification_binding_drift() -> None:
    plan, decision, backend, _ = _backend_tuple()
    certification = certify_runtime_backend(plan, decision, backend)

    object.__setattr__(certification, "dispatch_plan_checksum", "d" * 64)
    object.__setattr__(
        certification,
        "certification_checksum",
        recompute_backend_certification_checksum(certification),
    )
    with pytest.raises(ValueError, match="BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(plan, decision, backend, certification)

    decision_plan, decision, decision_backend, _ = _backend_tuple()
    decision_certification = certify_runtime_backend(decision_plan, decision, decision_backend)
    object.__setattr__(decision_certification, "firewall_decision_checksum", "e" * 64)
    object.__setattr__(
        decision_certification,
        "certification_checksum",
        recompute_backend_certification_checksum(decision_certification),
    )
    with pytest.raises(ValueError, match="BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(
            decision_plan,
            decision,
            decision_backend,
            decision_certification,
        )

    descriptor_plan, descriptor_decision, descriptor_backend, _ = _backend_tuple()
    descriptor_certification = certify_runtime_backend(
        descriptor_plan,
        descriptor_decision,
        descriptor_backend,
    )
    object.__setattr__(descriptor_certification, "backend_descriptor_checksum", "f" * 64)
    object.__setattr__(
        descriptor_certification,
        "certification_checksum",
        recompute_backend_certification_checksum(descriptor_certification),
    )
    with pytest.raises(ValueError, match="BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH"):
        build_backend_dry_run_receipt(
            descriptor_plan,
            descriptor_decision,
            descriptor_backend,
            descriptor_certification,
        )
