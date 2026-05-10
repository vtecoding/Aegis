"""Contract tests for ADR-0018 backend certification results."""

from __future__ import annotations

from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    recompute_backend_certification_checksum,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.runtime_dispatch import DispatchFirewallDecision, DispatchFirewallReason
from aegis.execution import (
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


def _certification_tuple() -> tuple[BackendCertificationResult, object, object, object]:
    request = adapter_replay_request(request_id="backend-certification-contract")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    certification = certify_runtime_backend(plan, decision, backend)
    return certification, plan, decision, backend


def test_valid_dry_run_dispatch_plan_certifies_null_backend() -> None:
    certification, plan, decision, backend = _certification_tuple()

    assert certification.status is BackendCertificationStatus.CERTIFIED_NULL
    assert certification.reason_code == BackendCertificationReason.BACKEND_CERTIFIED_NULL.value
    assert certification.dispatch_plan_checksum == plan.plan_checksum
    assert certification.firewall_decision_checksum == decision.decision_checksum
    assert certification.backend_descriptor_checksum == backend.descriptor.descriptor_checksum
    assert certification.no_execution_guarantee is True
    assert certification.no_io_guarantee is True
    assert certification.no_async_guarantee is True
    assert certification.capability_scope_match is True
    assert certification.runtime_kind_scope_match is True
    assert certification.certification_checksum == recompute_backend_certification_checksum(
        certification
    )


def test_backend_certification_blocks_invalid_firewall_decision() -> None:
    request = adapter_replay_request(request_id="backend-certification-blocked-decision")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    blocked_decision = DispatchFirewallDecision(
        status="BLOCKED",
        reason_code=DispatchFirewallReason.RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY.value,
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


def test_backend_certification_blocks_non_null_kind_and_scope_drift() -> None:
    non_null_certification, plan, decision, backend = _certification_tuple()
    object.__setattr__(backend.descriptor, "backend_kind", "ROS_BACKEND_V1")
    object.__setattr__(
        backend.descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(backend.descriptor),
    )
    non_null_certification = certify_runtime_backend(plan, decision, backend)

    scope_request = adapter_replay_request(request_id="backend-certification-scope")
    scope_proof = prove_adapter_replay(scope_request)
    scope_plan = build_runtime_dispatch_plan(scope_request.expected_envelope, scope_proof)
    scope_decision = evaluate_dispatch_firewall(
        scope_plan, scope_request.expected_envelope, scope_proof
    )
    scope_backend = build_null_runtime_backend(scope_plan)
    object.__setattr__(
        scope_backend.descriptor,
        "supported_capabilities",
        frozenset({"locomotion.stop"}),
    )
    object.__setattr__(
        scope_backend.descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(scope_backend.descriptor),
    )
    scope_certification = certify_runtime_backend(scope_plan, scope_decision, scope_backend)

    assert non_null_certification.status is BackendCertificationStatus.BLOCKED
    assert non_null_certification.reason_code == BackendCertificationReason.BACKEND_KIND_NOT_NULL
    assert scope_certification.status is BackendCertificationStatus.BLOCKED
    assert (
        scope_certification.reason_code == BackendCertificationReason.BACKEND_CAPABILITY_SCOPE_DRIFT
    )


def test_backend_certification_blocks_execution_io_and_async_flags() -> None:
    for field_name, reason in (
        ("allows_execution", BackendCertificationReason.BACKEND_EXECUTION_CAPABILITY_CLAIMED),
        ("allows_io", BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED),
        ("allows_async", BackendCertificationReason.BACKEND_ASYNC_CAPABILITY_CLAIMED),
    ):
        certification, plan, decision, backend = _certification_tuple()
        object.__setattr__(backend.descriptor, field_name, True)
        object.__setattr__(
            backend.descriptor,
            "descriptor_checksum",
            recompute_runtime_backend_descriptor_checksum(backend.descriptor),
        )

        certification = certify_runtime_backend(plan, decision, backend)

        assert certification.status is BackendCertificationStatus.BLOCKED
        assert certification.reason_code == reason


def test_backend_certification_result_rejects_forged_checksum() -> None:
    certification, _, _, _ = _certification_tuple()

    try:
        BackendCertificationResult(
            status=certification.status,
            reason_code=certification.reason_code,
            dispatch_plan_checksum=certification.dispatch_plan_checksum,
            firewall_decision_checksum=certification.firewall_decision_checksum,
            backend_descriptor_checksum=certification.backend_descriptor_checksum,
            no_execution_guarantee=certification.no_execution_guarantee,
            no_io_guarantee=certification.no_io_guarantee,
            no_async_guarantee=certification.no_async_guarantee,
            capability_scope_match=certification.capability_scope_match,
            runtime_kind_scope_match=certification.runtime_kind_scope_match,
            certification_checksum="0" * 64,
        )
    except ValueError as exc:
        assert "certification_checksum" in str(exc)
    else:
        raise AssertionError("forged certification checksum was accepted")


def test_repeated_backend_certification_is_deterministic() -> None:
    _, plan, decision, backend = _certification_tuple()

    first = certify_runtime_backend(plan, decision, backend)
    second = certify_runtime_backend(plan, decision, backend)

    assert first == second
    assert first.certification_checksum == second.certification_checksum


def test_backend_certification_checksum_changes_on_bound_field_change() -> None:
    certification, _, _, _ = _certification_tuple()
    changed = BackendCertificationResult(
        status=BackendCertificationStatus.BLOCKED,
        reason_code=BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED.value,
        dispatch_plan_checksum=certification.dispatch_plan_checksum,
        firewall_decision_checksum=certification.firewall_decision_checksum,
        backend_descriptor_checksum=certification.backend_descriptor_checksum,
        no_execution_guarantee=certification.no_execution_guarantee,
        no_io_guarantee=False,
        no_async_guarantee=certification.no_async_guarantee,
        capability_scope_match=certification.capability_scope_match,
        runtime_kind_scope_match=certification.runtime_kind_scope_match,
    )

    assert certification.certification_checksum != changed.certification_checksum
