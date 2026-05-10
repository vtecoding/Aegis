"""Adversarial tests for runtime object injection into ADR-0018 backends."""

from __future__ import annotations

from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import BackendCertificationReason, BackendCertificationStatus
from aegis.execution import (
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)


class CallableInjectedBackend:
    """Test-only backend object with a callable runtime handle."""

    def __init__(self, descriptor: object) -> None:
        self.descriptor = descriptor
        self.publish_callback = self.publish

    def publish(self) -> None:
        """Represent a forbidden runtime publishing surface."""


class ClientInjectedBackend:
    """Test-only backend object with a client handle."""

    def __init__(self, descriptor: object) -> None:
        self.descriptor = descriptor
        self.ros_client = object()


class MutableInjectedBackend:
    """Test-only backend object with mutable runtime state."""

    def __init__(self, descriptor: object) -> None:
        self.descriptor = descriptor
        self.runtime_state = {"queue": "execute"}


def _plan_decision_descriptor() -> tuple[object, object, object]:
    request = adapter_replay_request(request_id="backend-runtime-object-injection")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)
    decision = evaluate_dispatch_firewall(plan, request.expected_envelope, proof)
    backend = build_null_runtime_backend(plan)
    return plan, decision, backend.descriptor


def test_backend_certification_blocks_callable_runtime_surface() -> None:
    plan, decision, descriptor = _plan_decision_descriptor()
    backend = CallableInjectedBackend(descriptor)

    certification = certify_runtime_backend(plan, decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert certification.reason_code == BackendCertificationReason.BACKEND_RUNTIME_OBJECT_INJECTION


def test_backend_certification_blocks_client_runtime_surface() -> None:
    plan, decision, descriptor = _plan_decision_descriptor()
    backend = ClientInjectedBackend(descriptor)

    certification = certify_runtime_backend(plan, decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert certification.reason_code == BackendCertificationReason.BACKEND_RUNTIME_OBJECT_INJECTION


def test_backend_certification_blocks_mutable_runtime_state() -> None:
    plan, decision, descriptor = _plan_decision_descriptor()
    backend = MutableInjectedBackend(descriptor)

    certification = certify_runtime_backend(plan, decision, backend)

    assert certification.status is BackendCertificationStatus.BLOCKED
    assert certification.reason_code == BackendCertificationReason.BACKEND_RUNTIME_OBJECT_INJECTION


def test_null_runtime_backend_rejects_non_descriptor_object() -> None:
    from aegis.execution.null_runtime_backend import NullRuntimeBackend

    try:
        NullRuntimeBackend(descriptor=object())
    except ValueError as exc:
        assert "RuntimeBackendDescriptor" in str(exc)
    else:
        raise AssertionError("non-descriptor null backend construction was accepted")
