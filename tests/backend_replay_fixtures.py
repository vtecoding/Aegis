"""Shared deterministic fixtures for ADR-0019 backend replay tests."""

from __future__ import annotations

from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.backend_replay import BackendReplayRequest
from aegis.contracts.runtime_backend import BackendCertificationResult, BackendDryRunReceipt
from aegis.contracts.runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan
from aegis.execution import (
    build_backend_dry_run_receipt,
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    certify_runtime_backend,
    evaluate_dispatch_firewall,
    prove_adapter_replay,
)
from aegis.execution.null_runtime_backend import NullRuntimeBackend


def backend_replay_parts(
    *,
    request_id: str = "backend-replay",
) -> tuple[
    RuntimeDispatchPlan,
    DispatchFirewallDecision,
    NullRuntimeBackend,
    BackendCertificationResult,
    BackendDryRunReceipt,
]:
    """Return the positive ADR-0019 source evidence chain."""
    adapter_request = adapter_replay_request(request_id=request_id)
    adapter_proof = prove_adapter_replay(adapter_request)
    plan = build_runtime_dispatch_plan(adapter_request.expected_envelope, adapter_proof)
    decision = evaluate_dispatch_firewall(plan, adapter_request.expected_envelope, adapter_proof)
    backend = build_null_runtime_backend(plan)
    certification = certify_runtime_backend(plan, decision, backend)
    receipt = build_backend_dry_run_receipt(plan, decision, backend, certification)
    return plan, decision, backend, certification, receipt


def backend_replay_request(*, request_id: str = "backend-replay") -> BackendReplayRequest:
    """Return a deterministic positive backend replay request."""
    plan, decision, backend, certification, receipt = backend_replay_parts(request_id=request_id)
    return BackendReplayRequest(
        dispatch_plan=plan,
        firewall_decision=decision,
        backend_descriptor=backend.descriptor,
        expected_certification=certification,
        expected_receipt=receipt,
    )


__all__ = ["backend_replay_parts", "backend_replay_request"]
