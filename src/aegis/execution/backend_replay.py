"""Deterministic backend certification and receipt replay for ADR-0019."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.backend_replay import BackendReplayRequest
from aegis.contracts.runtime_backend import BackendCertificationResult, BackendDryRunReceipt
from aegis.execution.backend_certification import certify_runtime_backend
from aegis.execution.backend_receipt import build_backend_dry_run_receipt
from aegis.execution.null_runtime_backend import NullRuntimeBackend


@dataclass(frozen=True, slots=True)
class BackendReplayOutput:
    """Reconstructed backend certification and dry-run receipt evidence."""

    certification: BackendCertificationResult
    receipt: BackendDryRunReceipt


def replay_runtime_backend(request: BackendReplayRequest) -> BackendReplayOutput:
    """Rebuild backend certification and receipt evidence from replay request data."""
    backend = NullRuntimeBackend(descriptor=request.backend_descriptor)
    certification = certify_runtime_backend(
        request.dispatch_plan,
        request.firewall_decision,
        backend,
    )
    receipt = build_backend_dry_run_receipt(
        request.dispatch_plan,
        request.firewall_decision,
        backend,
        certification,
    )
    return BackendReplayOutput(certification=certification, receipt=receipt)


__all__ = ["BackendReplayOutput", "replay_runtime_backend"]
