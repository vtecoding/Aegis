"""Shared deterministic fixtures for ADR-0020 backend authority tests."""

from __future__ import annotations

from tests.backend_replay_fixtures import backend_replay_request

from aegis.contracts.backend_replay import BackendReplayProofResult
from aegis.contracts.runtime_backend import BackendCertificationResult, RuntimeBackendDescriptor
from aegis.execution import (
    build_backend_authority_manifest,
    build_backend_authority_registry,
    prove_backend_replay,
)
from aegis.execution.backend_admission import BackendAdmissionRequest
from aegis.execution.backend_authority import BackendAuthorityManifest
from aegis.execution.backend_registry import BackendAuthorityRegistry


def backend_authority_parts(
    *,
    request_id: str = "backend-authority",
) -> tuple[
    RuntimeBackendDescriptor,
    BackendCertificationResult,
    BackendReplayProofResult,
    BackendAuthorityManifest,
    BackendAuthorityRegistry,
]:
    """Return the positive ADR-0020 source evidence chain."""
    replay_request = backend_replay_request(request_id=request_id)
    replay_proof = prove_backend_replay(replay_request)
    manifest = build_backend_authority_manifest(replay_request.backend_descriptor)
    registry = build_backend_authority_registry(manifest)
    return (
        replay_request.backend_descriptor,
        replay_request.expected_certification,
        replay_proof,
        manifest,
        registry,
    )


def backend_admission_request(
    *,
    request_id: str = "backend-authority",
) -> BackendAdmissionRequest:
    """Return a deterministic positive backend admission request."""
    descriptor, certification, replay_proof, manifest, registry = backend_authority_parts(
        request_id=request_id
    )
    return BackendAdmissionRequest(
        backend_descriptor=descriptor,
        backend_certification=certification,
        backend_replay_proof=replay_proof,
        authority_manifest=manifest,
        registry_checksum=registry.registry_checksum,
    )


__all__ = ["backend_admission_request", "backend_authority_parts"]
