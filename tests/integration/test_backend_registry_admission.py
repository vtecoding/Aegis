"""Integration tests for ADR-0020 backend registry admission."""

from __future__ import annotations

from tests.backend_authority_fixtures import backend_admission_request

from aegis.execution.aegis_backend_admission import admit_runtime_backend


def test_valid_null_backend_admits() -> None:
    request = backend_admission_request(request_id="backend-admission-positive")

    decision = admit_runtime_backend(request)

    assert decision.status == "ADMITTED"
    assert decision.reason_code == "BACKEND_ADMISSION_ADMITTED_NULL_BACKEND"
    assert decision.backend_kind == "NULL_BACKEND_V1"
    assert decision.backend_descriptor_checksum == request.backend_descriptor.descriptor_checksum
    assert decision.certification_checksum == request.backend_certification.certification_checksum
    assert decision.replay_proof_checksum == request.backend_replay_proof.proof_checksum
    assert decision.authority_manifest_checksum == request.authority_manifest.manifest_checksum
    assert decision.registry_checksum == request.registry_checksum


def test_unknown_backend_kind_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-unknown-kind")
    object.__setattr__(request.backend_descriptor, "backend_kind", "UNDECLARED_BACKEND_V1")

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_UNKNOWN_BACKEND_KIND"


def test_non_null_backend_kind_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-non-null-kind")
    object.__setattr__(request.backend_descriptor, "backend_kind", "SIMULATOR_BACKEND_V1")

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_BACKEND_KIND_NOT_NULL"


def test_missing_certification_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-missing-certification")
    object.__setattr__(request, "backend_certification", None)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_CERTIFICATION_MISSING"


def test_missing_replay_proof_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-missing-replay")
    object.__setattr__(request, "backend_replay_proof", None)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_REPLAY_PROOF_MISSING"


def test_manifest_drift_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-manifest-drift")
    object.__setattr__(request.authority_manifest, "manifest_checksum", "0" * 64)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_MANIFEST_CHECKSUM_DRIFT"


def test_registry_drift_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-registry-drift")
    object.__setattr__(request, "registry_checksum", "0" * 64)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT"


def test_only_null_backend_is_admitted() -> None:
    request = backend_admission_request(request_id="backend-admission-only-null")
    positive = admit_runtime_backend(request)
    object.__setattr__(request.backend_descriptor, "backend_kind", "SIMULATOR_BACKEND_V1")
    negative = admit_runtime_backend(request)

    assert positive.status == "ADMITTED"
    assert negative.status == "BLOCKED"
