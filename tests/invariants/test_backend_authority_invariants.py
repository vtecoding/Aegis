"""Invariant tests for ADR-0020 backend authority admission."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.backend_authority_fixtures import backend_admission_request

from aegis.execution.backend_admission import BackendAdmissionDecision, admit_runtime_backend


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_backend_admission_is_deterministic(request_number: int) -> None:
    request = backend_admission_request(request_id=f"backend-admission-{request_number}")

    first = admit_runtime_backend(request)
    second = admit_runtime_backend(request)

    assert first == second
    assert first.decision_checksum == second.decision_checksum


def test_invariant_only_null_backend_is_admitted() -> None:
    request = backend_admission_request(request_id="backend-admission-invariant-null-only")

    admitted = admit_runtime_backend(request)
    object.__setattr__(request.backend_descriptor, "backend_kind", "SIMULATOR_BACKEND_V1")
    blocked = admit_runtime_backend(request)

    assert admitted.status == "ADMITTED"
    assert admitted.backend_kind == "NULL_BACKEND_V1"
    assert blocked.status == "BLOCKED"


def test_invariant_backend_admission_does_not_mutate_request_evidence() -> None:
    request = backend_admission_request(request_id="backend-admission-no-mutation")
    descriptor_checksum = request.backend_descriptor.descriptor_checksum
    certification_checksum = request.backend_certification.certification_checksum
    proof_checksum = request.backend_replay_proof.proof_checksum
    manifest_checksum = request.authority_manifest.manifest_checksum
    registry_checksum = request.registry_checksum

    admit_runtime_backend(request)

    assert request.backend_descriptor.descriptor_checksum == descriptor_checksum
    assert request.backend_certification.certification_checksum == certification_checksum
    assert request.backend_replay_proof.proof_checksum == proof_checksum
    assert request.authority_manifest.manifest_checksum == manifest_checksum
    assert request.registry_checksum == registry_checksum


def test_invariant_backend_admission_decision_checksum_changes_on_bound_field_change() -> None:
    decision = admit_runtime_backend(
        backend_admission_request(request_id="backend-admission-bound-field")
    )
    changed_decisions = (
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code=decision.reason_code,
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind="UNKNOWN_BACKEND_KIND",
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum="1" * 64,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum="1" * 64,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum="1" * 64,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum="1" * 64,
            registry_checksum=decision.registry_checksum,
        ),
        BackendAdmissionDecision(
            status="BLOCKED",
            reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
            backend_kind=decision.backend_kind,
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum="1" * 64,
        ),
    )

    assert all(
        decision.decision_checksum != changed.decision_checksum for changed in changed_decisions
    )
