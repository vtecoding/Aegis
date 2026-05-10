"""Contract tests for ADR-0020 backend admission requests and decisions."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.backend_authority_fixtures import backend_admission_request, backend_authority_parts

from aegis.contracts.aegis_runtime_backend import RuntimeBackendKind
from aegis.execution.aegis_backend_admission import (
    BackendAdmissionDecision,
    BackendAdmissionRequest,
    admit_runtime_backend,
    recompute_backend_admission_decision_checksum,
)


def test_backend_admission_request_binds_authority_evidence() -> None:
    request = backend_admission_request(request_id="backend-admission-contract")

    assert request.backend_descriptor.descriptor_checksum == (
        request.backend_certification.backend_descriptor_checksum
    )
    assert request.backend_replay_proof.expected_certification_checksum == (
        request.backend_certification.certification_checksum
    )
    assert request.authority_manifest.backend_kind is RuntimeBackendKind.NULL_BACKEND_V1
    assert len(request.registry_checksum) == 64


def test_backend_admission_request_and_decision_are_immutable() -> None:
    request = backend_admission_request(request_id="backend-admission-immutable")
    decision = admit_runtime_backend(request)

    with pytest.raises(FrozenInstanceError):
        request.registry_checksum = "0" * 64
    with pytest.raises(FrozenInstanceError):
        decision.status = "BLOCKED"


def test_backend_admission_request_rejects_raw_dict_escape_hatches() -> None:
    descriptor, certification, replay_proof, manifest, registry = backend_authority_parts(
        request_id="backend-admission-raw-dict"
    )

    with pytest.raises(ValueError, match="backend_descriptor"):
        BackendAdmissionRequest(
            backend_descriptor={},
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
        )
    with pytest.raises(ValueError, match="authority_manifest"):
        BackendAdmissionRequest(
            backend_descriptor=descriptor,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            authority_manifest={},
            registry_checksum=registry.registry_checksum,
        )


def test_backend_admission_request_rejects_malformed_evidence_fields() -> None:
    descriptor, certification, replay_proof, manifest, registry = backend_authority_parts(
        request_id="backend-admission-request-malformed"
    )

    with pytest.raises(ValueError, match="backend_certification"):
        BackendAdmissionRequest(
            backend_descriptor=descriptor,
            backend_certification={},
            backend_replay_proof=replay_proof,
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
        )
    with pytest.raises(ValueError, match="backend_replay_proof"):
        BackendAdmissionRequest(
            backend_descriptor=descriptor,
            backend_certification=certification,
            backend_replay_proof={},
            authority_manifest=manifest,
            registry_checksum=registry.registry_checksum,
        )
    with pytest.raises(ValueError, match="registry_checksum"):
        BackendAdmissionRequest(
            backend_descriptor=descriptor,
            backend_certification=certification,
            backend_replay_proof=replay_proof,
            authority_manifest=manifest,
            registry_checksum="bad-checksum",
        )


def test_backend_admission_decision_checksum_binds_all_fields() -> None:
    decision = admit_runtime_backend(backend_admission_request(request_id="backend-admission-hash"))

    changed = BackendAdmissionDecision(
        status="BLOCKED",
        reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
        backend_kind=decision.backend_kind,
        backend_descriptor_checksum=decision.backend_descriptor_checksum,
        certification_checksum=decision.certification_checksum,
        replay_proof_checksum=decision.replay_proof_checksum,
        authority_manifest_checksum=decision.authority_manifest_checksum,
        registry_checksum=decision.registry_checksum,
    )

    assert decision.decision_checksum == recompute_backend_admission_decision_checksum(decision)
    assert decision.decision_checksum != changed.decision_checksum


def test_backend_admission_decision_rejects_non_null_admitted_status() -> None:
    decision = admit_runtime_backend(
        backend_admission_request(request_id="backend-admission-admitted-contract")
    )

    with pytest.raises(ValueError, match="NULL_BACKEND_V1"):
        BackendAdmissionDecision(
            status="ADMITTED",
            reason_code=decision.reason_code,
            backend_kind="SIMULATOR_BACKEND_V1",
            backend_descriptor_checksum=decision.backend_descriptor_checksum,
            certification_checksum=decision.certification_checksum,
            replay_proof_checksum=decision.replay_proof_checksum,
            authority_manifest_checksum=decision.authority_manifest_checksum,
            registry_checksum=decision.registry_checksum,
        )


@pytest.mark.parametrize(
    ("field_name", "field_value", "match"),
    (
        ("status", "ALLOW", "status"),
        ("reason_code", "not_upper", "reason_code"),
        ("backend_kind", "not_upper", "backend_kind"),
        ("backend_descriptor_checksum", "bad", "backend_descriptor_checksum"),
        ("certification_checksum", object(), "certification_checksum"),
        ("decision_checksum", "0" * 64, "decision_checksum"),
    ),
)
def test_backend_admission_decision_rejects_malformed_fields(
    field_name: str,
    field_value: object,
    match: str,
) -> None:
    decision = admit_runtime_backend(
        backend_admission_request(request_id="backend-admission-decision-malformed")
    )
    values: dict[str, object] = {
        "status": "BLOCKED",
        "reason_code": "BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
        "backend_kind": decision.backend_kind,
        "backend_descriptor_checksum": decision.backend_descriptor_checksum,
        "certification_checksum": decision.certification_checksum,
        "replay_proof_checksum": decision.replay_proof_checksum,
        "authority_manifest_checksum": decision.authority_manifest_checksum,
        "registry_checksum": decision.registry_checksum,
        "decision_checksum": None,
    }
    values[field_name] = field_value

    with pytest.raises(ValueError, match=match):
        BackendAdmissionDecision(
            status=values["status"],
            reason_code=values["reason_code"],
            backend_kind=values["backend_kind"],
            backend_descriptor_checksum=values["backend_descriptor_checksum"],
            certification_checksum=values["certification_checksum"],
            replay_proof_checksum=values["replay_proof_checksum"],
            authority_manifest_checksum=values["authority_manifest_checksum"],
            registry_checksum=values["registry_checksum"],
            decision_checksum=values["decision_checksum"]
            if isinstance(values["decision_checksum"], str)
            else None,
        )
