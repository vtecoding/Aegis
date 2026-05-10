"""Runtime object injection tests for ADR-0020 backend authority admission."""

from __future__ import annotations

import pytest
from tests.backend_authority_fixtures import backend_admission_request, backend_authority_parts

from aegis.execution.backend_admission import BackendAdmissionRequest, admit_runtime_backend


class _InjectedBackendClient:
    def __init__(self, descriptor: object) -> None:
        self.descriptor = descriptor
        self.client_handle = _injected_callable


def _injected_callable() -> None:
    return None


@pytest.mark.parametrize(
    "injected_value",
    (_injected_callable, [_injected_callable], _InjectedBackendClient),
)
def test_backend_descriptor_runtime_object_injection_blocks(injected_value: object) -> None:
    request = backend_admission_request(request_id="backend-admission-descriptor-injection")
    replacement = (
        injected_value(request.backend_descriptor)
        if injected_value is _InjectedBackendClient
        else injected_value
    )
    object.__setattr__(request, "backend_descriptor", replacement)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION"


@pytest.mark.parametrize("injected_value", ({"manifest": "mutable"}, [_injected_callable]))
def test_authority_manifest_mutable_injection_blocks(injected_value: object) -> None:
    request = backend_admission_request(request_id="backend-admission-manifest-injection")
    object.__setattr__(request, "authority_manifest", injected_value)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_MUTABLE_MANIFEST_INJECTION"


def test_backend_admission_request_constructor_rejects_runtime_objects() -> None:
    descriptor, certification, replay_proof, manifest, registry = backend_authority_parts(
        request_id="backend-admission-constructor-injection"
    )

    with pytest.raises(ValueError, match="backend_descriptor"):
        BackendAdmissionRequest(
            backend_descriptor=_InjectedBackendClient(descriptor),
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
            authority_manifest=_injected_callable,
            registry_checksum=registry.registry_checksum,
        )
