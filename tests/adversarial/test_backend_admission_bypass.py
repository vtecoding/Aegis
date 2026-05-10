"""Bypass tests for ADR-0020 backend admission."""

from __future__ import annotations

import pytest
from tests.backend_authority_fixtures import backend_admission_request, backend_authority_parts

from aegis.contracts.backend_replay import (
    BackendReplayProofResult,
    recompute_backend_replay_proof_checksum,
)
from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    recompute_backend_certification_checksum,
)
from aegis.contracts.runtime_dispatch import RuntimeDispatchKind
from aegis.execution.backend_admission import admit_runtime_backend
from aegis.execution.backend_authority import recompute_backend_authority_manifest_checksum
from aegis.execution.backend_registry import backend_authority_registry_checksum


def test_scope_overclaim_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-scope-overclaim")
    object.__setattr__(
        request.backend_descriptor,
        "supported_capabilities",
        request.backend_descriptor.supported_capabilities.union({"locomotion.stop"}),
    )

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_CAPABILITY_SCOPE_OVERCLAIM"


def test_runtime_kind_overclaim_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-runtime-overclaim")
    object.__setattr__(
        request.backend_descriptor,
        "supported_runtime_kinds",
        request.backend_descriptor.supported_runtime_kinds.union({RuntimeDispatchKind.SERVICE}),
    )

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_RUNTIME_KIND_SCOPE_OVERCLAIM"


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    (
        ("allows_execution", "BACKEND_ADMISSION_EXECUTION_CAPABILITY_CLAIMED"),
        ("allows_io", "BACKEND_ADMISSION_IO_CAPABILITY_CLAIMED"),
        ("allows_async", "BACKEND_ADMISSION_ASYNC_CAPABILITY_CLAIMED"),
    ),
)
def test_execution_io_or_async_overclaim_blocks(field_name: str, reason_code: str) -> None:
    request = backend_admission_request(request_id=f"backend-admission-{field_name}")
    object.__setattr__(request.backend_descriptor, field_name, True)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "field_value", "reason_code"),
    (
        ("allowed_capabilities", frozenset({"*"}), "BACKEND_ADMISSION_WILDCARD_CAPABILITY"),
        ("allowed_runtime_kinds", frozenset({"*"}), "BACKEND_ADMISSION_WILDCARD_RUNTIME_KIND"),
    ),
)
def test_wildcard_authority_blocks(field_name: str, field_value: object, reason_code: str) -> None:
    request = backend_admission_request(request_id=f"backend-admission-{field_name}")
    object.__setattr__(request.authority_manifest, field_name, field_value)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


def test_certification_not_certified_null_blocks() -> None:
    descriptor, certification, _, manifest, registry = backend_authority_parts(
        request_id="backend-admission-bad-certification"
    )
    blocked_certification = BackendCertificationResult(
        status=BackendCertificationStatus.BLOCKED,
        reason_code=BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED.value,
        dispatch_plan_checksum=certification.dispatch_plan_checksum,
        firewall_decision_checksum=certification.firewall_decision_checksum,
        backend_descriptor_checksum=certification.backend_descriptor_checksum,
        no_execution_guarantee=True,
        no_io_guarantee=False,
        no_async_guarantee=True,
        capability_scope_match=True,
        runtime_kind_scope_match=True,
    )
    request = backend_admission_request(request_id="backend-admission-bad-certification")
    object.__setattr__(request, "backend_descriptor", descriptor)
    object.__setattr__(request, "backend_certification", blocked_certification)
    object.__setattr__(request, "authority_manifest", manifest)
    object.__setattr__(request, "registry_checksum", registry.registry_checksum)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL"


def test_replay_proof_not_passed_blocks() -> None:
    request = backend_admission_request(request_id="backend-admission-replay-failed")
    failed_proof = BackendReplayProofResult(
        status="FAILED",
        reason_code="BACKEND_REPLAY_RECEIPT_MISMATCH",
        dispatch_plan_checksum=request.backend_replay_proof.dispatch_plan_checksum,
        firewall_decision_checksum=request.backend_replay_proof.firewall_decision_checksum,
        backend_descriptor_checksum=request.backend_replay_proof.backend_descriptor_checksum,
        expected_certification_checksum=request.backend_replay_proof.expected_certification_checksum,
        replayed_certification_checksum=request.backend_replay_proof.replayed_certification_checksum,
        expected_receipt_checksum=request.backend_replay_proof.expected_receipt_checksum,
        replayed_receipt_checksum="1" * 64,
        zero_execution_verified=True,
        scope_match_verified=True,
        certification_match=True,
        receipt_match=False,
        mutation_detected=True,
        failure_stage="receipt",
    )
    object.__setattr__(request, "backend_replay_proof", failed_proof)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == "BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED"


@pytest.mark.parametrize(
    ("field_name", "field_value", "reason_code"),
    (
        ("backend_version", "runtime-backend-v2", "BACKEND_ADMISSION_BACKEND_VERSION_DRIFT"),
        ("allowed_modes", frozenset(), "BACKEND_ADMISSION_DESCRIPTOR_MANIFEST_MISMATCH"),
        ("allows_execution", True, "BACKEND_ADMISSION_EXECUTION_CAPABILITY_CLAIMED"),
        (
            "required_certification_profile",
            "BLOCKED",
            "BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH",
        ),
        (
            "required_replay_profile",
            "RELAXED_REPLAY",
            "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH",
        ),
    ),
)
def test_manifest_mutation_blocks(
    field_name: str,
    field_value: object,
    reason_code: str,
) -> None:
    request = backend_admission_request(request_id=f"backend-admission-{field_name}")
    object.__setattr__(request.authority_manifest, field_name, field_value)
    if field_name in {"required_certification_profile", "required_replay_profile"}:
        object.__setattr__(
            request.authority_manifest,
            "manifest_checksum",
            recompute_backend_authority_manifest_checksum(request.authority_manifest),
        )
        object.__setattr__(
            request,
            "registry_checksum",
            backend_authority_registry_checksum((request.authority_manifest,)),
        )

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "field_value", "reason_code"),
    (
        ("backend_mode", "EXECUTE", "BACKEND_ADMISSION_DESCRIPTOR_MANIFEST_MISMATCH"),
        ("descriptor_checksum", "0" * 64, "BACKEND_ADMISSION_DESCRIPTOR_CHECKSUM_DRIFT"),
        (
            "supported_capabilities",
            ["locomotion.translation"],
            "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION",
        ),
        (
            "supported_runtime_kinds",
            [RuntimeDispatchKind.TOPIC],
            "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION",
        ),
    ),
)
def test_descriptor_mutation_blocks(
    field_name: str,
    field_value: object,
    reason_code: str,
) -> None:
    request = backend_admission_request(request_id=f"backend-admission-descriptor-{field_name}")
    object.__setattr__(request.backend_descriptor, field_name, field_value)

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "field_value", "reason_code"),
    (
        ("certification_checksum", "0" * 64, "BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH"),
        (
            "backend_descriptor_checksum",
            "1" * 64,
            "BACKEND_ADMISSION_CERTIFICATION_MANIFEST_MISMATCH",
        ),
        ("no_execution_guarantee", False, "BACKEND_ADMISSION_CERTIFICATION_NOT_CERTIFIED_NULL"),
    ),
)
def test_certification_mutation_blocks(
    field_name: str,
    field_value: object,
    reason_code: str,
) -> None:
    request = backend_admission_request(request_id=f"backend-admission-cert-{field_name}")
    object.__setattr__(request.backend_certification, field_name, field_value)
    if field_name == "no_execution_guarantee":
        object.__setattr__(
            request.backend_certification,
            "certification_checksum",
            recompute_backend_certification_checksum(request.backend_certification),
        )

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "field_value", "reason_code"),
    (
        ("proof_checksum", "0" * 64, "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH"),
        ("backend_descriptor_checksum", "1" * 64, "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH"),
        (
            "expected_certification_checksum",
            "1" * 64,
            "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH",
        ),
        (
            "replayed_certification_checksum",
            "1" * 64,
            "BACKEND_ADMISSION_REPLAY_MANIFEST_MISMATCH",
        ),
        ("zero_execution_verified", False, "BACKEND_ADMISSION_REPLAY_PROOF_NOT_PASSED"),
    ),
)
def test_replay_proof_mutation_blocks(
    field_name: str,
    field_value: object,
    reason_code: str,
) -> None:
    request = backend_admission_request(request_id=f"backend-admission-replay-{field_name}")
    object.__setattr__(request.backend_replay_proof, field_name, field_value)
    if field_name == "zero_execution_verified":
        object.__setattr__(
            request.backend_replay_proof,
            "proof_checksum",
            recompute_backend_replay_proof_checksum(request.backend_replay_proof),
        )

    decision = admit_runtime_backend(request)

    assert decision.status == "BLOCKED"
    assert decision.reason_code == reason_code


def test_admission_decision_is_deterministic() -> None:
    request = backend_admission_request(request_id="backend-admission-deterministic")

    first = admit_runtime_backend(request)
    second = admit_runtime_backend(request)

    assert first == second
    assert first.decision_checksum == second.decision_checksum
