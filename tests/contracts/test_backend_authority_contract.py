"""Contract tests for ADR-0020 backend authority manifests."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import FrozenInstanceError

import pytest
from tests.backend_authority_fixtures import backend_authority_parts

from aegis.aegis_constants import RUNTIME_BACKEND_CONTRACT_VERSION
from aegis.contracts.aegis_backend_replay import BackendReplayProfile
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationStatus,
    RuntimeBackendKind,
    RuntimeBackendMode,
)
from aegis.contracts.aegis_runtime_dispatch import RuntimeDispatchKind
from aegis.execution.aegis_backend_authority import (
    BackendAuthorityAdmissionStatus,
    BackendAuthorityManifest,
    recompute_backend_authority_manifest_checksum,
)
from aegis.execution.aegis_backend_registry import (
    BackendAuthorityRegistry,
    recompute_backend_authority_registry_checksum,
)


def _authority_manifest(
    *,
    backend_kind: object = RuntimeBackendKind.NULL_BACKEND_V1,
    backend_version: object = RUNTIME_BACKEND_CONTRACT_VERSION,
    allowed_modes: Iterable[object] = (RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,),
    allowed_runtime_kinds: Iterable[object] = (RuntimeDispatchKind.TOPIC,),
    allowed_capabilities: Iterable[object] = ("locomotion.translation",),
    required_certification_profile: object = BackendCertificationStatus.CERTIFIED_NULL,
    required_replay_profile: object = BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
    allows_execution: object = False,
    allows_io: object = False,
    allows_async: object = False,
    admission_status: object = BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY,
    manifest_checksum: str | None = None,
) -> BackendAuthorityManifest:
    return BackendAuthorityManifest(
        backend_kind=backend_kind,
        backend_version=backend_version,
        allowed_modes=allowed_modes,
        allowed_runtime_kinds=allowed_runtime_kinds,
        allowed_capabilities=allowed_capabilities,
        required_certification_profile=required_certification_profile,
        required_replay_profile=required_replay_profile,
        allows_execution=allows_execution,
        allows_io=allows_io,
        allows_async=allows_async,
        admission_status=admission_status,
        manifest_checksum=manifest_checksum,
    )


def test_backend_authority_manifest_binds_null_backend_scope() -> None:
    descriptor, _, _, manifest, registry = backend_authority_parts(
        request_id="backend-authority-contract"
    )

    assert manifest.backend_kind is RuntimeBackendKind.NULL_BACKEND_V1
    assert manifest.backend_version == RUNTIME_BACKEND_CONTRACT_VERSION
    assert manifest.allowed_modes == frozenset({RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY})
    assert manifest.allowed_runtime_kinds == descriptor.supported_runtime_kinds
    assert manifest.allowed_capabilities == descriptor.supported_capabilities
    assert manifest.required_certification_profile is BackendCertificationStatus.CERTIFIED_NULL
    assert manifest.required_replay_profile is BackendReplayProfile.STRICT_BACKEND_REPLAY_V1
    assert manifest.allows_execution is False
    assert manifest.allows_io is False
    assert manifest.allows_async is False
    assert manifest.admission_status is BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY
    assert manifest.manifest_checksum == recompute_backend_authority_manifest_checksum(manifest)
    assert registry.registry_checksum == recompute_backend_authority_registry_checksum(registry)


def test_backend_authority_manifest_is_immutable() -> None:
    _, _, _, manifest, registry = backend_authority_parts(request_id="backend-authority-immutable")

    with pytest.raises(FrozenInstanceError):
        manifest.backend_version = "changed"
    with pytest.raises(FrozenInstanceError):
        registry.manifests = ()


def test_backend_authority_manifest_rejects_non_null_or_drifted_authority() -> None:
    with pytest.raises(ValueError, match="BACKEND_AUTHORITY_BACKEND_KIND_NOT_NULL"):
        BackendAuthorityManifest(
            backend_kind="SIMULATOR_BACKEND_V1",
            backend_version=RUNTIME_BACKEND_CONTRACT_VERSION,
            allowed_modes={RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY},
            allowed_runtime_kinds={RuntimeDispatchKind.TOPIC},
            allowed_capabilities={"locomotion.translation"},
            required_certification_profile=BackendCertificationStatus.CERTIFIED_NULL,
            required_replay_profile=BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
            allows_execution=False,
            allows_io=False,
            allows_async=False,
            admission_status=BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY,
        )
    with pytest.raises(ValueError, match="BACKEND_AUTHORITY_BACKEND_VERSION_DRIFT"):
        BackendAuthorityManifest(
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_version="runtime-backend-v2",
            allowed_modes={RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY},
            allowed_runtime_kinds={RuntimeDispatchKind.TOPIC},
            allowed_capabilities={"locomotion.translation"},
            required_certification_profile=BackendCertificationStatus.CERTIFIED_NULL,
            required_replay_profile=BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
            allows_execution=False,
            allows_io=False,
            allows_async=False,
            admission_status=BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY,
        )


def test_backend_authority_manifest_rejects_wildcards_and_callables() -> None:
    base = {
        "backend_kind": RuntimeBackendKind.NULL_BACKEND_V1,
        "backend_version": RUNTIME_BACKEND_CONTRACT_VERSION,
        "allowed_modes": {RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY},
        "allowed_runtime_kinds": {RuntimeDispatchKind.TOPIC},
        "allowed_capabilities": {"locomotion.translation"},
        "required_certification_profile": BackendCertificationStatus.CERTIFIED_NULL,
        "required_replay_profile": BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
        "allows_execution": False,
        "allows_io": False,
        "allows_async": False,
        "admission_status": BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY,
    }

    with pytest.raises(ValueError, match="BACKEND_AUTHORITY_WILDCARD_CAPABILITY"):
        BackendAuthorityManifest(**{**base, "allowed_capabilities": {"*"}})
    with pytest.raises(ValueError, match="BACKEND_AUTHORITY_WILDCARD_RUNTIME_KIND"):
        BackendAuthorityManifest(**{**base, "allowed_runtime_kinds": {"*"}})
    with pytest.raises(ValueError, match="allowed_capabilities"):
        BackendAuthorityManifest(**{**base, "allowed_capabilities": {lambda: "execute"}})
    with pytest.raises(ValueError, match="allowed_runtime_kinds"):
        BackendAuthorityManifest(**{**base, "allowed_runtime_kinds": {lambda: "topic"}})


def test_backend_authority_manifest_accepts_string_scope_values() -> None:
    manifest = _authority_manifest(
        allowed_modes=(RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY.value,),
        allowed_runtime_kinds=(RuntimeDispatchKind.TOPIC.value,),
        required_certification_profile=BackendCertificationStatus.CERTIFIED_NULL.value,
        required_replay_profile=BackendReplayProfile.STRICT_BACKEND_REPLAY_V1.value,
        admission_status=BackendAuthorityAdmissionStatus.ADMITTED_NULL_ONLY.value,
    )
    explicit_checksum = recompute_backend_authority_manifest_checksum(manifest)

    explicit = _authority_manifest(manifest_checksum=explicit_checksum)

    assert manifest.allowed_runtime_kinds == frozenset({RuntimeDispatchKind.TOPIC})
    assert explicit.manifest_checksum == explicit_checksum


@pytest.mark.parametrize(
    ("field_name", "field_value", "match"),
    (
        ("allowed_modes", "DRY_RUN_CERTIFICATION_ONLY", "allowed_modes"),
        ("allowed_modes", {"mutable": "mode"}, "allowed_modes"),
        ("allowed_modes", (lambda: None,), "allowed_modes"),
        ("allowed_modes", ("EXECUTE",), "allowed_modes"),
        ("allowed_modes", (object(),), "allowed_modes"),
        ("allowed_modes", (), "BACKEND_AUTHORITY_MODE_SCOPE_DRIFT"),
        ("allowed_runtime_kinds", "topic", "allowed_runtime_kinds"),
        ("allowed_runtime_kinds", {"mutable": "topic"}, "allowed_runtime_kinds"),
        ("allowed_runtime_kinds", ("publisher",), "allowed_runtime_kinds"),
        ("allowed_runtime_kinds", (object(),), "allowed_runtime_kinds"),
        ("allowed_runtime_kinds", (), "allowed_runtime_kinds"),
        ("allowed_capabilities", "locomotion.translation", "allowed_capabilities"),
        ("allowed_capabilities", {"mutable": "capability"}, "allowed_capabilities"),
        ("allowed_capabilities", (), "allowed_capabilities"),
        ("allowed_capabilities", ("Locomotion.Translation",), "allowed_capabilities"),
        ("required_certification_profile", "BLOCKED", "CERTIFICATION_PROFILE"),
        ("required_replay_profile", "RELAXED_REPLAY", "REPLAY_PROFILE"),
        ("allows_execution", True, "ALLOWS_EXECUTION"),
        ("allows_io", "false", "allows_io"),
        ("allows_async", True, "ALLOWS_ASYNC"),
        ("admission_status", "ADMITTED_REAL_BACKEND", "STATUS"),
        ("manifest_checksum", "0" * 64, "manifest_checksum"),
    ),
)
def test_backend_authority_manifest_rejects_malformed_fields(
    field_name: str,
    field_value: object,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        _authority_manifest(**{field_name: field_value})


@pytest.mark.parametrize(
    ("backend_version", "match"),
    (
        (lambda: "version", "backend_version"),
        (123, "backend_version"),
        ("", "backend_version"),
        (" runtime-backend-v1", "backend_version"),
        ("runtime backend v1", "backend_version"),
        ("runtime-backend-v1-\u2603", "backend_version"),
    ),
)
def test_backend_authority_manifest_rejects_malformed_text(
    backend_version: object,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        _authority_manifest(backend_version=backend_version)


def test_backend_authority_registry_rejects_mutable_or_duplicate_manifest_sets() -> None:
    _, _, _, manifest, _ = backend_authority_parts(request_id="backend-authority-registry")

    with pytest.raises(ValueError, match="manifests"):
        BackendAuthorityRegistry(manifests={"mutable": manifest})
    with pytest.raises(ValueError, match="DUPLICATE"):
        BackendAuthorityRegistry(manifests=(manifest, manifest))


def test_backend_authority_registry_lookup_and_checksum_validation() -> None:
    _, _, _, manifest, registry = backend_authority_parts(
        request_id="backend-authority-registry-lookup"
    )
    explicit = BackendAuthorityRegistry(
        manifests=(manifest,), registry_checksum=registry.registry_checksum
    )

    assert explicit.manifest_for(RuntimeBackendKind.NULL_BACKEND_V1) == manifest
    assert explicit.manifest_for("UNDECLARED_BACKEND_V1") is None
    with pytest.raises(ValueError, match="registry_checksum"):
        BackendAuthorityRegistry(manifests=(manifest,), registry_checksum="0" * 64)
    with pytest.raises(ValueError, match="manifests"):
        BackendAuthorityRegistry(manifests=())
    with pytest.raises(ValueError, match="manifests"):
        BackendAuthorityRegistry(manifests=(object(),))
    with pytest.raises(ValueError, match="registry_checksum"):
        BackendAuthorityRegistry(manifests=(manifest,), registry_checksum=object())


def test_backend_authority_registry_rejects_drifted_manifest() -> None:
    _, _, _, manifest, _ = backend_authority_parts(request_id="backend-authority-registry-drift")
    object.__setattr__(manifest, "manifest_checksum", "0" * 64)

    with pytest.raises(ValueError, match="MANIFEST_CHECKSUM_DRIFT"):
        BackendAuthorityRegistry(manifests=(manifest,))
