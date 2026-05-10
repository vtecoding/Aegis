"""Closed ADR-0020 backend authority field and category registries."""

from __future__ import annotations

BACKEND_AUTHORITY_MANIFEST_CHECKSUM_FIELDS = (
    "backend_kind",
    "backend_version",
    "allowed_modes",
    "allowed_runtime_kinds",
    "allowed_capabilities",
    "required_certification_profile",
    "required_replay_profile",
    "allows_execution",
    "allows_io",
    "allows_async",
    "admission_status",
)
"""BackendAuthorityManifest fields bound by manifest_checksum."""

BACKEND_AUTHORITY_REGISTRY_CHECKSUM_FIELDS = ("manifests",)
"""BackendAuthorityRegistry fields bound by registry_checksum."""

BACKEND_ADMISSION_REQUEST_FIELDS = (
    "backend_descriptor",
    "backend_certification",
    "backend_replay_proof",
    "authority_manifest",
    "registry_checksum",
)
"""Fields carried by BackendAdmissionRequest."""

BACKEND_ADMISSION_DECISION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "backend_kind",
    "backend_descriptor_checksum",
    "certification_checksum",
    "replay_proof_checksum",
    "authority_manifest_checksum",
    "registry_checksum",
)
"""BackendAdmissionDecision fields bound by decision_checksum."""

STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES = (
    "closed_backend_kind_registry",
    "null_backend_only",
    "adr_0018_certification_required",
    "adr_0019_replay_required",
    "checksum_bound_manifest",
    "checksum_bound_registry",
    "checksum_bound_decision",
    "no_execution_capability",
    "no_io_capability",
    "no_async_capability",
    "no_wildcard_capabilities",
    "no_wildcard_runtime_kinds",
    "no_runtime_objects",
    "no_callable_handles",
    "no_backend_clients",
    "no_filesystem_reads",
    "no_network_calls",
    "no_environment_reads",
    "no_ros_imports",
)
"""Profile properties required by ADR-0020 backend authority admission."""

BACKEND_AUTHORITY_SCENARIO_CATEGORY_NAMES = (
    "BACKEND_ADMISSION_NULL_POSITIVE",
    "BACKEND_ADMISSION_UNKNOWN_KIND",
    "BACKEND_ADMISSION_NON_NULL_KIND",
    "BACKEND_ADMISSION_MANIFEST_DRIFT",
    "BACKEND_ADMISSION_REGISTRY_DRIFT",
    "BACKEND_ADMISSION_MISSING_CERTIFICATION",
    "BACKEND_ADMISSION_MISSING_REPLAY",
    "BACKEND_ADMISSION_SCOPE_OVERCLAIM",
    "BACKEND_ADMISSION_WILDCARD_AUTHORITY",
    "BACKEND_ADMISSION_RUNTIME_OBJECT_INJECTION",
)
"""Scenario categories introduced by ADR-0020."""


__all__ = [
    "BACKEND_ADMISSION_DECISION_CHECKSUM_FIELDS",
    "BACKEND_ADMISSION_REQUEST_FIELDS",
    "BACKEND_AUTHORITY_MANIFEST_CHECKSUM_FIELDS",
    "BACKEND_AUTHORITY_REGISTRY_CHECKSUM_FIELDS",
    "BACKEND_AUTHORITY_SCENARIO_CATEGORY_NAMES",
    "STRICT_BACKEND_AUTHORITY_ADMISSION_V1_PROPERTIES",
]
