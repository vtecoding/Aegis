"""Closed ADR-0021 capability lease field and category registries."""

from __future__ import annotations

CAPABILITY_LEASE_CHECKSUM_FIELDS = (
    "lease_id",
    "backend_kind",
    "backend_descriptor_checksum",
    "admission_decision_checksum",
    "authority_manifest_checksum",
    "registry_checksum",
    "certification_checksum",
    "replay_proof_checksum",
    "dispatch_plan_checksum",
    "firewall_decision_checksum",
    "context_authority_checksum",
    "leased_capabilities",
    "leased_runtime_kinds",
    "lease_epoch",
    "lease_status",
)
"""RuntimeCapabilityLease fields bound by lease_checksum."""

LEASE_VALIDATION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "lease_checksum",
    "current_registry_checksum",
    "current_manifest_checksum",
    "current_context_authority_checksum",
    "scope_match",
    "evidence_chain_match",
)
"""LeaseValidationResult fields bound by validation_checksum."""

LEASE_REVOCATION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "lease_checksum",
    "revoked_evidence_checksum",
    "revocation_stage",
)
"""LeaseRevocationDecision fields bound by revocation_checksum."""

STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES = (
    "admitted_null_backend_required",
    "checksum_bound_descriptor",
    "checksum_bound_admission_decision",
    "checksum_bound_registry",
    "checksum_bound_manifest",
    "checksum_bound_certification",
    "checksum_bound_replay_proof",
    "checksum_bound_dispatch_plan",
    "checksum_bound_firewall_decision",
    "checksum_bound_context_authority",
    "explicit_epoch_required",
    "no_wall_clock_fallback",
    "scope_subset_bound",
    "no_wildcard_capabilities",
    "no_wildcard_runtime_kinds",
    "no_empty_scope",
    "no_runtime_objects",
    "no_callable_handles",
    "no_backend_clients",
    "no_filesystem_reads",
    "no_network_calls",
    "no_environment_reads",
    "no_ros_imports",
)
"""Profile properties required by ADR-0021 runtime capability leases."""

CAPABILITY_LEASE_SCENARIO_CATEGORY_NAMES = (
    "CAPABILITY_LEASE_NULL_POSITIVE",
    "CAPABILITY_LEASE_REQUIRES_ADMISSION",
    "CAPABILITY_LEASE_SCOPE_SUBSET",
    "CAPABILITY_LEASE_REGISTRY_DRIFT",
    "CAPABILITY_LEASE_MANIFEST_DRIFT",
    "CAPABILITY_LEASE_CERTIFICATION_DRIFT",
    "CAPABILITY_LEASE_REPLAY_DRIFT",
    "CAPABILITY_LEASE_CONTEXT_AUTHORITY_DRIFT",
    "CAPABILITY_LEASE_WILDCARD_SCOPE",
    "CAPABILITY_LEASE_REVOCATION",
)
"""Scenario categories introduced by ADR-0021."""

__all__ = [
    "CAPABILITY_LEASE_CHECKSUM_FIELDS",
    "CAPABILITY_LEASE_SCENARIO_CATEGORY_NAMES",
    "LEASE_REVOCATION_CHECKSUM_FIELDS",
    "LEASE_VALIDATION_CHECKSUM_FIELDS",
    "STRICT_RUNTIME_CAPABILITY_LEASE_V1_PROPERTIES",
]
