"""Closed ADR-0023 operator authority field and category registries."""

from __future__ import annotations

OPERATOR_AUTHORITY_MANIFEST_CHECKSUM_FIELDS = (
    "authority_id",
    "authority_version",
    "allowed_operator_roles",
    "allowed_approval_scopes",
    "required_context_authority_checksum",
    "approval_epoch",
    "manifest_status",
)
"""OperatorAuthorityManifest fields bound by manifest_checksum."""

OPERATOR_IDENTITY_CLAIM_CHECKSUM_FIELDS = (
    "operator_id",
    "operator_role",
    "operator_authority_manifest_checksum",
    "context_authority_checksum",
    "identity_epoch",
)
"""OperatorIdentityClaim fields bound by identity_checksum."""

OPERATOR_APPROVAL_NONCE_CHECKSUM_FIELDS = (
    "nonce_id",
    "quarantine_checksum",
    "operator_identity_checksum",
    "approval_epoch",
)
"""OperatorApprovalNonce fields bound by nonce_checksum."""

AUTHORITY_BOUND_APPROVAL_CHECKSUM_FIELDS = (
    "approval_id",
    "approval_status",
    "quarantine_checksum",
    "operator_identity_checksum",
    "operator_authority_manifest_checksum",
    "approval_nonce_checksum",
    "approved_scope",
    "approval_epoch",
)
"""AuthorityBoundApprovalReceipt fields bound by authority_bound_checksum."""

APPROVAL_REPLAY_VALIDATION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "approval_checksum",
    "quarantine_checksum",
    "operator_identity_checksum",
    "authority_manifest_checksum",
    "nonce_checksum",
    "context_authority_checksum",
)
"""ApprovalReplayValidationResult fields bound by replay_validation_checksum."""

STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES = (
    "registered_operator_role_required",
    "authority_manifest_required",
    "structural_identity_only",
    "identity_bound_to_manifest",
    "identity_bound_to_context_authority",
    "approval_nonce_bound_to_quarantine",
    "approval_nonce_bound_to_identity",
    "approval_bound_to_nonce",
    "approval_bound_to_identity",
    "approval_bound_to_authority_manifest",
    "approval_bound_to_quarantine",
    "approval_bound_to_dispatch_plan",
    "approval_bound_to_capability_lease",
    "approval_bound_to_backend_admission",
    "approval_bound_to_registry",
    "approval_bound_to_certification",
    "approval_bound_to_backend_replay_proof",
    "approval_bound_to_context_authority",
    "approval_scope_explicit",
    "approval_scope_subset_bound",
    "no_wildcard_operator_roles",
    "no_wildcard_approval_scopes",
    "no_auth_provider_claim",
    "no_signatures_or_pki",
    "no_runtime_objects",
    "no_callable_handles",
    "no_filesystem_reads",
    "no_network_calls",
    "no_environment_reads",
    "no_ros_imports",
)
"""Profile properties required by ADR-0023 operator authority and anti-replay."""

OPERATOR_AUTHORITY_SCENARIO_CATEGORY_NAMES = (
    "OPERATOR_AUTHORITY_POSITIVE",
    "OPERATOR_AUTHORITY_UNKNOWN_ROLE",
    "OPERATOR_AUTHORITY_SCOPE_OVERCLAIM",
    "OPERATOR_AUTHORITY_MANIFEST_DRIFT",
    "OPERATOR_AUTHORITY_CONTEXT_DRIFT",
    "OPERATOR_AUTHORITY_NONCE_REPLAY",
    "OPERATOR_AUTHORITY_CROSS_QUARANTINE_REPLAY",
    "OPERATOR_AUTHORITY_CROSS_OPERATOR_REPLAY",
    "OPERATOR_AUTHORITY_EPOCH_REPLAY",
    "OPERATOR_AUTHORITY_OBJECT_INJECTION",
)
"""Scenario categories introduced by ADR-0023."""

__all__ = [
    "APPROVAL_REPLAY_VALIDATION_CHECKSUM_FIELDS",
    "AUTHORITY_BOUND_APPROVAL_CHECKSUM_FIELDS",
    "OPERATOR_APPROVAL_NONCE_CHECKSUM_FIELDS",
    "OPERATOR_AUTHORITY_MANIFEST_CHECKSUM_FIELDS",
    "OPERATOR_AUTHORITY_SCENARIO_CATEGORY_NAMES",
    "OPERATOR_IDENTITY_CLAIM_CHECKSUM_FIELDS",
    "STRICT_OPERATOR_AUTHORITY_V1_PROPERTIES",
]
