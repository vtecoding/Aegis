"""Closed ADR-0022 quarantine field and category registries."""

from __future__ import annotations

COMMAND_QUARANTINE_CHECKSUM_FIELDS = (
    "quarantine_id",
    "dispatch_plan_checksum",
    "backend_admission_checksum",
    "capability_lease_checksum",
    "backend_descriptor_checksum",
    "authority_manifest_checksum",
    "registry_checksum",
    "certification_checksum",
    "backend_replay_proof_checksum",
    "context_authority_checksum",
    "quarantined_items",
    "quarantine_status",
    "quarantine_epoch",
)
"""CommandQuarantineEnvelope fields bound by quarantine_checksum."""

OPERATOR_APPROVAL_CHECKSUM_FIELDS = (
    "approval_id",
    "operator_id",
    "approval_status",
    "quarantine_checksum",
    "approved_scope",
    "approval_epoch",
    "approval_reason",
)
"""OperatorApprovalReceipt fields bound by approval_checksum."""

QUARANTINE_RELEASE_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "quarantine_checksum",
    "approval_checksum",
    "lease_checksum",
    "dispatch_plan_checksum",
    "released_item_count",
)
"""QuarantineReleaseDecision fields bound by decision_checksum."""

STRICT_COMMAND_QUARANTINE_V1_PROPERTIES = (
    "lease_valid_dispatch_enters_quarantine",
    "all_dispatch_items_quarantined",
    "no_partial_silent_omission",
    "approval_required_for_release",
    "approval_scope_explicit",
    "approval_scope_subset_bound",
    "approval_scope_exact_for_release",
    "approval_bound_to_quarantine_checksum",
    "release_bound_to_backend_admission",
    "release_bound_to_backend_descriptor",
    "release_bound_to_authority_manifest",
    "release_bound_to_registry",
    "release_bound_to_certification",
    "release_bound_to_backend_replay_proof",
    "release_bound_to_context_authority",
    "release_bound_to_capability_lease",
    "stale_approval_blocks",
    "rejected_approval_blocks",
    "no_runtime_objects",
    "no_callable_handles",
    "no_backend_calls",
    "no_queueing",
    "no_filesystem_reads",
    "no_network_calls",
    "no_environment_reads",
    "no_ros_imports",
)
"""Profile properties required by ADR-0022 command quarantine."""

COMMAND_QUARANTINE_SCENARIO_CATEGORY_NAMES = (
    "COMMAND_QUARANTINE_POSITIVE",
    "COMMAND_QUARANTINE_REQUIRES_VALID_LEASE",
    "COMMAND_QUARANTINE_MISSING_APPROVAL",
    "COMMAND_QUARANTINE_REJECTED_APPROVAL",
    "COMMAND_QUARANTINE_SCOPE_OVERCLAIM",
    "COMMAND_QUARANTINE_EVIDENCE_DRIFT",
    "COMMAND_QUARANTINE_STALE_APPROVAL",
    "COMMAND_QUARANTINE_PARTIAL_OMISSION",
    "COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION",
    "COMMAND_QUARANTINE_RELEASE_DRY_RUN_ONLY",
)
"""Scenario categories introduced by ADR-0022."""

__all__ = [
    "COMMAND_QUARANTINE_CHECKSUM_FIELDS",
    "COMMAND_QUARANTINE_SCENARIO_CATEGORY_NAMES",
    "OPERATOR_APPROVAL_CHECKSUM_FIELDS",
    "QUARANTINE_RELEASE_CHECKSUM_FIELDS",
    "STRICT_COMMAND_QUARANTINE_V1_PROPERTIES",
]
