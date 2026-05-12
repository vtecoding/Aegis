"""Closed ADR-0026 approval ledger state field and category registries."""

from __future__ import annotations

APPROVAL_LEDGER_STATE_SNAPSHOT_CHECKSUM_FIELDS = (
    "contract_version",
    "ledger_epoch_manifest_checksum",
    "ledger_head_checksum",
    "latest_sequence_index",
    "latest_entry_checksum",
    "genesis_checksum",
    "context_authority_checksum",
    "backend_admission_checksum",
    "state_source_id",
)
"""ApprovalLedgerStateSnapshot fields bound by state_snapshot_checksum."""

APPROVAL_LEDGER_STATE_TRANSITION_CHECKSUM_FIELDS = (
    "contract_version",
    "previous_snapshot_checksum",
    "append_result_checksum",
    "new_snapshot_checksum",
    "previous_sequence_index",
    "new_sequence_index",
    "previous_entry_checksum",
    "new_entry_checksum",
    "ledger_epoch_manifest_checksum",
    "state_source_id",
)
"""ApprovalLedgerStateTransition fields bound by state_transition_checksum."""

LEDGER_STATE_VALIDATION_RESULT_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "state_snapshot_checksum",
    "ledger_head_checksum",
    "ledger_epoch_manifest_checksum",
)
"""LedgerStateValidationResult fields bound by validation_checksum."""

STRICT_APPROVAL_LEDGER_STATE_SNAPSHOT_V1_PROPERTIES = (
    "canonical_current_state_boundary",
    "state_snapshot_checksum_recomputable",
    "head_bound_state_snapshot",
    "epoch_manifest_bound_state_snapshot",
    "context_authority_bound_state_snapshot",
    "backend_admission_bound_state_snapshot",
    "state_source_id_required_and_bounded",
    "direct_snapshot_construction_blocked",
    "no_filesystem_persistence",
    "no_network_calls",
    "no_auth_provider",
    "no_signatures_or_pki",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0026 state snapshot contract."""

STRICT_APPROVAL_LEDGER_STATE_TRANSITION_V1_PROPERTIES = (
    "append_only_transition",
    "sequence_increment_exactly_one",
    "previous_tip_bound_transition",
    "new_tip_bound_transition",
    "append_result_bound_transition",
    "state_transition_checksum_recomputable",
    "direct_transition_construction_blocked",
    "no_rollback",
    "no_sequence_skip",
    "no_cross_epoch_graft",
    "no_state_source_drift",
    "no_filesystem_persistence",
    "no_network_calls",
    "no_auth_provider",
    "no_signatures_or_pki",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0026 state transition contract."""

STRICT_LEDGER_STATE_VALIDATION_RESULT_V1_PROPERTIES = (
    "valid_result_token_gated",
    "validation_checksum_recomputable",
    "snapshot_shape_validation",
    "head_binding_validation",
    "epoch_binding_validation",
    "context_authority_validation",
    "backend_admission_validation",
    "sequence_and_tip_validation",
    "state_source_validation",
    "no_filesystem_persistence",
    "no_network_calls",
    "no_auth_provider",
    "no_signatures_or_pki",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0026 state validation result contract."""

APPROVAL_LEDGER_STATE_SCENARIO_CATEGORY_NAMES = (
    "APPROVAL_LEDGER_STATE_VALID",
    "APPROVAL_LEDGER_STATE_STALE_HEAD",
    "APPROVAL_LEDGER_STATE_FORKED_HEAD",
    "APPROVAL_LEDGER_STATE_SEQUENCE_ROLLBACK",
    "APPROVAL_LEDGER_STATE_SEQUENCE_SKIP",
    "APPROVAL_LEDGER_STATE_CROSS_EPOCH_GRAFT",
    "APPROVAL_LEDGER_STATE_SOURCE_DRIFT",
)
"""Scenario categories introduced by ADR-0026."""

__all__ = [
    "APPROVAL_LEDGER_STATE_SCENARIO_CATEGORY_NAMES",
    "APPROVAL_LEDGER_STATE_SNAPSHOT_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_STATE_TRANSITION_CHECKSUM_FIELDS",
    "LEDGER_STATE_VALIDATION_RESULT_CHECKSUM_FIELDS",
    "STRICT_APPROVAL_LEDGER_STATE_SNAPSHOT_V1_PROPERTIES",
    "STRICT_APPROVAL_LEDGER_STATE_TRANSITION_V1_PROPERTIES",
    "STRICT_LEDGER_STATE_VALIDATION_RESULT_V1_PROPERTIES",
]
