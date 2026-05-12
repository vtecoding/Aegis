"""Closed ADR-0027 approval-ledger repository field/category registries."""

from __future__ import annotations

APPROVAL_LEDGER_REPOSITORY_AUTHORITY_EVIDENCE_CHECKSUM_FIELDS = (
    "ledger_head_checksum",
    "ledger_epoch_manifest_checksum",
    "state_source_id",
    "prior_entries_checksum",
)
"""ApprovalLedgerRepositoryAuthorityEvidence checksum-bound authority inputs."""

REPOSITORY_COMMIT_RESULT_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "expected_previous_snapshot_checksum",
    "previous_snapshot_checksum",
    "committed_snapshot_checksum",
    "committed_transition_checksum",
    "repository_epoch_manifest_checksum",
    "expected_previous_snapshot_matched",
    "transition_valid",
    "new_snapshot_became_current",
    "stale_write_rejected",
    "fork_rejected",
    "rollback_rejected",
    "cross_epoch_rejected",
)
"""RepositoryCommitResult fields bound by commit_result_checksum."""

STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES = (
    "repository_boundary_contract_only",
    "read_current_state_requires_epoch_manifest",
    "propose_append_requires_authority_evidence",
    "commit_requires_compare_and_swap_proof",
    "stale_write_rejected",
    "lost_update_rejected",
    "fork_rejected",
    "rollback_rejected",
    "cross_epoch_commit_rejected",
    "forged_transition_rejected",
    "unavailable_repository_blocks_commit",
    "new_snapshot_becomes_current_on_commit",
    "no_filesystem_persistence",
    "no_database_clients",
    "no_network_calls",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0027 repository contract."""

APPROVAL_LEDGER_REPOSITORY_SCENARIO_CATEGORY_NAMES = (
    "APPROVAL_LEDGER_REPOSITORY_POSITIVE",
    "APPROVAL_LEDGER_REPOSITORY_STALE_READ",
    "APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE",
    "APPROVAL_LEDGER_REPOSITORY_FORK_ATTEMPT",
    "APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ATTEMPT",
    "APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT",
    "APPROVAL_LEDGER_REPOSITORY_FORGED_TRANSITION",
    "APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE",
)
"""Scenario categories introduced by ADR-0027."""

__all__ = [
    "APPROVAL_LEDGER_REPOSITORY_AUTHORITY_EVIDENCE_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_REPOSITORY_SCENARIO_CATEGORY_NAMES",
    "REPOSITORY_COMMIT_RESULT_CHECKSUM_FIELDS",
    "STRICT_APPROVAL_LEDGER_REPOSITORY_V1_PROPERTIES",
]
