"""Closed ADR-0028 approval-ledger persistence field/category registries."""

from __future__ import annotations

APPROVAL_LEDGER_PERSISTENCE_RECORD_CHECKSUM_FIELDS = (
    "contract_version",
    "repository_id",
    "ledger_epoch",
    "head_checksum",
    "state_checksum",
    "sequence",
    "evaluation_time_ms",
    "state_source_id",
    "context_authority_checksum",
    "backend_admission_checksum",
    "release_decision_checksums",
    "canonical_json",
)
"""ApprovalLedgerPersistenceRecord fields bound by checksum."""

APPROVAL_LEDGER_PERSISTENCE_RECEIPT_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "contract_version",
    "repository_id",
    "ledger_epoch",
    "head_checksum",
    "state_checksum",
    "sequence",
    "evaluation_time_ms",
)
"""ApprovalLedgerPersistenceReceipt fields bound by checksum."""

APPROVAL_LEDGER_PERSISTENCE_LOAD_RESULT_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "contract_version",
    "repository_id",
    "ledger_epoch",
    "head_checksum",
    "state_checksum",
    "sequence",
    "evaluation_time_ms",
    "persisted_payload_json",
)
"""ApprovalLedgerPersistenceLoadResult fields bound by checksum."""

APPROVAL_LEDGER_PERSISTENCE_VALIDATION_RESULT_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "contract_version",
    "repository_id",
    "ledger_epoch",
    "head_checksum",
    "state_checksum",
    "sequence",
    "evaluation_time_ms",
)
"""ApprovalLedgerPersistenceValidationResult fields bound by checksum."""

APPROVAL_LEDGER_RECOVERY_RESULT_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "contract_version",
    "repository_id",
    "ledger_epoch",
    "head_checksum",
    "state_checksum",
    "sequence",
    "evaluation_time_ms",
    "recovered_snapshot",
    "recovered_head",
    "recovered_manifest",
    "recovered_entries",
)
"""ApprovalLedgerRecoveryResult fields bound by checksum."""

STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES = (
    "deterministic_serialization_boundary",
    "canonical_json_sorted_keys",
    "allow_nan_false",
    "checksum_bound_payload",
    "cross_repository_replay_rejected",
    "cross_epoch_replay_rejected",
    "sequence_rollback_rejected",
    "forked_head_rejected",
    "partial_write_detected",
    "unavailable_adapter_fail_closed",
    "runtime_object_injection_rejected",
    "read_after_write_consistent",
    "failed_write_does_not_mutate_repository_authority",
    "no_filesystem_persistence_claim",
    "no_database_clients",
    "no_network_calls",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0028 persistence boundary."""

APPROVAL_LEDGER_PERSISTENCE_SCENARIO_CATEGORY_NAMES = (
    "APPROVAL_LEDGER_PERSISTENCE_POSITIVE",
    "APPROVAL_LEDGER_PERSISTENCE_CORRUPT",
    "APPROVAL_LEDGER_PERSISTENCE_ROLLBACK",
    "APPROVAL_LEDGER_PERSISTENCE_FORKED",
    "APPROVAL_LEDGER_PERSISTENCE_CROSS_REPOSITORY_REPLAY",
    "APPROVAL_LEDGER_PERSISTENCE_CROSS_EPOCH_REPLAY",
    "APPROVAL_LEDGER_PERSISTENCE_PARTIAL_WRITE",
    "APPROVAL_LEDGER_PERSISTENCE_UNAVAILABLE",
)
"""Scenario categories introduced by ADR-0028."""

__all__ = [
    "APPROVAL_LEDGER_PERSISTENCE_LOAD_RESULT_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_PERSISTENCE_RECEIPT_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_PERSISTENCE_RECORD_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_PERSISTENCE_SCENARIO_CATEGORY_NAMES",
    "APPROVAL_LEDGER_PERSISTENCE_VALIDATION_RESULT_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_RECOVERY_RESULT_CHECKSUM_FIELDS",
    "STRICT_APPROVAL_LEDGER_PERSISTENCE_V1_PROPERTIES",
]
