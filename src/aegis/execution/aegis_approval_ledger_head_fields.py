"""Closed ADR-0025 approval ledger head field and category registries."""

from __future__ import annotations

APPROVAL_LEDGER_HEAD_CHECKSUM_FIELDS = (
    "ledger_contract_version",
    "session_epoch",
    "latest_sequence_index",
    "latest_entry_checksum",
    "genesis_checksum",
    "context_authority_checksum",
)
"""ApprovalLedgerHead fields bound by head_checksum (excluding head_checksum itself)."""

LEDGER_EPOCH_MANIFEST_CHECKSUM_FIELDS = (
    "manifest_id",
    "session_epoch",
    "context_authority_checksum",
    "backend_admission_checksum",
)
"""LedgerEpochManifest fields bound by manifest_checksum (excluding manifest_checksum itself)."""

APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS = (
    "new_entry_checksum",
    "new_head_checksum",
    "chain_validation_checksum",
)
"""Logical fields bound by append_result_checksum (excluding append_result_checksum itself)."""

STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES = (
    "deterministic_genesis_head",
    "epoch_bound_head",
    "context_authority_bound_head",
    "tip_and_sequence_bound_head",
    "head_checksum_recomputable",
    "append_result_checksum_recomputable",
    "epoch_manifest_checksum_recomputable",
    "no_filesystem_persistence",
    "no_network_calls",
    "no_auth_provider",
    "no_signatures_or_pki",
    "no_runtime_objects_in_head",
    "no_callable_handles",
    "no_async",
    "no_ros_imports",
    "direct_head_construction_blocked",
    "direct_append_result_construction_blocked",
)
"""Profile properties required by ADR-0025 approval ledger head."""

APPROVAL_LEDGER_HEAD_SCENARIO_CATEGORY_NAMES = (
    "APPROVAL_LEDGER_HEAD_POSITIVE",
    "APPROVAL_LEDGER_HEAD_STALE_EPOCH",
    "APPROVAL_LEDGER_HEAD_CONTEXT_DRIFT",
    "APPROVAL_LEDGER_HEAD_TIP_MISMATCH",
    "APPROVAL_LEDGER_HEAD_ENFORCED_MODE_BYPASS",
)
"""Scenario categories introduced by ADR-0025."""

__all__ = [
    "APPROVAL_LEDGER_APPEND_RESULT_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_HEAD_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_HEAD_SCENARIO_CATEGORY_NAMES",
    "LEDGER_EPOCH_MANIFEST_CHECKSUM_FIELDS",
    "STRICT_APPROVAL_LEDGER_HEAD_V1_PROPERTIES",
]
