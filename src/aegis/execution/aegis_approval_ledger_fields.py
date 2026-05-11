"""Closed ADR-0024 approval ledger field and category registries."""

from __future__ import annotations

APPROVAL_LEDGER_ENTRY_CHECKSUM_FIELDS = (
    "sequence_index",
    "prior_entry_checksum",
    "release_decision_checksum",
)
"""ApprovalLedgerEntry fields bound by entry_checksum."""

APPROVAL_LEDGER_CHAIN_VALIDATION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "chain_depth",
    "chain_tip_checksum",
)
"""ApprovalLedgerChainValidationResult fields bound by ledger_validation_checksum."""

STRICT_APPROVAL_LEDGER_V1_PROPERTIES = (
    "deterministic_genesis_head",
    "hash_linked_sequence",
    "release_decision_checksum_binding",
    "entry_checksum_recomputable",
    "no_filesystem_persistence",
    "no_network_calls",
    "no_auth_provider",
    "no_signatures_or_pki",
    "no_runtime_objects_in_chain",
    "no_callable_handles",
    "no_async",
    "no_ros_imports",
)
"""Profile properties required by ADR-0024 approval ledger."""

APPROVAL_LEDGER_SCENARIO_CATEGORY_NAMES = (
    "APPROVAL_LEDGER_POSITIVE",
    "APPROVAL_LEDGER_CHAIN_TAMPER",
    "APPROVAL_LEDGER_RUNTIME_OBJECT_INJECTION",
)
"""Scenario categories introduced by ADR-0024."""

__all__ = [
    "APPROVAL_LEDGER_CHAIN_VALIDATION_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_ENTRY_CHECKSUM_FIELDS",
    "APPROVAL_LEDGER_SCENARIO_CATEGORY_NAMES",
    "STRICT_APPROVAL_LEDGER_V1_PROPERTIES",
]
