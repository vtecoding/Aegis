"""Closed ADR-0017 runtime dispatch field and category registries."""

from __future__ import annotations

RUNTIME_DISPATCH_ITEM_FIELDS = (
    "sequence",
    "capability",
    "runtime_kind",
    "runtime_name",
    "namespace",
    "message_type",
    "qos_profile_checksum",
    "payload_checksum",
    "payload_size_bytes",
    "field_map_checksum",
)
"""Fields carried by RuntimeDispatchItem."""

RUNTIME_DISPATCH_PLAN_CHECKSUM_FIELDS = (
    "plan_id",
    "source_envelope_checksum",
    "source_replay_proof_checksum",
    "runtime_target_checksum",
    "mapping_checksum",
    "dispatch_mode",
    "dispatch_items",
    "resource_bounds",
)
"""RuntimeDispatchPlan fields bound by plan_checksum."""

DISPATCH_FIREWALL_DECISION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "plan_checksum",
    "source_replay_proof_checksum",
    "blocked_stage",
)
"""DispatchFirewallDecision fields bound by decision_checksum."""

RUNTIME_DISPATCH_RECEIPT_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "plan_checksum",
    "source_envelope_checksum",
    "source_replay_proof_checksum",
    "decision_checksum",
    "dispatch_mode",
)
"""RuntimeDispatchReceipt fields bound by dry_run_receipt_checksum."""

STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES = (
    "deterministic_canonical_serialization",
    "replay_proof_required",
    "exact_envelope_binding",
    "dry_run_only",
    "inert_data_only",
    "no_runtime_backend",
    "no_runtime_io",
    "no_clocks",
    "no_random_ids",
    "no_environment_reads",
    "no_filesystem_reads",
    "no_network_calls",
    "no_ros_imports",
    "no_async",
    "no_global_mutable_state",
)
"""Profile properties required by ADR-0017 runtime dispatch dry-run planning."""

RUNTIME_DISPATCH_SCENARIO_CATEGORY_NAMES = (
    "RUNTIME_DISPATCH_DRY_RUN_POSITIVE",
    "RUNTIME_DISPATCH_REPLAY_PROOF_REQUIRED",
    "RUNTIME_DISPATCH_CROSS_ENVELOPE_SWAP",
    "RUNTIME_DISPATCH_MAPPING_DRIFT",
    "RUNTIME_DISPATCH_PAYLOAD_BOUNDS",
    "RUNTIME_DISPATCH_SEQUENCE_INTEGRITY",
    "RUNTIME_DISPATCH_MODE_FIREWALL",
    "RUNTIME_DISPATCH_RUNTIME_OBJECT_INJECTION",
)
"""Scenario categories introduced by ADR-0017."""

__all__ = [
    "DISPATCH_FIREWALL_DECISION_CHECKSUM_FIELDS",
    "RUNTIME_DISPATCH_ITEM_FIELDS",
    "RUNTIME_DISPATCH_PLAN_CHECKSUM_FIELDS",
    "RUNTIME_DISPATCH_RECEIPT_CHECKSUM_FIELDS",
    "RUNTIME_DISPATCH_SCENARIO_CATEGORY_NAMES",
    "STRICT_RUNTIME_DISPATCH_DRY_RUN_V1_PROPERTIES",
]
