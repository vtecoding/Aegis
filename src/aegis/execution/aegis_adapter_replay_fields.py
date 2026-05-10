"""Closed ADR-0016 adapter replay field and category registries."""

from __future__ import annotations

ADAPTER_REPLAY_REQUEST_FIELDS = (
    "pipeline_result",
    "expected_envelope",
    "expected_adapter_receipt",
    "replay_profile",
    "mutation_profile",
)
"""Fields carried by AdapterReplayRequest."""

ADAPTER_REPLAY_PROOF_CHECKSUM_FIELDS = (
    "status",
    "reason",
    "source_pipeline_checksum",
    "expected_envelope_checksum",
    "replayed_envelope_checksum",
    "expected_receipt_checksum",
    "replayed_receipt_checksum",
    "mapping_checksum_match",
    "runtime_target_checksum_match",
    "qos_checksum_match",
    "namespace_match",
    "receipt_chain_match",
    "mutation_detected",
    "failure_stage",
)
"""AdapterReplayProofResult fields bound by proof_checksum."""

STRICT_ADAPTER_REPLAY_V1_PROPERTIES = (
    "deterministic_canonical_serialization",
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
"""Profile properties required by STRICT_ADAPTER_REPLAY_V1."""

ADAPTER_REPLAY_SCENARIO_CATEGORY_NAMES = (
    "ADAPTER_REPLAY_POSITIVE",
    "ADAPTER_REPLAY_RECEIPT_DRIFT",
    "ADAPTER_REPLAY_MAPPING_DRIFT",
    "ADAPTER_REPLAY_RUNTIME_TARGET_DRIFT",
    "ADAPTER_REPLAY_CROSS_PIPELINE_SWAP",
    "ADAPTER_REPLAY_AUTHORITY_MISMATCH",
    "ADAPTER_REPLAY_QOS_NAMESPACE_MUTATION",
    "ADAPTER_REPLAY_RESOURCE_BOUNDS",
)
"""Scenario categories introduced by ADR-0016."""

__all__ = [
    "ADAPTER_REPLAY_PROOF_CHECKSUM_FIELDS",
    "ADAPTER_REPLAY_REQUEST_FIELDS",
    "ADAPTER_REPLAY_SCENARIO_CATEGORY_NAMES",
    "STRICT_ADAPTER_REPLAY_V1_PROPERTIES",
]
