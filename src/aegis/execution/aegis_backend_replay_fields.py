"""Closed ADR-0019 backend replay field and category registries."""

from __future__ import annotations

BACKEND_REPLAY_REQUEST_FIELDS = (
    "dispatch_plan",
    "firewall_decision",
    "backend_descriptor",
    "expected_certification",
    "expected_receipt",
    "replay_profile",
    "mutation_profile",
)
"""Fields carried by BackendReplayRequest."""

BACKEND_REPLAY_PROOF_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "dispatch_plan_checksum",
    "firewall_decision_checksum",
    "backend_descriptor_checksum",
    "expected_certification_checksum",
    "replayed_certification_checksum",
    "expected_receipt_checksum",
    "replayed_receipt_checksum",
    "zero_execution_verified",
    "scope_match_verified",
    "certification_match",
    "receipt_match",
    "mutation_detected",
    "failure_stage",
)
"""BackendReplayProofResult fields bound by proof_checksum."""

STRICT_BACKEND_REPLAY_V1_PROPERTIES = (
    "deterministic_canonical_serialization",
    "no_io",
    "no_clocks",
    "no_randomness",
    "no_async",
    "no_filesystem_reads",
    "no_network_calls",
    "no_environment_reads",
    "no_ros_imports",
    "no_runtime_imports",
    "no_simulator_hooks",
    "no_hardware_hooks",
    "no_global_mutable_state",
    "reuse_backend_certification_builder",
    "reuse_backend_receipt_builder",
    "zero_execution_required",
)
"""Profile properties required by STRICT_BACKEND_REPLAY_V1."""

BACKEND_REPLAY_SCENARIO_CATEGORY_NAMES = (
    "BACKEND_REPLAY_POSITIVE",
    "BACKEND_REPLAY_REQUIRES_CERTIFIED_NULL",
    "BACKEND_REPLAY_DISPATCH_DRIFT",
    "BACKEND_REPLAY_FIREWALL_DRIFT",
    "BACKEND_REPLAY_DESCRIPTOR_DRIFT",
    "BACKEND_REPLAY_SCOPE_DRIFT",
    "BACKEND_REPLAY_RECEIPT_EXECUTION_DRIFT",
    "BACKEND_REPLAY_CROSS_PLAN_SWAP",
    "BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION",
    "BACKEND_REPLAY_CHECKSUM_DRIFT",
)
"""Scenario categories introduced by ADR-0019."""

__all__ = [
    "BACKEND_REPLAY_PROOF_CHECKSUM_FIELDS",
    "BACKEND_REPLAY_REQUEST_FIELDS",
    "BACKEND_REPLAY_SCENARIO_CATEGORY_NAMES",
    "STRICT_BACKEND_REPLAY_V1_PROPERTIES",
]
