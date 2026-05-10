"""Closed ADR-0018 backend certification field and category registries."""

from __future__ import annotations

RUNTIME_BACKEND_DESCRIPTOR_CHECKSUM_FIELDS = (
    "backend_id",
    "backend_kind",
    "backend_mode",
    "supported_runtime_kinds",
    "supported_capabilities",
    "allows_execution",
    "allows_io",
    "allows_async",
)
"""RuntimeBackendDescriptor fields bound by descriptor_checksum."""

BACKEND_CERTIFICATION_CHECKSUM_FIELDS = (
    "status",
    "reason_code",
    "dispatch_plan_checksum",
    "firewall_decision_checksum",
    "backend_descriptor_checksum",
    "no_execution_guarantee",
    "no_io_guarantee",
    "no_async_guarantee",
    "capability_scope_match",
    "runtime_kind_scope_match",
)
"""BackendCertificationResult fields bound by certification_checksum."""

BACKEND_DRY_RUN_RECEIPT_CHECKSUM_FIELDS = (
    "receipt_id",
    "dispatch_plan_checksum",
    "firewall_decision_checksum",
    "backend_certification_checksum",
    "backend_descriptor_checksum",
    "observed_dispatch_items",
    "executed_count",
    "blocked_execution_count",
)
"""BackendDryRunReceipt fields bound by receipt_checksum."""

STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES = (
    "firewall_allowed_plan_required",
    "dry_run_only",
    "null_backend_only",
    "descriptor_only_interface",
    "no_execution_capability",
    "no_io_capability",
    "no_async_capability",
    "no_callable_handles",
    "no_runtime_objects",
    "no_runtime_backend_clients",
    "no_environment_reads",
    "no_filesystem_reads",
    "no_network_calls",
    "no_ros_imports",
    "checksum_bound_certification",
    "zero_executed_receipts",
)
"""Profile properties required by ADR-0018 null backend certification."""

BACKEND_CERTIFICATION_SCENARIO_CATEGORY_NAMES = (
    "BACKEND_NULL_POSITIVE",
    "BACKEND_REQUIRES_FIREWALL_ALLOWED_PLAN",
    "BACKEND_REJECTS_NON_NULL_KIND",
    "BACKEND_REJECTS_EXECUTION_CAPABILITY",
    "BACKEND_REJECTS_IO_CAPABILITY",
    "BACKEND_REJECTS_ASYNC_CAPABILITY",
    "BACKEND_REJECTS_RUNTIME_OBJECT_INJECTION",
    "BACKEND_REJECTS_SCOPE_DRIFT",
    "BACKEND_RECEIPT_ZERO_EXECUTION",
    "BACKEND_CERTIFICATION_CHECKSUM_DRIFT",
)
"""Scenario categories introduced by ADR-0018."""

__all__ = [
    "BACKEND_CERTIFICATION_CHECKSUM_FIELDS",
    "BACKEND_CERTIFICATION_SCENARIO_CATEGORY_NAMES",
    "BACKEND_DRY_RUN_RECEIPT_CHECKSUM_FIELDS",
    "RUNTIME_BACKEND_DESCRIPTOR_CHECKSUM_FIELDS",
    "STRICT_RUNTIME_BACKEND_NULL_V1_PROPERTIES",
]
