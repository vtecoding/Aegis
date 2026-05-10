"""Fail-closed runtime backend certification for ADR-0018."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import cast

from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.aegis_runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchMode,
    RuntimeDispatchPlan,
    recompute_dispatch_firewall_decision_checksum,
    recompute_runtime_dispatch_plan_checksum,
)
from aegis.execution.aegis_null_runtime_backend import NullRuntimeBackend
from aegis.execution.aegis_runtime_backend import (
    dispatch_plan_capability_scope,
    dispatch_plan_runtime_kind_scope,
)

_FALLBACK_CHECKSUM = "0" * 64
_FORBIDDEN_BACKEND_ATTRIBUTE_TOKENS = (
    "async",
    "call",
    "client",
    "dds",
    "env",
    "execute",
    "file",
    "gazebo",
    "hardware",
    "isaac",
    "moveit",
    "network",
    "node",
    "publish",
    "rclcpp",
    "rclpy",
    "ros",
    "send",
    "service",
    "socket",
    "subscriber",
    "viam",
)


def certify_runtime_backend(
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    backend: object,
) -> BackendCertificationResult:
    """Certify that a backend can only observe a firewall-allowed dry-run plan."""
    descriptor = _backend_descriptor(backend)
    capability_scope_match = _capability_scope_matches(plan, descriptor)
    runtime_kind_scope_match = _runtime_kind_scope_matches(plan, descriptor)
    no_execution_guarantee = _no_execution_guarantee(backend, descriptor)
    no_io_guarantee = descriptor is not None and descriptor.allows_io is False
    no_async_guarantee = descriptor is not None and descriptor.allows_async is False
    reason = _first_block_reason(
        plan=plan,
        decision=decision,
        backend=backend,
        descriptor=descriptor,
        capability_scope_match=capability_scope_match,
        runtime_kind_scope_match=runtime_kind_scope_match,
        no_execution_guarantee=no_execution_guarantee,
        no_io_guarantee=no_io_guarantee,
        no_async_guarantee=no_async_guarantee,
    )
    status = (
        BackendCertificationStatus.BLOCKED
        if reason is not None
        else BackendCertificationStatus.CERTIFIED_NULL
    )
    reason_code = reason or BackendCertificationReason.BACKEND_CERTIFIED_NULL
    return BackendCertificationResult(
        status=status,
        reason_code=reason_code.value,
        dispatch_plan_checksum=_valid_or_fallback_checksum(plan.plan_checksum),
        firewall_decision_checksum=_valid_or_fallback_checksum(decision.decision_checksum),
        backend_descriptor_checksum=_descriptor_checksum_or_fallback(descriptor),
        no_execution_guarantee=no_execution_guarantee,
        no_io_guarantee=no_io_guarantee,
        no_async_guarantee=no_async_guarantee,
        capability_scope_match=capability_scope_match,
        runtime_kind_scope_match=runtime_kind_scope_match,
    )


def _first_block_reason(
    *,
    plan: RuntimeDispatchPlan,
    decision: DispatchFirewallDecision,
    backend: object,
    descriptor: RuntimeBackendDescriptor | None,
    capability_scope_match: bool,
    runtime_kind_scope_match: bool,
    no_execution_guarantee: bool,
    no_io_guarantee: bool,
    no_async_guarantee: bool,
) -> BackendCertificationReason | None:
    if plan.dispatch_mode is not RuntimeDispatchMode.DRY_RUN_ONLY:
        return BackendCertificationReason.BACKEND_DISPATCH_MODE_NOT_DRY_RUN_ONLY
    if decision.status != "ALLOWED_DRY_RUN":
        return BackendCertificationReason.BACKEND_FIREWALL_DECISION_NOT_ALLOWED
    if decision.plan_checksum != plan.plan_checksum:
        return BackendCertificationReason.BACKEND_FIREWALL_PLAN_MISMATCH
    if not _plan_checksum_matches(plan):
        return BackendCertificationReason.BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH
    if not _firewall_decision_checksum_matches(decision):
        return BackendCertificationReason.BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH
    if descriptor is None:
        return BackendCertificationReason.BACKEND_UNSUPPORTED_IMPLEMENTATION
    if not _descriptor_checksum_matches(descriptor):
        return BackendCertificationReason.BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH
    if descriptor.backend_kind is not RuntimeBackendKind.NULL_BACKEND_V1:
        return BackendCertificationReason.BACKEND_KIND_NOT_NULL
    if descriptor.backend_mode is not RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY:
        return BackendCertificationReason.BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY
    if descriptor.allows_execution is not False:
        return BackendCertificationReason.BACKEND_EXECUTION_CAPABILITY_CLAIMED
    if descriptor.allows_io is not False:
        return BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED
    if descriptor.allows_async is not False:
        return BackendCertificationReason.BACKEND_ASYNC_CAPABILITY_CLAIMED
    if _backend_exposes_runtime_object(backend):
        return BackendCertificationReason.BACKEND_RUNTIME_OBJECT_INJECTION
    if not isinstance(backend, NullRuntimeBackend):
        return BackendCertificationReason.BACKEND_UNSUPPORTED_IMPLEMENTATION
    if not capability_scope_match:
        return BackendCertificationReason.BACKEND_CAPABILITY_SCOPE_DRIFT
    if not runtime_kind_scope_match:
        return BackendCertificationReason.BACKEND_RUNTIME_KIND_SCOPE_DRIFT
    if not (no_execution_guarantee and no_io_guarantee and no_async_guarantee):
        return BackendCertificationReason.BACKEND_RUNTIME_OBJECT_INJECTION
    return None


def _backend_descriptor(backend: object) -> RuntimeBackendDescriptor | None:
    if isinstance(backend, NullRuntimeBackend):
        return backend.descriptor
    try:
        attributes = vars(backend)
    except TypeError:
        return None
    descriptor = attributes.get("descriptor")
    if isinstance(descriptor, RuntimeBackendDescriptor):
        return descriptor
    return None


def _backend_exposes_runtime_object(backend: object) -> bool:
    if isinstance(backend, NullRuntimeBackend):
        return _dataclass_runtime_object_exposed(backend)
    try:
        attributes = vars(backend)
    except TypeError:
        return True
    for name, value in attributes.items():
        if name == "descriptor" and isinstance(value, RuntimeBackendDescriptor):
            continue
        if _forbidden_attribute_name(name) or _runtime_object_value(value):
            return True
    return False


def _dataclass_runtime_object_exposed(backend: NullRuntimeBackend) -> bool:
    if not is_dataclass(backend):
        return True
    allowed_field_names = {"descriptor"}
    backend_fields = {field.name for field in fields(backend)}
    if backend_fields != allowed_field_names:
        return True
    return bool(hasattr(backend, "__dict__"))


def _runtime_object_value(value: object) -> bool:
    if callable(value):
        return True
    if isinstance(value, (dict, list, set, bytearray)):
        return True
    if isinstance(value, (str, int, float, bool, type(None), frozenset, tuple)):
        return False
    return not isinstance(value, RuntimeBackendDescriptor)


def _forbidden_attribute_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _FORBIDDEN_BACKEND_ATTRIBUTE_TOKENS)


def _no_execution_guarantee(
    backend: object,
    descriptor: RuntimeBackendDescriptor | None,
) -> bool:
    if descriptor is None or descriptor.allows_execution is not False:
        return False
    return not _backend_exposes_runtime_object(backend)


def _capability_scope_matches(
    plan: RuntimeDispatchPlan,
    descriptor: RuntimeBackendDescriptor | None,
) -> bool:
    return (
        descriptor is not None
        and descriptor.supported_capabilities == dispatch_plan_capability_scope(plan)
    )


def _runtime_kind_scope_matches(
    plan: RuntimeDispatchPlan,
    descriptor: RuntimeBackendDescriptor | None,
) -> bool:
    return (
        descriptor is not None
        and descriptor.supported_runtime_kinds == dispatch_plan_runtime_kind_scope(plan)
    )


def _plan_checksum_matches(plan: RuntimeDispatchPlan) -> bool:
    try:
        return plan.plan_checksum == recompute_runtime_dispatch_plan_checksum(plan)
    except ValueError:
        return False


def _firewall_decision_checksum_matches(decision: DispatchFirewallDecision) -> bool:
    try:
        return decision.decision_checksum == recompute_dispatch_firewall_decision_checksum(decision)
    except ValueError:
        return False


def _descriptor_checksum_matches(descriptor: RuntimeBackendDescriptor) -> bool:
    try:
        return descriptor.descriptor_checksum == recompute_runtime_backend_descriptor_checksum(
            descriptor
        )
    except ValueError:
        return False


def _descriptor_checksum_or_fallback(descriptor: RuntimeBackendDescriptor | None) -> str:
    if descriptor is None:
        return _FALLBACK_CHECKSUM
    return _valid_or_fallback_checksum(cast(object, descriptor.descriptor_checksum))


def _valid_or_fallback_checksum(value: object) -> str:
    if _is_checksum(value):
        return cast(str, value)
    return _FALLBACK_CHECKSUM


def _is_checksum(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = ["certify_runtime_backend"]
