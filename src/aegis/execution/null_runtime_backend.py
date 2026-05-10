"""Certified non-executing null runtime backend for ADR-0018."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.runtime_backend import (
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
)
from aegis.contracts.runtime_dispatch import RuntimeDispatchPlan
from aegis.execution.runtime_backend import (
    dispatch_plan_capability_scope,
    dispatch_plan_runtime_kind_scope,
)


@dataclass(frozen=True, slots=True, init=False)
class NullRuntimeBackend:
    """Descriptor-only backend that can observe dry-run intent but cannot execute."""

    descriptor: RuntimeBackendDescriptor

    def __init__(self, *, descriptor: object) -> None:
        if not isinstance(descriptor, RuntimeBackendDescriptor):
            raise ValueError("descriptor must be a RuntimeBackendDescriptor")
        object.__setattr__(self, "descriptor", descriptor)


def build_null_runtime_backend(plan: RuntimeDispatchPlan) -> NullRuntimeBackend:
    """Build a null backend descriptor scoped exactly to one dispatch plan."""
    return NullRuntimeBackend(
        descriptor=RuntimeBackendDescriptor(
            backend_id=f"null-backend-v1:{plan.plan_checksum}",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds=dispatch_plan_runtime_kind_scope(plan),
            supported_capabilities=dispatch_plan_capability_scope(plan),
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    )


__all__ = ["NullRuntimeBackend", "build_null_runtime_backend"]
