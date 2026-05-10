"""Pure runtime backend scope helpers for ADR-0018."""

from __future__ import annotations

from aegis.contracts.runtime_dispatch import RuntimeDispatchKind, RuntimeDispatchPlan


def dispatch_plan_capability_scope(plan: RuntimeDispatchPlan) -> frozenset[str]:
    """Return the exact capability scope declared by a dispatch plan."""
    return frozenset(item.capability for item in plan.dispatch_items)


def dispatch_plan_runtime_kind_scope(plan: RuntimeDispatchPlan) -> frozenset[RuntimeDispatchKind]:
    """Return the exact inert runtime kind scope declared by a dispatch plan."""
    return frozenset(item.runtime_kind for item in plan.dispatch_items)


__all__ = ["dispatch_plan_capability_scope", "dispatch_plan_runtime_kind_scope"]
