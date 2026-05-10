"""Aegis deterministic configuration contract.

``AegisConfig`` is a frozen dataclass with deterministic defaults.  It carries
no environment reads, no file I/O, and no mutable state.  Callers — tests, CLI
adapters, ROS 2 adapters — construct it explicitly and inject it wherever
pipeline functions need configuration.

See ADR-0007 for the rationale behind this design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class AegisConfig:
    """Immutable, injected configuration for the Aegis pipeline.

    All fields have deterministic defaults.  No field reads ``os.environ``,
    files, or any external state.  Outer adapters (CLI, ROS 2) are responsible
    for constructing this object from their own environment-loading logic and
    injecting it into the pipeline.

    Args:
        strict_mode: When ``True``, the pipeline applies the most conservative
            interpretation of all policy rules.  Defaults to ``True``.
        max_plan_steps: Maximum number of command steps permitted in a single
            ``CommandPlan``.  Must be a positive integer.  Defaults to ``32``.
        allow_unknown_metadata: When ``False``, unknown metadata fields in
            command parameters are stripped by the planning layer.  When
            ``True``, they are preserved.  Defaults to ``False``.
        audit_algorithm: Hash algorithm used by the audit layer.  Phase 1
            supports only ``"sha256"``.
        gate_version: Identifies the gate implementation that will verify
            audited plans.  Defaults to ``"gate-v1"``.
        pipeline_version: Identifies the pipeline contract version.
            Defaults to ``"pipeline-v1"``.

    Raises:
        ValueError: If ``max_plan_steps`` is not a positive integer.
    """

    strict_mode: bool = True
    max_plan_steps: int = 32
    allow_unknown_metadata: bool = False
    audit_algorithm: Literal["sha256"] = "sha256"
    gate_version: str = "gate-v1"
    pipeline_version: str = "pipeline-v1"

    def __post_init__(self) -> None:
        if isinstance(self.max_plan_steps, bool):
            raise ValueError("max_plan_steps must be an integer, bool is not allowed")
        if self.max_plan_steps < 1:
            raise ValueError("max_plan_steps must be a positive integer")
        gate_version = self.gate_version.strip()
        if gate_version == "":
            raise ValueError("gate_version must be non-empty")
        pipeline_version = self.pipeline_version.strip()
        if pipeline_version == "":
            raise ValueError("pipeline_version must be non-empty")
        # Reassign stripped values through object.__setattr__ since frozen=True.
        object.__setattr__(self, "gate_version", gate_version)
        object.__setattr__(self, "pipeline_version", pipeline_version)
