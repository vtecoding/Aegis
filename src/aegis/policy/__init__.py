"""Layer 2.5: Policy-v1 contract foundation.

This package exposes immutable Policy-v1 contracts only. It does not implement
policy evaluation, world-state ingestion, simulation, middleware integration, or
robot safety decisions.
"""

from aegis.policy.contracts import (
    Capability,
    Constraint,
    FrozenPolicyValue,
    Policy,
    PolicyDecision,
    PolicyDefaultDecision,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyScalar,
    SafetyCase,
    WorldSnapshotStub,
)
from aegis.policy.validation import validate_policy

__all__ = [
    "Capability",
    "Constraint",
    "FrozenPolicyValue",
    "Policy",
    "PolicyDecision",
    "PolicyDefaultDecision",
    "PolicyEvaluationResult",
    "PolicyRule",
    "PolicyScalar",
    "SafetyCase",
    "WorldSnapshotStub",
    "validate_policy",
]
