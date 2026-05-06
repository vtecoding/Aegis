"""Layer 2.5: Policy-v1 contract foundation and pure evaluator.

This package exposes immutable Policy-v1 contracts and a pure deterministic
evaluator. It does not wire policy decisions into the pipeline, ingest live
world state, integrate simulation or middleware, or prove robot safety.
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
from aegis.policy.evaluator import evaluate_policy, evaluate_policy_with_safety_case
from aegis.policy.safety_case import build_safety_case, canonicalise_for_hash
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
    "build_safety_case",
    "canonicalise_for_hash",
    "evaluate_policy",
    "evaluate_policy_with_safety_case",
    "validate_policy",
]
