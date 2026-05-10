"""Layer 2.5: Policy-v1 contract foundation and pure evaluator.

This package exposes immutable Policy-v1 contracts and a pure deterministic
evaluator. Pipeline admission wiring lives in ``aegis.pipeline``; this package
does not ingest live world state, integrate simulation or middleware, or prove
robot safety.
"""

from aegis.policy.aegis_contracts import (
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
    policy_evaluation_result_checksum,
)
from aegis.policy.aegis_evaluator import evaluate_policy, evaluate_policy_with_safety_case
from aegis.policy.aegis_safety_case import build_safety_case, canonicalise_for_hash
from aegis.policy.aegis_validation import validate_policy

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
    "policy_evaluation_result_checksum",
    "validate_policy",
]
