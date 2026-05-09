"""Policy-v1 immutable contract foundation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from re import fullmatch
from types import MappingProxyType
from typing import cast

type PolicyScalar = str | int | float | bool | None
type FrozenPolicyValue = (
    PolicyScalar
    | tuple[FrozenPolicyValue, ...]
    | frozenset[FrozenPolicyValue]
    | Mapping[str, FrozenPolicyValue]
)


class PolicyDecision(StrEnum):
    """Policy-v1 evaluation decision values."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    INVALID = "INVALID"
    ERROR = "ERROR"


class PolicyDefaultDecision(StrEnum):
    """Policy-v1 default decisions permitted for unmatched rules."""

    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"


@dataclass(frozen=True, slots=True, init=False)
class Capability:
    """Descriptive action capability requested by a future policy evaluator.

    Args:
        name: Canonical dotted capability name.
        version: Non-empty capability contract version.
        parameters: Explicit descriptive metadata for the capability. Values are
            recursively frozen and never interpreted as executable handlers.

    Raises:
        ValueError: If name or version is empty, name is not canonical, or
            parameters contain unsupported values.
    """

    name: str
    version: str
    parameters: Mapping[str, FrozenPolicyValue]

    def __init__(
        self,
        name: str,
        version: str = "v1",
        parameters: Mapping[str, object] | None = None,
    ) -> None:
        normalized_name = _normalize_capability_name(name)
        normalized_version = _normalize_required_text(version, "version")

        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "version", normalized_version)
        object.__setattr__(self, "parameters", _freeze_policy_mapping(parameters or {}))


@dataclass(frozen=True, slots=True, init=False)
class Constraint:
    """Deterministic condition metadata for future policy evaluation.

    Args:
        constraint_type: Non-empty constraint type identifier.
        parameters: Explicit constraint parameters, recursively frozen.
        required: Whether future evaluator failure must block admission.

    Raises:
        ValueError: If constraint_type is empty, parameters contain unsupported
            values, or required is not a bool.
    """

    constraint_type: str
    parameters: Mapping[str, FrozenPolicyValue]
    required: bool

    def __init__(
        self,
        constraint_type: str,
        parameters: Mapping[str, object] | None = None,
        required: object = True,
    ) -> None:
        if not isinstance(required, bool):
            raise ValueError("required must be a bool")

        object.__setattr__(
            self, "constraint_type", _normalize_required_text(constraint_type, "constraint_type")
        )
        object.__setattr__(self, "parameters", _freeze_policy_mapping(parameters or {}))
        object.__setattr__(self, "required", required)


@dataclass(frozen=True, slots=True, init=False)
class PolicyRule:
    """Policy rule binding one capability name to deterministic constraints.

    Args:
        rule_id: Stable non-empty rule identifier.
        capability: Canonical dotted capability name governed by this rule.
        constraints: Constraints associated with this rule.
        description: Optional human-readable description.
        enabled: Whether a future evaluator should consider the rule.

    Raises:
        ValueError: If required identifiers are empty, capability is not
            canonical, enabled is not a bool, or an enabled rule has no
            constraints.
    """

    rule_id: str
    capability: str
    constraints: tuple[Constraint, ...]
    description: str
    enabled: bool

    def __init__(
        self,
        rule_id: str,
        capability: str,
        constraints: Iterable[Constraint],
        description: str = "",
        enabled: object = True,
    ) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a bool")

        normalized_rule_id = _normalize_required_text(rule_id, "rule_id")
        normalized_capability = _normalize_capability_name(capability)
        constraints_tuple = tuple(constraints)
        if enabled and not constraints_tuple:
            raise ValueError("enabled rules must contain at least one constraint")

        object.__setattr__(self, "rule_id", normalized_rule_id)
        object.__setattr__(self, "capability", normalized_capability)
        object.__setattr__(self, "constraints", constraints_tuple)
        object.__setattr__(self, "description", description.strip())
        object.__setattr__(self, "enabled", enabled)


@dataclass(frozen=True, slots=True, init=False)
class Policy:
    """Complete deterministic Policy-v1 rule bundle.

    Args:
        policy_id: Stable non-empty policy identifier.
        version: Non-empty policy version.
        rules: Rule set for this policy. Duplicate rule IDs are rejected.
        default_decision: Fail-closed decision for unmatched rules.

    Raises:
        ValueError: If identifiers are empty, rule IDs are duplicated, the
            default decision is invalid, or default ALLOW is requested.
    """

    policy_id: str
    version: str
    rules: tuple[PolicyRule, ...]
    default_decision: PolicyDefaultDecision

    def __init__(
        self,
        policy_id: str,
        version: str,
        rules: Iterable[PolicyRule],
        default_decision: str | PolicyDefaultDecision = PolicyDefaultDecision.BLOCK,
    ) -> None:
        rules_tuple = tuple(rules)
        _reject_duplicate_rule_ids(rules_tuple)

        object.__setattr__(self, "policy_id", _normalize_required_text(policy_id, "policy_id"))
        object.__setattr__(self, "version", _normalize_required_text(version, "version"))
        object.__setattr__(self, "rules", rules_tuple)
        object.__setattr__(self, "default_decision", _normalize_default_decision(default_decision))


@dataclass(frozen=True, slots=True, init=False)
class WorldSnapshotStub:
    """Immutable deterministic evidence input for future policy evaluation.

    Args:
        snapshot_id: Stable non-empty snapshot identifier.
        captured_at_ms: Caller-provided capture timestamp in milliseconds.
        expires_at_ms: Caller-provided expiry timestamp in milliseconds.
        source: Non-empty evidence source identifier.
        confidence: Confidence in [0.0, 1.0].
        facts: Explicit immutable evidence facts.
        checksum: Optional non-empty checksum supplied by the caller.
        declared_capability_scope: Optional declared capability names the snapshot covers.
        declared_fact_keys: Optional declared fact keys carried by the snapshot.

    Raises:
        ValueError: If identifiers are empty, timestamps are invalid,
            confidence is outside [0.0, 1.0], or facts contain unsupported values.
    """

    snapshot_id: str
    captured_at_ms: int
    expires_at_ms: int
    source: str
    confidence: float
    facts: Mapping[str, FrozenPolicyValue]
    checksum: str | None
    declared_capability_scope: frozenset[str] | None
    declared_fact_keys: frozenset[str] | None

    def __init__(
        self,
        snapshot_id: str,
        captured_at_ms: object,
        expires_at_ms: object,
        source: str,
        confidence: object,
        facts: Mapping[str, object] | None = None,
        checksum: str | None = None,
        *,
        declared_capability_scope: Iterable[str] | None = None,
        declared_fact_keys: Iterable[str] | None = None,
    ) -> None:
        normalized_captured_at_ms = _normalize_non_negative_int(captured_at_ms, "captured_at_ms")
        normalized_expires_at_ms = _normalize_non_negative_int(expires_at_ms, "expires_at_ms")
        if normalized_expires_at_ms < normalized_captured_at_ms:
            raise ValueError("expires_at_ms must be greater than or equal to captured_at_ms")

        object.__setattr__(
            self, "snapshot_id", _normalize_required_text(snapshot_id, "snapshot_id")
        )
        object.__setattr__(self, "captured_at_ms", normalized_captured_at_ms)
        object.__setattr__(self, "expires_at_ms", normalized_expires_at_ms)
        object.__setattr__(self, "source", _normalize_required_text(source, "source"))
        object.__setattr__(self, "confidence", _normalize_confidence(confidence))
        object.__setattr__(self, "facts", _freeze_policy_mapping(facts or {}))
        object.__setattr__(self, "checksum", _normalize_optional_text(checksum, "checksum"))
        object.__setattr__(
            self,
            "declared_capability_scope",
            _normalize_optional_capability_scope(declared_capability_scope),
        )
        object.__setattr__(
            self,
            "declared_fact_keys",
            _normalize_optional_fact_keys(declared_fact_keys),
        )


@dataclass(frozen=True, slots=True, init=False)
class PolicyEvaluationResult:
    """Future policy evaluator output contract.

    Args:
        decision: Policy-v1 decision value.
        policy_id: Policy identifier used for the evaluation.
        matched_rule_ids: Rule IDs matched by the future evaluator.
        passed_constraints: Constraint IDs or types that passed.
        failed_constraints: Constraint IDs or types that failed.
        reasons: Human-readable deterministic explanation strings.
        world_snapshot_id: Optional world snapshot identity used for freshness.
        world_snapshot_observed_at_ms: Optional observed timestamp from the
            freshness gate.
        freshness_result_checksum: Optional deterministic freshness result checksum.
        freshness_status: Optional freshness status string.
        world_snapshot_admissibility_status: Optional admissibility status string.
        world_snapshot_admissibility_result_checksum: Optional admissibility result checksum.
        world_snapshot_trust_status: Optional trust status string.
        world_snapshot_trust_result_checksum: Optional trust result checksum.

    Raises:
        ValueError: If decision is invalid, ALLOW has no matched rules, failure
            decisions have no reasons, or any string tuple contains empty values.
    """

    decision: PolicyDecision
    policy_id: str
    matched_rule_ids: tuple[str, ...]
    passed_constraints: tuple[str, ...]
    failed_constraints: tuple[str, ...]
    reasons: tuple[str, ...]
    world_snapshot_id: str | None
    world_snapshot_observed_at_ms: int | None
    freshness_result_checksum: str | None
    freshness_status: str | None
    world_snapshot_admissibility_status: str | None
    world_snapshot_admissibility_reason_code: str | None
    world_snapshot_admissibility_result_checksum: str | None
    requested_capability: str | None
    declared_capability_scope: tuple[str, ...]
    declared_fact_keys: tuple[str, ...] | None
    missing_declared_fact_keys: tuple[str, ...]
    missing_required_fact_keys: tuple[str, ...]
    undeclared_required_fact_keys: tuple[str, ...]
    world_snapshot_trust_status: str | None
    world_snapshot_trust_reason_code: str | None
    world_snapshot_trust_result_checksum: str | None
    evidence_envelope_checksum: str | None
    attestation_checksum: str | None
    trust_policy_checksum: str | None
    verifier_certification_checksum: str | None
    trust_policy_config_validation_checksum: str | None
    verifier_id: str | None
    verifier_metadata_checksum: str | None
    source_id: str | None
    source_type: str | None
    trust_domain: str | None

    def __init__(
        self,
        decision: str | PolicyDecision,
        policy_id: str,
        matched_rule_ids: Iterable[str],
        passed_constraints: Iterable[str],
        failed_constraints: Iterable[str],
        reasons: Iterable[str],
        *,
        world_snapshot_id: str | None = None,
        world_snapshot_observed_at_ms: object = None,
        freshness_result_checksum: str | None = None,
        freshness_status: object = None,
        world_snapshot_admissibility_status: object = None,
        world_snapshot_admissibility_reason_code: str | None = None,
        world_snapshot_admissibility_result_checksum: str | None = None,
        requested_capability: str | None = None,
        declared_capability_scope: Iterable[str] = (),
        declared_fact_keys: Iterable[str] | None = None,
        missing_declared_fact_keys: Iterable[str] = (),
        missing_required_fact_keys: Iterable[str] = (),
        undeclared_required_fact_keys: Iterable[str] = (),
        world_snapshot_trust_status: object = None,
        world_snapshot_trust_reason_code: str | None = None,
        world_snapshot_trust_result_checksum: str | None = None,
        evidence_envelope_checksum: str | None = None,
        attestation_checksum: str | None = None,
        trust_policy_checksum: str | None = None,
        verifier_certification_checksum: str | None = None,
        trust_policy_config_validation_checksum: str | None = None,
        verifier_id: str | None = None,
        verifier_metadata_checksum: str | None = None,
        source_id: str | None = None,
        source_type: object = None,
        trust_domain: object = None,
    ) -> None:
        normalized_decision = _normalize_policy_decision(decision)
        normalized_matched_rule_ids = _normalize_text_tuple(matched_rule_ids, "matched_rule_ids")
        normalized_reasons = _normalize_text_tuple(reasons, "reasons")

        if normalized_decision is PolicyDecision.ALLOW and not normalized_matched_rule_ids:
            raise ValueError("ALLOW decisions must include at least one matched rule")
        if (
            normalized_decision
            in {
                PolicyDecision.BLOCK,
                PolicyDecision.INVALID,
                PolicyDecision.ERROR,
            }
            and not normalized_reasons
        ):
            raise ValueError("failure decisions must include at least one reason")

        object.__setattr__(self, "decision", normalized_decision)
        object.__setattr__(self, "policy_id", _normalize_required_text(policy_id, "policy_id"))
        object.__setattr__(self, "matched_rule_ids", normalized_matched_rule_ids)
        object.__setattr__(
            self,
            "passed_constraints",
            _normalize_text_tuple(passed_constraints, "passed_constraints"),
        )
        object.__setattr__(
            self,
            "failed_constraints",
            _normalize_text_tuple(failed_constraints, "failed_constraints"),
        )
        object.__setattr__(self, "reasons", normalized_reasons)
        object.__setattr__(
            self,
            "world_snapshot_id",
            _normalize_optional_text(world_snapshot_id, "world_snapshot_id"),
        )
        object.__setattr__(
            self,
            "world_snapshot_observed_at_ms",
            _normalize_optional_observed_at_ms(world_snapshot_observed_at_ms),
        )
        object.__setattr__(
            self,
            "freshness_result_checksum",
            _normalize_optional_text(freshness_result_checksum, "freshness_result_checksum"),
        )
        object.__setattr__(
            self,
            "freshness_status",
            _normalize_optional_freshness_status(freshness_status),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_status",
            _normalize_optional_admissibility_status(world_snapshot_admissibility_status),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_reason_code",
            _normalize_optional_reason_code(
                world_snapshot_admissibility_reason_code,
                "world_snapshot_admissibility_reason_code",
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_result_checksum",
            _normalize_optional_text(
                world_snapshot_admissibility_result_checksum,
                "world_snapshot_admissibility_result_checksum",
            ),
        )
        object.__setattr__(
            self,
            "requested_capability",
            _normalize_optional_capability_name(requested_capability, "requested_capability"),
        )
        object.__setattr__(
            self,
            "declared_capability_scope",
            _normalize_capability_tuple(declared_capability_scope, "declared_capability_scope"),
        )
        object.__setattr__(
            self,
            "declared_fact_keys",
            _normalize_optional_fact_key_tuple(declared_fact_keys, "declared_fact_keys"),
        )
        object.__setattr__(
            self,
            "missing_declared_fact_keys",
            _normalize_fact_key_tuple(missing_declared_fact_keys, "missing_declared_fact_keys"),
        )
        object.__setattr__(
            self,
            "missing_required_fact_keys",
            _normalize_fact_key_tuple(missing_required_fact_keys, "missing_required_fact_keys"),
        )
        object.__setattr__(
            self,
            "undeclared_required_fact_keys",
            _normalize_fact_key_tuple(
                undeclared_required_fact_keys, "undeclared_required_fact_keys"
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_status",
            _normalize_optional_trust_status(world_snapshot_trust_status),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_reason_code",
            _normalize_optional_reason_code(
                world_snapshot_trust_reason_code, "world_snapshot_trust_reason_code"
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_result_checksum",
            _normalize_optional_text(
                world_snapshot_trust_result_checksum, "world_snapshot_trust_result_checksum"
            ),
        )
        object.__setattr__(
            self,
            "evidence_envelope_checksum",
            _normalize_optional_text(evidence_envelope_checksum, "evidence_envelope_checksum"),
        )
        object.__setattr__(
            self,
            "attestation_checksum",
            _normalize_optional_text(attestation_checksum, "attestation_checksum"),
        )
        object.__setattr__(
            self,
            "trust_policy_checksum",
            _normalize_optional_text(trust_policy_checksum, "trust_policy_checksum"),
        )
        object.__setattr__(
            self,
            "verifier_certification_checksum",
            _normalize_optional_text(
                verifier_certification_checksum, "verifier_certification_checksum"
            ),
        )
        object.__setattr__(
            self,
            "trust_policy_config_validation_checksum",
            _normalize_optional_text(
                trust_policy_config_validation_checksum,
                "trust_policy_config_validation_checksum",
            ),
        )
        object.__setattr__(
            self, "verifier_id", _normalize_optional_text(verifier_id, "verifier_id")
        )
        object.__setattr__(
            self,
            "verifier_metadata_checksum",
            _normalize_optional_text(verifier_metadata_checksum, "verifier_metadata_checksum"),
        )
        object.__setattr__(self, "source_id", _normalize_optional_text(source_id, "source_id"))
        object.__setattr__(self, "source_type", _normalize_optional_source_type(source_type))
        object.__setattr__(self, "trust_domain", _normalize_optional_trust_domain(trust_domain))


@dataclass(frozen=True, slots=True, init=False)
class SafetyCase:
    """Auditable explanation package for a policy decision.

    Args:
        safety_case_id: Stable non-empty safety-case identifier.
        policy_result: Policy evaluation result being explained.
        audited_plan_id: Non-empty audited plan identifier.
        world_snapshot_id: Optional non-empty snapshot identifier.
        evidence: Explicit immutable explanation evidence.
        plan_id: Optional command plan identifier bound by pipeline admission.
        plan_checksum: Optional audited plan checksum bound by pipeline admission.
        policy_result_checksum: Deterministic checksum of the explained policy result.
        world_snapshot_checksum: Optional checksum from the world snapshot stub.
        capability_name: Optional capability name evaluated by policy admission.
        capability_version: Optional capability version evaluated by policy admission.
        world_snapshot_admissibility_status: Optional admissibility status bound by admission.
        world_snapshot_admissibility_result_checksum: Optional admissibility result checksum.
        world_snapshot_trust_status: Optional trust status bound by admission.
        world_snapshot_trust_result_checksum: Optional trust result checksum.

    Raises:
        ValueError: If identifiers are empty, evidence contains unsupported
            values, or an ALLOW result has no evidence.
    """

    safety_case_id: str
    policy_result: PolicyEvaluationResult
    audited_plan_id: str
    world_snapshot_id: str | None
    evidence: Mapping[str, FrozenPolicyValue]
    plan_id: str | None
    plan_checksum: str | None
    policy_result_checksum: str
    world_snapshot_checksum: str | None
    capability_name: str | None
    capability_version: str | None
    world_snapshot_observed_at_ms: int | None
    freshness_result_checksum: str | None
    freshness_status: str | None
    world_snapshot_admissibility_status: str | None
    world_snapshot_admissibility_reason_code: str | None
    world_snapshot_admissibility_result_checksum: str | None
    requested_capability: str | None
    declared_capability_scope: tuple[str, ...]
    declared_fact_keys: tuple[str, ...] | None
    missing_declared_fact_keys: tuple[str, ...]
    missing_required_fact_keys: tuple[str, ...]
    undeclared_required_fact_keys: tuple[str, ...]
    world_snapshot_trust_status: str | None
    world_snapshot_trust_reason_code: str | None
    world_snapshot_trust_result_checksum: str | None
    evidence_envelope_checksum: str | None
    attestation_checksum: str | None
    trust_policy_checksum: str | None
    verifier_certification_checksum: str | None
    trust_policy_config_validation_checksum: str | None
    verifier_id: str | None
    verifier_metadata_checksum: str | None
    source_id: str | None
    source_type: str | None
    trust_domain: str | None

    def __init__(
        self,
        safety_case_id: str,
        policy_result: PolicyEvaluationResult,
        audited_plan_id: str,
        world_snapshot_id: str | None,
        evidence: Mapping[str, object] | None = None,
        *,
        plan_id: str | None = None,
        plan_checksum: str | None = None,
        policy_result_checksum: str | None = None,
        world_snapshot_checksum: str | None = None,
        capability_name: str | None = None,
        capability_version: str | None = None,
        world_snapshot_observed_at_ms: int | None = None,
        freshness_result_checksum: str | None = None,
        freshness_status: str | None = None,
        world_snapshot_admissibility_status: object = None,
        world_snapshot_admissibility_reason_code: str | None = None,
        world_snapshot_admissibility_result_checksum: str | None = None,
        requested_capability: str | None = None,
        declared_capability_scope: Iterable[str] | None = None,
        declared_fact_keys: Iterable[str] | None = None,
        missing_declared_fact_keys: Iterable[str] | None = None,
        missing_required_fact_keys: Iterable[str] | None = None,
        undeclared_required_fact_keys: Iterable[str] | None = None,
        world_snapshot_trust_status: object = None,
        world_snapshot_trust_reason_code: str | None = None,
        world_snapshot_trust_result_checksum: str | None = None,
        evidence_envelope_checksum: str | None = None,
        attestation_checksum: str | None = None,
        trust_policy_checksum: str | None = None,
        verifier_certification_checksum: str | None = None,
        trust_policy_config_validation_checksum: str | None = None,
        verifier_id: str | None = None,
        verifier_metadata_checksum: str | None = None,
        source_id: str | None = None,
        source_type: object = None,
        trust_domain: object = None,
    ) -> None:
        frozen_evidence = _freeze_policy_mapping(evidence or {})
        if policy_result.decision is PolicyDecision.ALLOW and not frozen_evidence:
            raise ValueError("ALLOW safety cases must include evidence")
        computed_policy_result_checksum = policy_evaluation_result_checksum(policy_result)
        normalized_policy_result_checksum = _normalize_optional_text(
            policy_result_checksum, "policy_result_checksum"
        )
        if normalized_policy_result_checksum is None:
            normalized_policy_result_checksum = computed_policy_result_checksum
        if normalized_policy_result_checksum != computed_policy_result_checksum:
            raise ValueError("policy_result_checksum must match policy_result")

        object.__setattr__(
            self, "safety_case_id", _normalize_required_text(safety_case_id, "safety_case_id")
        )
        object.__setattr__(self, "policy_result", policy_result)
        object.__setattr__(
            self, "audited_plan_id", _normalize_required_text(audited_plan_id, "audited_plan_id")
        )
        object.__setattr__(
            self,
            "world_snapshot_id",
            _normalize_optional_text(world_snapshot_id, "world_snapshot_id"),
        )
        object.__setattr__(self, "evidence", frozen_evidence)
        object.__setattr__(self, "plan_id", _normalize_optional_text(plan_id, "plan_id"))
        object.__setattr__(
            self, "plan_checksum", _normalize_optional_text(plan_checksum, "plan_checksum")
        )
        object.__setattr__(self, "policy_result_checksum", normalized_policy_result_checksum)
        object.__setattr__(
            self,
            "world_snapshot_checksum",
            _normalize_optional_text(world_snapshot_checksum, "world_snapshot_checksum"),
        )
        object.__setattr__(
            self, "capability_name", _normalize_optional_text(capability_name, "capability_name")
        )
        object.__setattr__(
            self,
            "capability_version",
            _normalize_optional_text(capability_version, "capability_version"),
        )
        object.__setattr__(
            self,
            "world_snapshot_observed_at_ms",
            _normalize_optional_observed_at_ms(world_snapshot_observed_at_ms),
        )
        object.__setattr__(
            self,
            "freshness_result_checksum",
            _normalize_optional_text(freshness_result_checksum, "freshness_result_checksum"),
        )
        object.__setattr__(
            self,
            "freshness_status",
            _normalize_optional_freshness_status(freshness_status),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_status",
            _normalize_optional_admissibility_status(
                world_snapshot_admissibility_status
                if world_snapshot_admissibility_status is not None
                else policy_result.world_snapshot_admissibility_status
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_reason_code",
            _normalize_optional_reason_code(
                world_snapshot_admissibility_reason_code
                if world_snapshot_admissibility_reason_code is not None
                else policy_result.world_snapshot_admissibility_reason_code,
                "world_snapshot_admissibility_reason_code",
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_admissibility_result_checksum",
            _normalize_optional_text(
                world_snapshot_admissibility_result_checksum
                if world_snapshot_admissibility_result_checksum is not None
                else policy_result.world_snapshot_admissibility_result_checksum,
                "world_snapshot_admissibility_result_checksum",
            ),
        )
        object.__setattr__(
            self,
            "requested_capability",
            _normalize_optional_capability_name(
                requested_capability
                if requested_capability is not None
                else policy_result.requested_capability,
                "requested_capability",
            ),
        )
        object.__setattr__(
            self,
            "declared_capability_scope",
            _normalize_capability_tuple(
                declared_capability_scope
                if declared_capability_scope is not None
                else policy_result.declared_capability_scope,
                "declared_capability_scope",
            ),
        )
        object.__setattr__(
            self,
            "declared_fact_keys",
            _normalize_optional_fact_key_tuple(
                declared_fact_keys
                if declared_fact_keys is not None
                else policy_result.declared_fact_keys,
                "declared_fact_keys",
            ),
        )
        object.__setattr__(
            self,
            "missing_declared_fact_keys",
            _normalize_fact_key_tuple(
                missing_declared_fact_keys
                if missing_declared_fact_keys is not None
                else policy_result.missing_declared_fact_keys,
                "missing_declared_fact_keys",
            ),
        )
        object.__setattr__(
            self,
            "missing_required_fact_keys",
            _normalize_fact_key_tuple(
                missing_required_fact_keys
                if missing_required_fact_keys is not None
                else policy_result.missing_required_fact_keys,
                "missing_required_fact_keys",
            ),
        )
        object.__setattr__(
            self,
            "undeclared_required_fact_keys",
            _normalize_fact_key_tuple(
                undeclared_required_fact_keys
                if undeclared_required_fact_keys is not None
                else policy_result.undeclared_required_fact_keys,
                "undeclared_required_fact_keys",
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_status",
            _normalize_optional_trust_status(
                world_snapshot_trust_status
                if world_snapshot_trust_status is not None
                else policy_result.world_snapshot_trust_status
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_reason_code",
            _normalize_optional_reason_code(
                world_snapshot_trust_reason_code
                if world_snapshot_trust_reason_code is not None
                else policy_result.world_snapshot_trust_reason_code,
                "world_snapshot_trust_reason_code",
            ),
        )
        object.__setattr__(
            self,
            "world_snapshot_trust_result_checksum",
            _normalize_optional_text(
                world_snapshot_trust_result_checksum
                if world_snapshot_trust_result_checksum is not None
                else policy_result.world_snapshot_trust_result_checksum,
                "world_snapshot_trust_result_checksum",
            ),
        )
        object.__setattr__(
            self,
            "evidence_envelope_checksum",
            _normalize_optional_text(
                evidence_envelope_checksum
                if evidence_envelope_checksum is not None
                else policy_result.evidence_envelope_checksum,
                "evidence_envelope_checksum",
            ),
        )
        object.__setattr__(
            self,
            "attestation_checksum",
            _normalize_optional_text(
                attestation_checksum
                if attestation_checksum is not None
                else policy_result.attestation_checksum,
                "attestation_checksum",
            ),
        )
        object.__setattr__(
            self,
            "trust_policy_checksum",
            _normalize_optional_text(
                trust_policy_checksum
                if trust_policy_checksum is not None
                else policy_result.trust_policy_checksum,
                "trust_policy_checksum",
            ),
        )
        object.__setattr__(
            self,
            "verifier_certification_checksum",
            _normalize_optional_text(
                verifier_certification_checksum
                if verifier_certification_checksum is not None
                else policy_result.verifier_certification_checksum,
                "verifier_certification_checksum",
            ),
        )
        object.__setattr__(
            self,
            "trust_policy_config_validation_checksum",
            _normalize_optional_text(
                trust_policy_config_validation_checksum
                if trust_policy_config_validation_checksum is not None
                else policy_result.trust_policy_config_validation_checksum,
                "trust_policy_config_validation_checksum",
            ),
        )
        object.__setattr__(
            self,
            "verifier_id",
            _normalize_optional_text(
                verifier_id if verifier_id is not None else policy_result.verifier_id,
                "verifier_id",
            ),
        )
        object.__setattr__(
            self,
            "verifier_metadata_checksum",
            _normalize_optional_text(
                verifier_metadata_checksum
                if verifier_metadata_checksum is not None
                else policy_result.verifier_metadata_checksum,
                "verifier_metadata_checksum",
            ),
        )
        object.__setattr__(
            self,
            "source_id",
            _normalize_optional_text(
                source_id if source_id is not None else policy_result.source_id, "source_id"
            ),
        )
        object.__setattr__(
            self,
            "source_type",
            _normalize_optional_source_type(
                source_type if source_type is not None else policy_result.source_type
            ),
        )
        object.__setattr__(
            self,
            "trust_domain",
            _normalize_optional_trust_domain(
                trust_domain if trust_domain is not None else policy_result.trust_domain
            ),
        )


def policy_evaluation_result_checksum(policy_result: PolicyEvaluationResult) -> str:
    """Return a deterministic checksum for a PolicyEvaluationResult.

    Args:
        policy_result: Policy evaluation result to identify.

    Returns:
        SHA-256 checksum over canonical policy-result content.
    """
    payload = {
        "decision": policy_result.decision.value,
        "policy_id": policy_result.policy_id,
        "matched_rule_ids": list(policy_result.matched_rule_ids),
        "passed_constraints": list(policy_result.passed_constraints),
        "failed_constraints": list(policy_result.failed_constraints),
        "reasons": list(policy_result.reasons),
        "world_snapshot_id": policy_result.world_snapshot_id,
        "world_snapshot_observed_at_ms": policy_result.world_snapshot_observed_at_ms,
        "freshness_result_checksum": policy_result.freshness_result_checksum,
        "freshness_status": policy_result.freshness_status,
        "world_snapshot_admissibility_status": (policy_result.world_snapshot_admissibility_status),
        "world_snapshot_admissibility_reason_code": (
            policy_result.world_snapshot_admissibility_reason_code
        ),
        "world_snapshot_admissibility_result_checksum": (
            policy_result.world_snapshot_admissibility_result_checksum
        ),
        "requested_capability": policy_result.requested_capability,
        "declared_capability_scope": list(policy_result.declared_capability_scope),
        "declared_fact_keys": (
            None
            if policy_result.declared_fact_keys is None
            else list(policy_result.declared_fact_keys)
        ),
        "missing_declared_fact_keys": list(policy_result.missing_declared_fact_keys),
        "missing_required_fact_keys": list(policy_result.missing_required_fact_keys),
        "undeclared_required_fact_keys": list(policy_result.undeclared_required_fact_keys),
        "world_snapshot_trust_status": policy_result.world_snapshot_trust_status,
        "world_snapshot_trust_reason_code": policy_result.world_snapshot_trust_reason_code,
        "world_snapshot_trust_result_checksum": (
            policy_result.world_snapshot_trust_result_checksum
        ),
        "evidence_envelope_checksum": policy_result.evidence_envelope_checksum,
        "attestation_checksum": policy_result.attestation_checksum,
        "trust_policy_checksum": policy_result.trust_policy_checksum,
        "verifier_certification_checksum": policy_result.verifier_certification_checksum,
        "trust_policy_config_validation_checksum": (
            policy_result.trust_policy_config_validation_checksum
        ),
        "verifier_id": policy_result.verifier_id,
        "verifier_metadata_checksum": policy_result.verifier_metadata_checksum,
        "source_id": policy_result.source_id,
        "source_type": policy_result.source_type,
        "trust_domain": policy_result.trust_domain,
    }
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


def _normalize_optional_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_text(value, field_name)


def _normalize_optional_observed_at_ms(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("world_snapshot_observed_at_ms must be an integer or None")
    if value < 0:
        raise ValueError("world_snapshot_observed_at_ms must be >= 0")
    return value


_VALID_FRESHNESS_STATUS_VALUES = frozenset(
    {
        "FRESH",
        "STALE",
        "MISSING_SNAPSHOT",
        "MISSING_TIMESTAMP",
        "MISSING_EVALUATION_TIME",
        "FUTURE_DATED",
        "INVALID_MAX_AGE",
        "INVALID_TIMESTAMP",
        "SNAPSHOT_ID_MISSING",
        "CONTRADICTORY_METADATA",
        "NOT_CHECKED",
        "ERROR",
    }
)

_VALID_ADMISSIBILITY_STATUS_VALUES = frozenset(
    {
        "ADMISSIBLE",
        "SNAPSHOT_MISSING",
        "SNAPSHOT_CHECKSUM_MISSING",
        "SNAPSHOT_CHECKSUM_EMPTY",
        "CAPABILITY_SCOPE_MISSING",
        "CAPABILITY_SCOPE_EMPTY",
        "CAPABILITY_SCOPE_MISMATCH",
        "FACTS_MALFORMED",
        "DECLARED_FACT_KEY_MISSING",
        "REQUIRED_FACT_KEY_MISSING",
        "REQUIRED_FACT_KEY_UNDECLARED",
        "CONTRADICTORY_SNAPSHOT_EVIDENCE",
    }
)

_VALID_TRUST_STATUS_VALUES = frozenset(
    {
        "TRUSTED",
        "UNTRUSTED",
        "MISSING_EVIDENCE",
        "MISSING_TRUST_POLICY",
        "MISSING_VERIFIER",
        "SNAPSHOT_CHECKSUM_MISMATCH",
        "SOURCE_NOT_ALLOWED",
        "SOURCE_TYPE_NOT_ALLOWED",
        "TRUST_DOMAIN_NOT_ALLOWED",
        "CAPABILITY_NOT_ALLOWED",
        "ATTESTATION_MISSING",
        "ATTESTATION_INVALID",
        "ATTESTATION_EXPIRED",
        "ATTESTATION_NOT_YET_VALID",
        "ATTESTATION_REPLAY_DETECTED",
        "UNSUPPORTED_ATTESTATION_ALGORITHM",
        "MALFORMED_EVIDENCE",
        "CONTRADICTORY_EVIDENCE",
    }
)

_VALID_SOURCE_TYPE_VALUES = frozenset(
    {
        "TEST_FIXTURE",
        "SIMULATOR",
        "SENSOR_BRIDGE",
        "HUMAN_OPERATOR",
        "STATIC_SCENE",
        "UNKNOWN",
    }
)

_VALID_TRUST_DOMAIN_VALUES = frozenset(
    {"TEST", "SIMULATION", "DEVELOPMENT", "STAGING", "PHYSICAL_RUNTIME"}
)


def _normalize_optional_freshness_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("freshness_status must be a string or None")
    if value != value.strip():
        raise ValueError("freshness_status must not contain leading or trailing whitespace")
    if value not in _VALID_FRESHNESS_STATUS_VALUES:
        raise ValueError("freshness_status must be a valid WorldSnapshotFreshnessStatus value")
    return value


def _normalize_optional_admissibility_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("world_snapshot_admissibility_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError(
            "world_snapshot_admissibility_status must not contain surrounding whitespace"
        )
    if value not in _VALID_ADMISSIBILITY_STATUS_VALUES:
        raise ValueError("world_snapshot_admissibility_status must be a valid status value")
    return value


def _normalize_optional_trust_status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("world_snapshot_trust_status must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("world_snapshot_trust_status must not contain surrounding whitespace")
    if value not in _VALID_TRUST_STATUS_VALUES:
        raise ValueError("world_snapshot_trust_status must be a valid trust status value")
    return value


def _normalize_optional_source_type(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("source_type must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("source_type must not contain surrounding whitespace")
    if value not in _VALID_SOURCE_TYPE_VALUES:
        raise ValueError("source_type must be a valid WorldSnapshotSourceType value")
    return value


def _normalize_optional_trust_domain(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("trust_domain must be a string or None")
    if value != value.strip() or value == "":
        raise ValueError("trust_domain must not contain surrounding whitespace")
    if value not in _VALID_TRUST_DOMAIN_VALUES:
        raise ValueError("trust_domain must be a valid TrustDomain value")
    return value


def _normalize_optional_reason_code(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
        raise ValueError(f"{field_name} must be a machine-readable uppercase reason code")
    return normalized


def _normalize_capability_name(value: str) -> str:
    if value != value.strip():
        raise ValueError("capability must not contain leading or trailing whitespace")
    normalized = _normalize_required_text(value, "capability")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_optional_capability_name(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_capability_name(value)


def _normalize_capability_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of capability names")
    return tuple(sorted(_normalize_capability_name(value) for value in values))


def _normalize_fact_key_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of fact keys")
    return tuple(sorted(_normalize_fact_key(value) for value in values))


def _normalize_optional_fact_key_tuple(
    values: Iterable[str] | None,
    field_name: str,
) -> tuple[str, ...] | None:
    if values is None:
        return None
    return _normalize_fact_key_tuple(values, field_name)


def _normalize_optional_capability_scope(
    values: Iterable[str] | None,
) -> frozenset[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        raise ValueError("declared_capability_scope must be an iterable of capability names")
    return frozenset(_normalize_capability_name(value) for value in values)


def _normalize_optional_fact_keys(values: Iterable[str] | None) -> frozenset[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        raise ValueError("declared_fact_keys must be an iterable of fact keys")
    return frozenset(_normalize_fact_key(value) for value in values)


def _normalize_fact_key(value: str) -> str:
    if value != value.strip():
        raise ValueError("fact keys must not contain leading or trailing whitespace")
    normalized = _normalize_required_text(value, "fact key")
    if fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized) is None:
        raise ValueError("fact keys must be canonical identifiers")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be greater than or equal to 0")
    return value


def _normalize_confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("confidence must be a finite number")
    normalized = float(value)
    if not isfinite(normalized) or normalized < 0.0 or normalized > 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
    return normalized


def _normalize_default_decision(value: str | PolicyDefaultDecision) -> PolicyDefaultDecision:
    if isinstance(value, PolicyDefaultDecision):
        return value

    if value != value.strip():
        raise ValueError("default_decision must not contain leading or trailing whitespace")
    if value == PolicyDecision.ALLOW:
        raise ValueError("default_decision must not be ALLOW in Policy-v1")
    try:
        return PolicyDefaultDecision(value)
    except ValueError:
        raise ValueError("default_decision must be BLOCK or REQUIRE_REVIEW") from None


def _normalize_policy_decision(value: str | PolicyDecision) -> PolicyDecision:
    if isinstance(value, PolicyDecision):
        return value
    if value != value.strip():
        raise ValueError("decision must not contain leading or trailing whitespace")
    try:
        return PolicyDecision(value)
    except ValueError:
        raise ValueError("decision must be a valid PolicyDecision") from None


def _normalize_text_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of strings")

    normalized_values: list[str] = []
    for value in values:
        normalized_values.append(_normalize_required_text(value, field_name))
    return tuple(normalized_values)


def _reject_duplicate_rule_ids(rules: Iterable[PolicyRule]) -> None:
    seen_rule_ids: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen_rule_ids:
            raise ValueError("rules must not contain duplicate rule_id values")
        seen_rule_ids.add(rule.rule_id)


def _freeze_policy_mapping(values: Mapping[str, object]) -> Mapping[str, FrozenPolicyValue]:
    return _freeze_policy_items(values.items())


def _freeze_policy_items(items: Iterable[tuple[object, object]]) -> Mapping[str, FrozenPolicyValue]:
    frozen_values: dict[str, FrozenPolicyValue] = {}
    for key, value in items:
        if not isinstance(key, str):
            raise ValueError("policy metadata keys must be strings")
        frozen_values[key] = _freeze_policy_value(value)
    return MappingProxyType({key: frozen_values[key] for key in sorted(frozen_values)})


def _freeze_policy_value(value: object) -> FrozenPolicyValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("policy numeric values must be finite")
        return value
    if isinstance(value, list):
        items = cast(list[object], value)
        return tuple(_freeze_policy_value(item) for item in items)
    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(_freeze_policy_value(item) for item in items)
    if isinstance(value, set):
        items = cast(set[object], value)
        return frozenset(_freeze_policy_value(item) for item in items)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _freeze_policy_items(mapping.items())
    raise ValueError("policy metadata values must be primitive values or nested containers")
