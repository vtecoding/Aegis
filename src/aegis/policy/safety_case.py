"""Deterministic SafetyCase construction for Policy-v1 evaluation results."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from math import isfinite
from typing import cast

from aegis.contracts.policy import (
    Capability,
    Constraint,
    PolicyEvaluationResult,
    SafetyCase,
    WorldSnapshotStub,
    policy_evaluation_result_checksum,
)
from aegis.contracts.world_snapshot_trust import WorldSnapshotTrustResult

type CanonicalHashValue = (
    str | int | float | bool | None | list[CanonicalHashValue] | dict[str, CanonicalHashValue]
)

_RESERVED_EVIDENCE_FIELDS = frozenset(
    {
        "policy_id",
        "decision",
        "matched_rule_ids",
        "passed_constraints",
        "failed_constraints",
        "reasons",
        "capability_name",
        "capability_version",
        "plan_id",
        "plan_checksum",
        "policy_result_checksum",
        "world_snapshot_id",
        "world_snapshot_checksum",
        "constraint_evaluations",
        "world_snapshot_observed_at_ms",
        "freshness_result_checksum",
        "freshness_status",
        "world_snapshot_admissibility_status",
        "world_snapshot_admissibility_reason_code",
        "world_snapshot_admissibility_result_checksum",
        "world_snapshot_trust_status",
        "world_snapshot_trust_reason_code",
        "world_snapshot_trust_result_checksum",
        "evidence_envelope_checksum",
        "attestation_checksum",
        "trust_policy_checksum",
        "verifier_certification_checksum",
        "trust_policy_config_validation_checksum",
        "verifier_id",
        "verifier_metadata_checksum",
        "source_id",
        "source_type",
        "trust_domain",
    }
)


def build_safety_case(
    *,
    policy_result: PolicyEvaluationResult,
    audited_plan_id: str,
    world_snapshot: WorldSnapshotStub | None = None,
    evidence: Mapping[str, object] | None = None,
    plan_id: str | None = None,
    plan_checksum: str | None = None,
    capability: Capability | None = None,
    world_snapshot_observed_at_ms: int | None = None,
    freshness_result_checksum: str | None = None,
    freshness_status: str | None = None,
    trust_result: WorldSnapshotTrustResult | None = None,
) -> SafetyCase:
    """Build a deterministic SafetyCase for a Policy-v1 evaluation result.

    Args:
        policy_result: The policy evaluation result being explained.
        audited_plan_id: Caller-supplied audited plan identifier to bind.
        world_snapshot: Optional immutable evidence snapshot used by evaluation.
        evidence: Optional caller-supplied deterministic explanation evidence.
        plan_id: Optional command plan identifier to bind.
        plan_checksum: Optional audited plan checksum to bind.
        capability: Optional capability evaluated by policy admission.
        world_snapshot_observed_at_ms: Optional observed timestamp from the
            freshness gate (Phase 2 Part 5).
        freshness_result_checksum: Optional checksum from the freshness result
            (Phase 2 Part 5).
        freshness_status: Optional freshness status string (Phase 2 Part 5).
        trust_result: Optional deterministic world snapshot trust result to bind
            into the SafetyCase (Phase 2 Part 6).

    Returns:
        A SafetyCase with a deterministic SHA-256 identifier.

    Raises:
        ValueError: If the audited plan ID is empty, evidence contains unsupported
            values, or an ALLOW result has no meaningful constraint evidence.
    """
    normalized_audited_plan_id = _normalize_required_text(audited_plan_id, "audited_plan_id")
    supplied_evidence = dict(evidence or {})
    world_snapshot_id = world_snapshot.snapshot_id if world_snapshot is not None else None
    world_snapshot_checksum = world_snapshot.checksum if world_snapshot is not None else None
    capability_name = capability.name if capability is not None else None
    capability_version = capability.version if capability is not None else None
    result_checksum = policy_evaluation_result_checksum(policy_result)
    trust_fields = _trust_fields(trust_result)
    combined_evidence = _combined_safety_evidence(
        policy_result=policy_result,
        world_snapshot_id=world_snapshot_id,
        world_snapshot_checksum=world_snapshot_checksum,
        plan_id=plan_id,
        plan_checksum=plan_checksum,
        policy_result_checksum=result_checksum,
        capability_name=capability_name,
        capability_version=capability_version,
        supplied_evidence=supplied_evidence,
        world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
        freshness_result_checksum=freshness_result_checksum,
        freshness_status=freshness_status,
        trust_fields=trust_fields,
    )

    if policy_result.decision.value == "ALLOW" and not policy_result.passed_constraints:
        raise ValueError("ALLOW safety cases must include passed constraint evidence")

    safety_case_id = _safety_case_id(
        policy_result=policy_result,
        audited_plan_id=normalized_audited_plan_id,
        world_snapshot_id=world_snapshot_id,
        evidence=combined_evidence,
    )
    return SafetyCase(
        safety_case_id,
        policy_result,
        normalized_audited_plan_id,
        world_snapshot_id,
        combined_evidence,
        plan_id=plan_id,
        plan_checksum=plan_checksum,
        policy_result_checksum=result_checksum,
        world_snapshot_checksum=world_snapshot_checksum,
        capability_name=capability_name,
        capability_version=capability_version,
        world_snapshot_observed_at_ms=world_snapshot_observed_at_ms,
        freshness_result_checksum=freshness_result_checksum,
        freshness_status=freshness_status,
        world_snapshot_admissibility_status=policy_result.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=(
            policy_result.world_snapshot_admissibility_reason_code
        ),
        world_snapshot_admissibility_result_checksum=(
            policy_result.world_snapshot_admissibility_result_checksum
        ),
        world_snapshot_trust_status=trust_fields["world_snapshot_trust_status"],
        world_snapshot_trust_reason_code=trust_fields["world_snapshot_trust_reason_code"],
        world_snapshot_trust_result_checksum=trust_fields["world_snapshot_trust_result_checksum"],
        evidence_envelope_checksum=trust_fields["evidence_envelope_checksum"],
        attestation_checksum=trust_fields["attestation_checksum"],
        trust_policy_checksum=trust_fields["trust_policy_checksum"],
        verifier_certification_checksum=trust_fields["verifier_certification_checksum"],
        trust_policy_config_validation_checksum=trust_fields[
            "trust_policy_config_validation_checksum"
        ],
        verifier_id=trust_fields["verifier_id"],
        verifier_metadata_checksum=trust_fields["verifier_metadata_checksum"],
        source_id=trust_fields["source_id"],
        source_type=trust_fields["source_type"],
        trust_domain=trust_fields["trust_domain"],
    )


def canonicalise_for_hash(value: object) -> CanonicalHashValue:
    """Convert supported policy evidence into deterministic JSON-compatible data.

    Args:
        value: A supported primitive, container, or Policy-v1 contract object.

    Returns:
        A JSON-compatible value suitable for stable hashing.

    Raises:
        ValueError: If value contains unsupported objects or non-finite numbers.
    """
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
            raise ValueError("hash evidence numeric values must be finite")
        return value
    if isinstance(value, PolicyEvaluationResult):
        return {
            "decision": value.decision.value,
            "policy_id": value.policy_id,
            "matched_rule_ids": list(value.matched_rule_ids),
            "passed_constraints": list(value.passed_constraints),
            "failed_constraints": list(value.failed_constraints),
            "reasons": list(value.reasons),
            "world_snapshot_id": value.world_snapshot_id,
            "world_snapshot_observed_at_ms": value.world_snapshot_observed_at_ms,
            "freshness_result_checksum": value.freshness_result_checksum,
            "freshness_status": value.freshness_status,
            "world_snapshot_admissibility_status": value.world_snapshot_admissibility_status,
            "world_snapshot_admissibility_reason_code": (
                value.world_snapshot_admissibility_reason_code
            ),
            "world_snapshot_admissibility_result_checksum": (
                value.world_snapshot_admissibility_result_checksum
            ),
            "world_snapshot_trust_status": value.world_snapshot_trust_status,
            "world_snapshot_trust_reason_code": value.world_snapshot_trust_reason_code,
            "world_snapshot_trust_result_checksum": (value.world_snapshot_trust_result_checksum),
            "evidence_envelope_checksum": value.evidence_envelope_checksum,
            "attestation_checksum": value.attestation_checksum,
            "trust_policy_checksum": value.trust_policy_checksum,
            "verifier_certification_checksum": value.verifier_certification_checksum,
            "trust_policy_config_validation_checksum": (
                value.trust_policy_config_validation_checksum
            ),
            "verifier_id": value.verifier_id,
            "verifier_metadata_checksum": value.verifier_metadata_checksum,
            "source_id": value.source_id,
            "source_type": value.source_type,
            "trust_domain": value.trust_domain,
        }
    if isinstance(value, WorldSnapshotTrustResult):
        return {
            "status": value.status.value,
            "reason_code": value.reason_code,
            "world_snapshot_checksum": value.world_snapshot_checksum,
            "world_snapshot_admissibility_status": value.world_snapshot_admissibility_status,
            "world_snapshot_admissibility_reason_code": (
                value.world_snapshot_admissibility_reason_code
            ),
            "world_snapshot_admissibility_result_checksum": (
                value.world_snapshot_admissibility_result_checksum
            ),
            "evidence_envelope_checksum": value.evidence_envelope_checksum,
            "attestation_checksum": value.attestation_checksum,
            "trust_policy_checksum": value.trust_policy_checksum,
            "verifier_certification_checksum": value.verifier_certification_checksum,
            "trust_policy_config_validation_checksum": (
                value.trust_policy_config_validation_checksum
            ),
            "verifier_id": value.verifier_id,
            "verifier_metadata_checksum": value.verifier_metadata_checksum,
            "source_id": value.source_id,
            "source_type": value.source_type.value if value.source_type is not None else None,
            "trust_domain": value.trust_domain.value if value.trust_domain is not None else None,
            "capability": value.capability,
            "verification_result_checksum": value.verification_result_checksum,
            "evaluation_time_ms": value.evaluation_time_ms,
            "checksum": value.checksum,
        }
    if isinstance(value, Capability):
        return {
            "name": value.name,
            "version": value.version,
            "parameters": canonicalise_for_hash(value.parameters),
        }
    if isinstance(value, Constraint):
        return {
            "constraint_type": value.constraint_type,
            "parameters": canonicalise_for_hash(value.parameters),
            "required": value.required,
        }
    if isinstance(value, WorldSnapshotStub):
        return {
            "snapshot_id": value.snapshot_id,
            "captured_at_ms": value.captured_at_ms,
            "expires_at_ms": value.expires_at_ms,
            "source": value.source,
            "confidence": value.confidence,
            "facts": canonicalise_for_hash(value.facts),
            "checksum": value.checksum,
        }
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return _canonical_mapping(mapping)
    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return [canonicalise_for_hash(item) for item in items]
    if isinstance(value, list):
        items = cast(list[object], value)
        return [canonicalise_for_hash(item) for item in items]
    if isinstance(value, frozenset):
        items = cast(frozenset[object], value)
        canonical_items = [canonicalise_for_hash(item) for item in items]
        return sorted(canonical_items, key=_canonical_sort_key)
    if isinstance(value, set):
        items = cast(set[object], value)
        canonical_items = [canonicalise_for_hash(item) for item in items]
        return sorted(canonical_items, key=_canonical_sort_key)
    raise ValueError("hash evidence values must be primitive values or supported containers")


def _combined_safety_evidence(
    *,
    policy_result: PolicyEvaluationResult,
    world_snapshot_id: str | None,
    world_snapshot_checksum: str | None,
    plan_id: str | None,
    plan_checksum: str | None,
    policy_result_checksum: str,
    capability_name: str | None,
    capability_version: str | None,
    supplied_evidence: Mapping[str, object],
    world_snapshot_observed_at_ms: int | None = None,
    freshness_result_checksum: str | None = None,
    freshness_status: str | None = None,
    trust_fields: Mapping[str, str | None] | None = None,
) -> dict[str, object]:
    constraint_evaluations = supplied_evidence.get("constraint_evaluations", ())
    normalized_trust_fields = trust_fields or _trust_fields(None)

    combined: dict[str, object] = {
        "policy_id": policy_result.policy_id,
        "decision": policy_result.decision.value,
        "matched_rule_ids": policy_result.matched_rule_ids,
        "passed_constraints": policy_result.passed_constraints,
        "failed_constraints": policy_result.failed_constraints,
        "reasons": policy_result.reasons,
        "capability_name": capability_name,
        "capability_version": capability_version,
        "plan_id": plan_id,
        "plan_checksum": plan_checksum,
        "policy_result_checksum": policy_result_checksum,
        "world_snapshot_id": world_snapshot_id,
        "world_snapshot_checksum": world_snapshot_checksum,
        "constraint_evaluations": constraint_evaluations,
        "world_snapshot_observed_at_ms": world_snapshot_observed_at_ms,
        "freshness_result_checksum": freshness_result_checksum,
        "freshness_status": freshness_status,
        "world_snapshot_admissibility_status": (policy_result.world_snapshot_admissibility_status),
        "world_snapshot_admissibility_reason_code": (
            policy_result.world_snapshot_admissibility_reason_code
        ),
        "world_snapshot_admissibility_result_checksum": (
            policy_result.world_snapshot_admissibility_result_checksum
        ),
        "world_snapshot_trust_status": normalized_trust_fields["world_snapshot_trust_status"],
        "world_snapshot_trust_reason_code": normalized_trust_fields[
            "world_snapshot_trust_reason_code"
        ],
        "world_snapshot_trust_result_checksum": normalized_trust_fields[
            "world_snapshot_trust_result_checksum"
        ],
        "evidence_envelope_checksum": normalized_trust_fields["evidence_envelope_checksum"],
        "attestation_checksum": normalized_trust_fields["attestation_checksum"],
        "trust_policy_checksum": normalized_trust_fields["trust_policy_checksum"],
        "verifier_certification_checksum": normalized_trust_fields[
            "verifier_certification_checksum"
        ],
        "trust_policy_config_validation_checksum": normalized_trust_fields[
            "trust_policy_config_validation_checksum"
        ],
        "verifier_id": normalized_trust_fields["verifier_id"],
        "verifier_metadata_checksum": normalized_trust_fields["verifier_metadata_checksum"],
        "source_id": normalized_trust_fields["source_id"],
        "source_type": normalized_trust_fields["source_type"],
        "trust_domain": normalized_trust_fields["trust_domain"],
    }
    for key, value in supplied_evidence.items():
        if key not in _RESERVED_EVIDENCE_FIELDS:
            combined[key] = value
    canonicalise_for_hash(combined)
    return combined


def _trust_fields(trust_result: WorldSnapshotTrustResult | None) -> dict[str, str | None]:
    if trust_result is None:
        return {
            "world_snapshot_trust_status": None,
            "world_snapshot_trust_reason_code": None,
            "world_snapshot_trust_result_checksum": None,
            "evidence_envelope_checksum": None,
            "attestation_checksum": None,
            "trust_policy_checksum": None,
            "verifier_certification_checksum": None,
            "trust_policy_config_validation_checksum": None,
            "verifier_id": None,
            "verifier_metadata_checksum": None,
            "source_id": None,
            "source_type": None,
            "trust_domain": None,
        }
    return {
        "world_snapshot_trust_status": trust_result.status.value,
        "world_snapshot_trust_reason_code": trust_result.reason_code,
        "world_snapshot_trust_result_checksum": trust_result.checksum,
        "evidence_envelope_checksum": trust_result.evidence_envelope_checksum,
        "attestation_checksum": trust_result.attestation_checksum,
        "trust_policy_checksum": trust_result.trust_policy_checksum,
        "verifier_certification_checksum": trust_result.verifier_certification_checksum,
        "trust_policy_config_validation_checksum": (
            trust_result.trust_policy_config_validation_checksum
        ),
        "verifier_id": trust_result.verifier_id,
        "verifier_metadata_checksum": trust_result.verifier_metadata_checksum,
        "source_id": trust_result.source_id,
        "source_type": trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        "trust_domain": trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
    }


def _safety_case_id(
    *,
    policy_result: PolicyEvaluationResult,
    audited_plan_id: str,
    world_snapshot_id: str | None,
    evidence: Mapping[str, object],
) -> str:
    payload: dict[str, CanonicalHashValue] = {
        "policy_result": canonicalise_for_hash(policy_result),
        "audited_plan_id": audited_plan_id,
        "world_snapshot_id": world_snapshot_id,
        "evidence": canonicalise_for_hash(evidence),
    }
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _canonical_mapping(values: Mapping[object, object]) -> dict[str, CanonicalHashValue]:
    canonical: dict[str, CanonicalHashValue] = {}
    for key, value in values.items():
        if not isinstance(key, str):
            raise ValueError("hash evidence mapping keys must be strings")
        canonical[key] = canonicalise_for_hash(value)
    return {key: canonical[key] for key in sorted(canonical)}


def _canonical_sort_key(value: CanonicalHashValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


__all__ = ["build_safety_case", "canonicalise_for_hash"]
