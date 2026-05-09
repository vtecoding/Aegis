"""Shared deterministic freshness fixtures for policy admission tests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from aegis.contracts.policy import PolicyEvaluationResult, WorldSnapshotStub
from aegis.contracts.world_snapshot_admissibility import validate_world_snapshot_admissibility
from aegis.contracts.world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    WorldSnapshotFreshnessResult,
    validate_world_snapshot_freshness,
)

FRESH_OBSERVED_AT_MS = 1_000_000
FRESH_EVALUATION_TIME_MS = 1_000_500
FRESH_EXPIRES_AT_MS = 1_010_000
FRESH_SNAPSHOT_ID = "snapshot-fresh"
FRESH_SNAPSHOT_CHECKSUM = "snapshot-checksum-fresh"
FRESH_REQUESTED_CAPABILITY = "locomotion.translation"
FRESH_DECLARED_CAPABILITY_SCOPE = ("locomotion.translation",)


def fresh_world_snapshot(
    snapshot_id: str = FRESH_SNAPSHOT_ID,
    *,
    observed_at_ms: int = FRESH_OBSERVED_AT_MS,
    expires_at_ms: int = FRESH_EXPIRES_AT_MS,
    confidence: object = 1.0,
    facts: Mapping[str, object] | None = None,
    checksum: str | None = FRESH_SNAPSHOT_CHECKSUM,
    declared_capability_scope: Iterable[str] | None = FRESH_DECLARED_CAPABILITY_SCOPE,
    declared_fact_keys: Iterable[str] | None = None,
) -> WorldSnapshotStub:
    """Return a deterministic world snapshot that is fresh at the shared eval time."""
    return WorldSnapshotStub(
        snapshot_id,
        observed_at_ms,
        expires_at_ms,
        "fixture",
        confidence,
        facts,
        checksum=checksum,
        declared_capability_scope=declared_capability_scope,
        declared_fact_keys=declared_fact_keys,
    )


def fresh_policy_context(extra: Mapping[str, object] | None = None) -> dict[str, object]:
    """Return deterministic evaluator context aligned with the shared fresh snapshot."""
    context: dict[str, object] = {"requested_at_ms": FRESH_EVALUATION_TIME_MS}
    if extra is not None:
        context.update(extra)
    return context


def fresh_world_snapshot_result(
    snapshot: WorldSnapshotStub | None = None,
    *,
    evaluation_time_ms: int = FRESH_EVALUATION_TIME_MS,
    requested_capability: str = FRESH_REQUESTED_CAPABILITY,
) -> WorldSnapshotFreshnessResult:
    """Return the deterministic freshness result for a fresh test snapshot."""
    snapshot_value = snapshot or fresh_world_snapshot()
    admissibility_result = validate_world_snapshot_admissibility(
        snapshot_value,
        requested_capability=requested_capability,
    )
    return validate_world_snapshot_freshness(
        snapshot_value,
        evaluation_time_ms=evaluation_time_ms,
        freshness_policy=DEFAULT_FRESHNESS_POLICY,
        admissibility_result=admissibility_result,
    )


def bind_policy_result_to_freshness(
    policy_result: PolicyEvaluationResult,
    freshness_result: WorldSnapshotFreshnessResult | None = None,
) -> PolicyEvaluationResult:
    """Return a PolicyEvaluationResult carrying the supplied FRESH binding."""
    result = freshness_result or fresh_world_snapshot_result()
    return PolicyEvaluationResult(
        policy_result.decision,
        policy_result.policy_id,
        policy_result.matched_rule_ids,
        policy_result.passed_constraints,
        policy_result.failed_constraints,
        policy_result.reasons,
        policy_version=policy_result.policy_version,
        policy_schema_version=policy_result.policy_schema_version,
        policy_checksum=policy_result.policy_checksum,
        policy_authority=policy_result.policy_authority,
        context_authority_checksum=policy_result.context_authority_checksum,
        world_snapshot_id=result.snapshot_id,
        world_snapshot_observed_at_ms=result.observed_at_ms,
        freshness_result_checksum=result.checksum,
        freshness_status=result.status.value,
        world_snapshot_admissibility_status=result.world_snapshot_admissibility_status,
        world_snapshot_admissibility_reason_code=result.world_snapshot_admissibility_reason_code,
        world_snapshot_admissibility_result_checksum=(
            result.world_snapshot_admissibility_result_checksum
        ),
    )


__all__ = [
    "FRESH_EVALUATION_TIME_MS",
    "FRESH_EXPIRES_AT_MS",
    "FRESH_OBSERVED_AT_MS",
    "FRESH_REQUESTED_CAPABILITY",
    "FRESH_DECLARED_CAPABILITY_SCOPE",
    "FRESH_SNAPSHOT_CHECKSUM",
    "FRESH_SNAPSHOT_ID",
    "bind_policy_result_to_freshness",
    "fresh_policy_context",
    "fresh_world_snapshot",
    "fresh_world_snapshot_result",
]
