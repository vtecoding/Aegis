"""Policy identity helpers for ADR-0014 governance checks."""

from __future__ import annotations

from aegis.contracts.aegis_policy import Policy, policy_identity_checksum

POLICY_IDENTITY_FIELDS = (
    "policy_id",
    "policy_version",
    "policy_schema_version",
    "policy_checksum",
    "policy_authority",
    "effective_from_ms",
    "supersedes_policy_checksum",
)
"""Closed set of policy identity fields required for approval paths."""

POLICY_CHECKSUM_FIELDS = (
    "policy_id",
    "policy_version",
    "policy_schema_version",
    "policy_authority",
    "effective_from_ms",
    "supersedes_policy_checksum",
    "rules",
    "capabilities",
    "default_decision",
    "metadata",
)
"""Fields consumed by the canonical policy checksum."""


def policy_identity_fields(policy: Policy) -> dict[str, str | int | None]:
    """Return the stable identity fields for a policy object."""
    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_schema_version": policy.policy_schema_version,
        "policy_checksum": policy.policy_checksum,
        "policy_authority": policy.policy_authority,
        "effective_from_ms": policy.effective_from_ms,
        "supersedes_policy_checksum": policy.supersedes_policy_checksum,
    }


def recompute_policy_checksum(policy: Policy) -> str:
    """Recompute the canonical checksum for a Policy-v1 object."""
    return policy_identity_checksum(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_schema_version=policy.policy_schema_version,
        policy_authority=policy.policy_authority,
        effective_from_ms=policy.effective_from_ms,
        supersedes_policy_checksum=policy.supersedes_policy_checksum,
        rules=policy.rules,
        capabilities=policy.capabilities,
        default_decision=policy.default_decision,
        metadata=policy.metadata,
    )


def policy_identity_errors(policy: Policy) -> tuple[str, ...]:
    """Return deterministic policy identity drift errors."""
    errors: list[str] = []
    if policy.policy_id == "":
        errors.append("POLICY_ID_MISSING")
    if policy.policy_version == "":
        errors.append("POLICY_VERSION_MISSING")
    if policy.policy_schema_version == "":
        errors.append("POLICY_SCHEMA_VERSION_MISSING")
    if policy.policy_authority == "":
        errors.append("POLICY_AUTHORITY_MISSING")
    if policy.policy_checksum != recompute_policy_checksum(policy):
        errors.append("POLICY_CHECKSUM_MISMATCH")
    return tuple(errors)


__all__ = [
    "POLICY_CHECKSUM_FIELDS",
    "POLICY_IDENTITY_FIELDS",
    "policy_identity_errors",
    "policy_identity_fields",
    "recompute_policy_checksum",
]
