"""Execution context contract for deterministic Aegis runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Caller-injected metadata required by deterministic core contracts.

    Args:
        request_id: Caller-provided request identifier.
        submitted_at: Caller-provided UTC timestamp.
        policy_version: Caller-provided policy version string.
        run_id: Optional caller-provided run identifier.

    Raises:
        ValueError: If identifiers are empty, or if the timestamp is naive or
            not UTC.
    """

    request_id: str
    submitted_at: datetime
    policy_version: str
    run_id: str | None = None

    def __post_init__(self) -> None:
        request_id = self.request_id.strip()
        if request_id == "":
            raise ValueError("request_id must be non-empty")

        policy_version = self.policy_version.strip()
        if policy_version == "":
            raise ValueError("policy_version must be non-empty")

        submitted_offset = self.submitted_at.utcoffset()
        if self.submitted_at.tzinfo is None or submitted_offset is None:
            raise ValueError("submitted_at must be timezone-aware")
        if submitted_offset != timedelta(0):
            raise ValueError("submitted_at must be UTC")

        run_id = self.run_id.strip() if self.run_id is not None else None
        if run_id == "":
            raise ValueError("run_id must be non-empty when provided")

        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "policy_version", policy_version)
        object.__setattr__(self, "run_id", run_id)
