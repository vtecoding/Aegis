"""Audit contracts for deterministic plan receipts."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.aegis_planning import CommandPlan


@dataclass(frozen=True, slots=True)
class AuditedPlan:
    """Deterministic immutable audit receipt for a command plan.

    Both ``audit_id`` and ``checksum`` are deterministic SHA-256 hexadecimal
    digests derived from explicit plan content.  They must never be generated
    with ``uuid.uuid4()``, ``datetime.now()``, or any other non-deterministic
    source.

    Args:
        plan: The command plan this receipt covers.
        audit_id: Deterministic SHA-256 hash of the plan checksum and
            execution context fields (request_id, submitted_at,
            policy_version, run_id).
        checksum: Deterministic SHA-256 hash of the executable command steps only
            (step_type, parameters, sequence for each step). The plan_id and context
            fields are intentionally excluded; they are bound into audit_id instead.

    Raises:
        ValueError: If ``audit_id`` or ``checksum`` are empty strings.
    """

    plan: CommandPlan
    audit_id: str
    checksum: str

    def __post_init__(self) -> None:
        audit_id = self.audit_id.strip()
        if audit_id == "":
            raise ValueError("audit_id must be non-empty")

        checksum = self.checksum.strip()
        if checksum == "":
            raise ValueError("checksum must be non-empty")

        object.__setattr__(self, "audit_id", audit_id)
        object.__setattr__(self, "checksum", checksum)
