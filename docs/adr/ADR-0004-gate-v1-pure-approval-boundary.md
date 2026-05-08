# ADR-0004: Gate-v1 as a Pure Approval Boundary

## Status

Accepted — Phase 1

## Context

In a robot safety pipeline, the final layer before physical execution is the highest-risk
boundary. Three candidate designs were considered:

1. **Policy-evaluating gate** — the gate reads policy rules and decides allow/block based
   on intent semantics.
2. **Executing gate** — the gate actually drives robot actuators or publishes to a ROS topic.
3. **Integrity-verifying gate** — the gate recomputes and verifies audit receipt integrity,
   then returns a typed decision. Execution happens outside the deterministic core.

## Decision

Gate-v1 is an **integrity-verifying approval boundary** only. It:

- Accepts an `AuditedPlan`.
- Recomputes `plan_checksum` and `plan_audit_id` from scratch.
- Compares recomputed values to stored values in the `AuditedPlan`.
- Returns an immutable `GateDecision` (`ALLOWED` or `BLOCKED`) with typed reasons.
- **Does not execute**, simulate, publish, persist, log, or mutate anything.
- **Does not create a new audit receipt** — it only verifies an existing one.

Policy-based allow/block decisions (e.g. "is this command in the allowed set for this
robot?") are deferred to a future policy layer. Gate-v1's only policy is: the audit
receipt must be internally consistent.

## Consequences

**Positive:**
- Gate-v1 is a pure function: `gate_audited_plan(audited_plan) → GateDecision`.
- Tamper detection is automatic: any mutation of an `AuditedPlan` after it leaves the
  audit layer will produce a checksum mismatch and be blocked.
- No key material, no network call, no filesystem access — fully testable in isolation.
- The pattern is extensible: future gates can chain on top of `GateDecision` without
  modifying the integrity gate.

**Negative:**
- Gate-v1 does not enforce semantic safety (e.g. "don't move to coordinates outside
  the safe zone"). That is a Phase 2+ concern and requires a separate policy gate.
- The integrity check protects against post-audit tampering only. It does not protect
  against a malicious but valid `AuditedPlan` constructed from scratch with correct
  checksums.

## Alternatives Considered

**Gate executes robot commands directly:** Rejected. Mixing execution and integrity
verification in one layer violates the single-responsibility principle and makes the
gate untestable without hardware.

**Gate evaluates a policy DSL:** Deferred. Useful in Phase 2+ when per-robot or
per-environment policies are needed. Adding policy evaluation to Phase 1 would require
a policy language, policy storage, and policy versioning — all out of scope.

**Gate as an async publish step to ROS 2:** Explicitly rejected for all phases. The DIG
core must remain deterministic and pure. ROS 2 integration is an adapter concern.
