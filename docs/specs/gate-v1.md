# gate-v1 Specification

## Executive Summary

`gate-v1` is the first deterministic approval boundary after `audit-v1`. It
accepts an `AuditedPlan`, recomputes the audit-v1 checksum and audit ID, and
returns an immutable `GateDecision` that is `allowed` only when the receipt is
internally consistent.

The canonical Phase 1 pipeline is:

```text
RawIntent -> validate_intent -> plan_validated_intent -> build_audited_plan -> gate_audited_plan
```

`gate-v1` does not execute, simulate, publish, mutate, persist, log authority,
or create a new audit receipt. It only verifies whether an already-built audit
receipt still matches its embedded command plan.

As of Phase 2 Part 4, direct `gate_audited_plan(...).status == allowed` is not a full
pipeline approval claim. `PipelineOutcome.ALLOWED` also requires enforced policy admission,
a valid SafetyCase, passed admission integrity, and a gate decision bound to the same
audited plan.

## Goals

- Verify `AuditedPlan.checksum` by recomputing SHA-256 over executable-shaped command steps.
- Verify `AuditedPlan.audit_id` by recomputing SHA-256 over checksum, `plan_id`, and execution context.
- Return deterministic immutable `GateDecision` objects.
- Emit stable block reasons for checksum mismatch, audit ID mismatch, and malformed audited-plan shape.
- Block malformed public-boundary inputs deterministically when verification cannot be completed.
- Preserve audit-v1 meaning exactly.

## Non-Goals

- No command execution, ROS publishing, hardware calls, or simulation.
- No LLM, network, database, filesystem, environment, time, random, or UUID reads.
- No policy evaluation beyond audit receipt integrity.
- No policy-backed pipeline approval decision by itself.
- No scenario runner coupling or scenario metrics.
- No new audit receipt creation as a gate side effect.
- No second schema validator for `CommandPlan` or `RawIntent`.

## Architecture

`gate-v1` lives at the final Phase 1 layer boundary:

```text
intent/ -> validation/ -> planning/ -> audit/ -> gate/
```

The gate imports only upstream contracts and audit checksum functions:

- `AuditedPlan` from `aegis.contracts.aegis_audit`
- `GateDecision`, `GateDecisionStatus`, and `GateBlockReason` from `aegis.contracts.aegis_gate`
- `plan_checksum` and `plan_audit_id` from `aegis.audit.aegis_checksum`

Verification is ordered and deterministic:

1. Confirm the input is an `AuditedPlan` instance with readable `plan`, `checksum`, and `audit_id` fields.
2. Confirm the embedded plan is a `CommandPlan` with readable non-empty `plan_id`.
3. Recompute `expected_checksum = plan_checksum(audited_plan.plan)`.
4. Recompute `expected_audit_id = plan_audit_id(audited_plan.plan, expected_checksum)`.
5. Return `ALLOWED` only when both stored values match expected values.
6. Return `BLOCKED` with reasons in this order: `CHECKSUM_MISMATCH`, then `AUDIT_ID_MISMATCH`.
7. Return `BLOCKED` with `MALFORMED_AUDITED_PLAN` when deterministic recomputation cannot be completed.

This preserves the audit-v1 invariant:

```text
checksum = SHA-256({ steps })
audit_id = SHA-256({ checksum, plan_id, context })
```

## API / Schema

### `src/aegis/contracts/aegis_gate.py`

```python
class GateDecisionStatus(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class GateBlockReason(StrEnum):
    CHECKSUM_MISMATCH = "checksum_mismatch"
    AUDIT_ID_MISMATCH = "audit_id_mismatch"
    MALFORMED_AUDITED_PLAN = "malformed_audited_plan"


@dataclass(frozen=True, slots=True)
class GateDecision:
    status: GateDecisionStatus
    audit_id: str | None
    plan_id: str | None
    reasons: tuple[GateBlockReason, ...]
    checksum_verified: bool
    audit_id_verified: bool
```

Decision invariants:

- If `status == ALLOWED`, then `reasons == ()`.
- If `status == ALLOWED`, then `checksum_verified is True`.
- If `status == ALLOWED`, then `audit_id_verified is True`.
- If `status == ALLOWED`, then `audit_id is not None` and `plan_id is not None`.
- If `status == BLOCKED`, then `reasons` is non-empty.
- `GateDecision` is immutable.
- Reason ordering is deterministic.

### `src/aegis/gate/aegis_decision_gate.py`

```python
def gate_audited_plan(audited_plan: AuditedPlan) -> GateDecision:
    ...
```

Input: `AuditedPlan`.

Output: `GateDecision`.

Side effects: none.

Raises: no intentional public exception for malformed boundary input; malformed
inputs are represented as blocked decisions when deterministic verification
cannot be completed.

## Security, Scalability, Observability, Reliability

Security:

- Gate-v1 treats command steps as inert data and never executes them.
- Gate-v1 allowed status means audit receipt integrity only; callers that need DIG pipeline
    approval must use `run_pipeline` with enforced policy admission.
- Checksum mismatches block changed executable-shaped command content.
- Audit ID mismatches block changed receipt identity, plan ID, or execution context.
- Hostile metadata added after audit changes the steps payload and blocks integrity.
- Malformed public-boundary inputs return deterministic blocked decisions instead of uncontrolled exceptions where the shape cannot be verified.

Scalability:

- Gate-v1 performs O(n) canonicalization over command steps and their JSON-compatible parameters.
- It performs exactly two SHA-256 recomputations for a well-formed audited plan.
- It stores no global mutable state and performs no caching.

Observability:

- Gate-v1 exposes status, audit ID, plan ID, reason codes, and verification booleans as data.
- It does not log, persist, stream, or produce authority outside the returned decision.
- Scenario runner metrics are intentionally deferred to a later integration PR.

Reliability:

- Same input produces the same `GateDecision` repeatedly.
- The gate does not mutate `AuditedPlan`, `CommandPlan`, command steps, or context.
- Block reason ordering is stable across repeated calls.
- The decision contract rejects contradictory allowed or blocked states.

## Failure Modes

| Scenario | Gate-v1 behavior |
|---|---|
| Valid audited plan | `ALLOWED`, no reasons, both verification flags true |
| Command step changed after audit | `BLOCKED` with `CHECKSUM_MISMATCH` and `AUDIT_ID_MISMATCH` |
| `checksum` corrupted | `BLOCKED` with `CHECKSUM_MISMATCH` |
| `audit_id` corrupted | `BLOCKED` with `AUDIT_ID_MISMATCH` |
| Context changed after audit | `BLOCKED` with `AUDIT_ID_MISMATCH` only |
| Plan shape unreadable or not a `CommandPlan` | `BLOCKED` with `MALFORMED_AUDITED_PLAN` |
| Non-`AuditedPlan` object at runtime boundary | `BLOCKED` with `MALFORMED_AUDITED_PLAN` |
| Deterministic canonicalization cannot complete | `BLOCKED` with `MALFORMED_AUDITED_PLAN` |

## Validation Matrix

| Test file | Coverage |
|---|---|
| `tests/contracts/test_gate_contract.py` | Enums, decision invariants, immutability, reason ordering |
| `tests/unit/test_gate_decision_gate.py` | Allow/block behavior, corrupted checksum/audit ID, context tampering, malformed shape, no mutation, no scenario runner, no audit receipt creation |
| `tests/invariants/test_invariant_gate_determinism.py` | Repeated-call determinism, equivalent-plan determinism, no mutation, context separation, stable reasons |
| `tests/adversarial/test_gate_adversarial_inputs.py` | Mutated move targets, hostile metadata, step reorder, valid-looking corrupted hashes, context tampering, non-`AuditedPlan` misuse, malformed deterministic block |

## Alternatives Considered

1. Call `build_audited_plan(plan)` and compare the resulting receipt.
   Rejected because gate-v1 must not create a new audit receipt as a side effect or blur audit creation with verification.

2. Duplicate audit canonicalization inside `gate/`.
   Rejected because audit-v1 owns checksum and audit ID meaning. Gate-v1 must reuse `aegis.audit.aegis_checksum`.

3. Raise typed `GateError` for malformed inputs.
   Rejected for this public boundary. Malformed audited-plan misuse is represented as a deterministic blocked decision when verification cannot be completed.

4. Fully validate `CommandPlan` and `RawIntent` again inside gate-v1.
   Rejected because validation and planning contracts already own schema and semantic checks. Gate-v1 checks only enough shape to recompute audit integrity deterministically.

## Memory / Future Integration

Gate-v1 stores no memory and reads no external state. It returns a value object
that future layers can consume.

The next integration step can wire gate output into scenario-runner metrics, for
example `gate_allowed_count`, `gate_blocked_count`, and
`gate_integrity_mismatch_count`. That work is intentionally outside gate-v1 so
this PR remains a pure approval boundary after audit.