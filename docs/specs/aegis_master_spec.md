# Aegis Master Specification — Phase 1 + Phase 2 Part 1

## Purpose

Aegis is a safety gateway platform. Its Phase 1 component is **DIG — the Deterministic
Intent Gateway**: a pure-Python pipeline that converts untrusted, high-level intent into
a validated, auditable command plan.

Phase 2 begins Aegis's evolution from deterministic command integrity into deterministic
safety-policy admission. Phase 2 Part 1 adds the immutable Policy-v1 contract foundation
only; it does not evaluate policies or prove real-world safety.

Aegis does not execute robot commands. Phase 1 produces a typed decision (`ALLOWED` or
`BLOCKED`) and an immutable audit receipt. Policy-v1 contracts prepare the next pure
admission layer without changing Phase 1 pipeline behaviour.

---

## Phase 1 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Intent boundary (`RawIntent`) | Intent parsing / NLU |
| Schema and semantic validation | Physical safety (bounds, hazards) |
| Deterministic command planning | Multi-step plans |
| SHA-256 audit receipt construction | Real-time audit streaming |
| Integrity-verification gate | Policy-based allow/block logic |
| Full Hypothesis invariant suite | ROS 2 / hardware integration |
| Scenario runner harness | LLM inference in core |
| Structured log event values | Log emission / sinks |
| Typed config injection | Environment variable loading in core |

---

## Phase 2 Part 1 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Immutable Policy-v1 contracts | Runtime policy enforcement |
| `src/aegis/policy/` package namespace | Policy evaluator wiring in `run_pipeline()` |
| Pure structural policy validation helper | Real world-state ingestion |
| `WorldSnapshotStub` evidence input contract | Sensors, simulation, collision checking |
| `PolicyEvaluationResult` and `SafetyCase` contracts | ROS 2, hardware, execution APIs |
| Fail-closed contract invariants | Real-world safety claims |

Honest status after Part 1: Aegis has deterministic immutable Policy-v1 contracts ready
for a future pure policy evaluator.

---

## Non-Goals

- No production safety claims. Phase 1 correctness is bounded by typed contracts,
  deterministic replay, property-based invariant tests, unit/adversarial tests, and
  quality gates.
- No real-world robot safety certification.
- No claim that Policy-v1 contracts prove semantic physical safety.
- No LLM SDK dependencies anywhere in the deterministic core.
- No ROS 2, hardware, or network I/O inside `src/aegis/`.

---

## Layer Architecture

```
[Intent Boundary]   →   [Validation]   →   [Planning]   →   [Audit]   →   [Gate]
   intent/               validation/        planning/        audit/         gate/
   (stub)
```

Future Phase 2 target flow inserts policy admission after audit and before the final gate:

```text
RawIntent → ValidationResult → CommandPlan → AuditedPlan
    → PolicyEvaluationResult → SafetyCase → GateDecision
```

Phase 2 Part 1 defines only the policy contracts needed for this future flow. It does
not wire policy evaluation into `run_pipeline()`.

Data flows forward only. No layer imports from a layer ahead of it. Cross-layer
communication uses typed contracts in `contracts/`.

| Layer | Package | Side Effects | Phase 1 Status |
|-------|---------|--------------|----------------|
| Intent | `aegis.intent` | None | Stub — namespace reserved |
| Validation | `aegis.validation` | None | Implemented |
| Planning | `aegis.planning` | None | Implemented |
| Audit | `aegis.audit` | None | Implemented |
| Gate | `aegis.gate` | Phase 2+ only | Implemented |
| Policy | `aegis.policy` | None | Contracts only |

---

## Data Flow

```
caller constructs RawIntent(command, parameters, source_id, priority, context)
    ↓
validate_intent(raw_intent) → ValidationResult
    ↓  [if invalid → PipelineOutcome.INVALID]
plan_validated_intent(validation_result) → CommandPlan
    ↓
build_audited_plan(plan) → AuditedPlan
    ↓
gate_audited_plan(audited_plan) → GateDecision
    ↓
run_pipeline returns PipelineResult(outcome, validation_result, plan, audited_plan, gate_decision)
```

---

## Core Invariants

1. Same `(RawIntent, ExecutionContext)` → same `PipelineResult`. Every time.
2. No hidden I/O inside `src/aegis/` core packages.
3. No `datetime.now()`, `uuid.uuid4()`, `random.*`, `os.environ`, filesystem reads,
   network calls, or database calls inside the deterministic core.
4. Unknown commands are blocked at the validation layer with `unsupported_command`.
5. Malformed boundary input raises `ValueError` at the contract boundary.
6. `AuditedPlan.checksum` is a SHA-256 of executable steps only.
7. `AuditedPlan.audit_id` is a SHA-256 of checksum + plan_id + execution context.
8. Gate recomputes both hashes from scratch — any post-audit mutation is detected.
9. The gate never mutates the `AuditedPlan` it receives.
10. Unexpected non-`AegisError` exceptions map to `PipelineOutcome.ERROR`.
11. Unknown capability names do not imply allow.
12. Unknown policy rules do not imply allow.
13. Policy default decision must not be `ALLOW`.
14. World snapshot stubs are immutable evidence inputs, not live sensor state.
15. `SafetyCase` explains a policy decision; it is not execution permission by itself.

---

## Public API

```python
from aegis.pipeline import run_pipeline
from aegis.contracts.intent import RawIntent
from aegis.contracts.context import ExecutionContext

result = run_pipeline(raw_intent, context)
# result.outcome: PipelineOutcome — ALLOWED | BLOCKED | INVALID | ERROR
# result.gate_decision: GateDecision | None
# result.audited_plan: AuditedPlan | None
```

---

## Threat Model

Aegis Phase 1 protects against:

| Threat | Mitigation |
|--------|------------|
| AI/LLM issuing unsupported commands | Validation allowlist; `unsupported_command` block |
| AI/LLM embedding hostile metadata in parameters | Planning layer strips non-semantic keys |
| Tampered audit receipt after construction | Gate recomputes both SHA-256 hashes |
| Non-deterministic pipeline output | All non-deterministic values injected via `ExecutionContext` |
| Silent failure swallowing | Typed `AegisError` hierarchy; `except Exception` only in narrow harness boundary |
| Config mutation in flight | `AegisConfig` is a frozen dataclass |
| Log side-effects corrupting core purity | Log events are value objects; emission is adapter concern |

Aegis Phase 1 does **not** protect against:

- A validly-constructed malicious `AuditedPlan` with correct hashes.
- Physical safety violations (out-of-bounds coordinates, collision paths).
- Adversarial execution contexts (future policy gate concern).

Policy-v1 contract foundation does **not** protect against:

- Missing or incorrect future policy evaluator logic.
- Stale or false world snapshot evidence.
- Real-world collision, dynamics, or human-proximity hazards.
- Any robot execution path outside the deterministic core.

---

## Failure Model

See `docs/specs/failure_modes.md`.

---

## Testing Requirements

| Tier | Location | Requirement |
|------|----------|-------------|
| Unit | `tests/unit/` | Every pure function; no I/O |
| Contract | `tests/contracts/` | Every contract invariant |
| Invariant | `tests/invariants/` | Hypothesis property-based; determinism proofs |
| Integration | `tests/integration/` | Full pipeline traversals |
| Adversarial | `tests/adversarial/` | Hostile inputs; required for a gateway |
| Regression | `tests/regression/` | One file per bug, named by issue number |

Coverage floor: 90% line coverage overall; 100% on `contracts/` and `errors.py`.

---

## Future Phases

**Phase 2 Part 2:** Pure Policy-v1 evaluator over explicit policy, audited plan, and
world snapshot inputs.
**Phase 3+:** Adapter integration, simulation, formal verification, middleware, and
hardware work after the deterministic policy core is proven independently.
