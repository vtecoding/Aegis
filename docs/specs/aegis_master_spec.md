# Aegis Master Specification — Phase 1 + Phase 2 Part 3

## Purpose

Aegis is a safety gateway platform. Its Phase 1 component is **DIG — the Deterministic
Intent Gateway**: a pure-Python pipeline that converts untrusted, high-level intent into
a validated, auditable command plan.

Phase 2 begins Aegis's evolution from deterministic command integrity into deterministic
safety-policy admission. Phase 2 Part 1 added the immutable Policy-v1 contract
foundation. Phase 2 Part 2 added a pure evaluator over those contracts. Phase 2 Part 3
wires that evaluator into the pipeline admission path after audit and before final gate
approval when policy enforcement is explicitly requested.

Aegis does not execute robot commands. Phase 1 produces a typed decision (`ALLOWED` or
`BLOCKED`) and an immutable audit receipt. Policy-v1 contracts, the pure evaluator, and
pipeline admission wiring provide deterministic policy admission over supplied evidence
without claiming real-world physical safety.

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

## Phase 2 Part 2 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Pure Policy-v1 evaluator in `aegis.policy` | `run_pipeline()` policy enforcement |
| Exact capability-to-rule matching | Wildcards, regex, fuzzy, or semantic matching |
| Built-in deterministic constraint evaluators | Dynamic plugins or external registries |
| Optional caller-supplied context freezing | Environment-variable or current-time reads |
| Optional `WorldSnapshotStub` evidence evaluation | Live sensors, simulation, or middleware |
| Deterministic `SafetyCase` generation | Execution permission or legal proof packs |

Honest status after Part 2: Aegis can deterministically evaluate a declared capability
against declared Policy-v1 rules and immutable supplied evidence, producing a
`PolicyEvaluationResult` and explanatory `SafetyCase`.

Policy-v1 evaluator output is a policy admission decision over provided evidence. It is
not proof of real-world physical safety.

---

## Phase 2 Part 3 Scope

| In Scope | Out of Scope |
|----------|--------------|
| `PolicyAdmissionInput` and `PolicyAdmissionRecord` contracts | Global/default policy state |
| Explicit `DISABLED` and `ENFORCE` admission modes | Shadow, observe, warn-only modes |
| Policy evaluation after `AuditedPlan` creation | Policy evaluation before audit |
| SafetyCase binding to the actual `AuditedPlan.audit_id` | Caller-forged audited plan IDs |
| Policy denial preventing gate approval | Policy `ALLOW` bypassing gate integrity |
| PipelineResult policy admission observability | Log-only admission observability |

Honest status after Part 3: Aegis can explicitly enforce deterministic Policy-v1 admission
inside the pipeline before final gate approval. Policy `ALLOW` is necessary but not
sufficient because the existing gate must also pass.

Forbidden status after Part 3: Aegis proves a robot action is physically safe.

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

Phase 2 Part 3 inserts policy admission after audit and before the final gate:

```text
RawIntent → ValidationResult → CommandPlan → AuditedPlan
    → PolicyAdmissionRecord(PolicyEvaluationResult + SafetyCase) → GateDecision
```

Disabled mode preserves legacy Phase 1 gate behaviour. Enforced mode requires explicit
policy and capability inputs and fails closed when admission is missing or denied.

Data flows forward only. No layer imports from a layer ahead of it. Cross-layer
communication uses typed contracts in `contracts/`.

| Layer | Package | Side Effects | Phase 1 Status |
|-------|---------|--------------|----------------|
| Intent | `aegis.intent` | None | Stub — namespace reserved |
| Validation | `aegis.validation` | None | Implemented |
| Planning | `aegis.planning` | None | Implemented |
| Audit | `aegis.audit` | None | Implemented |
| Gate | `aegis.gate` | Phase 2+ only | Implemented |
| Policy | `aegis.policy` | None | Pure evaluator implemented and wired through pipeline admission |

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
if policy_admission.mode == ENFORCE:
    evaluate Policy + Capability + optional WorldSnapshotStub
    build SafetyCase bound to AuditedPlan.audit_id
    if decision != ALLOW → non-approved PipelineResult, gate not reached
    ↓
gate_audited_plan(audited_plan) → GateDecision
    ↓
run_pipeline returns PipelineResult(..., gate_decision, policy_admission)
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
16. No matching Policy-v1 rule ever produces `ALLOW`.
17. Unknown Policy-v1 constraints never produce `ALLOW`.
18. Failed required constraints always produce `BLOCK`.
19. Failed optional constraints produce `REQUIRE_REVIEW` unless a required failure blocks.
20. Policy-v1 evaluator never reads current time, environment, files, network, or live state.
21. `SafetyCase.safety_case_id` is deterministic over explicit inputs.
22. In policy ENFORCE mode, final approval is impossible without `PolicyDecision.ALLOW`.
23. Policy `ALLOW` cannot bypass gate checksum or audit ID verification.
24. Missing policy or capability in ENFORCE mode never falls back to legacy approval.
25. Disabled mode is not represented as a policy `ALLOW`.
26. SafetyCase admission binding uses the actual audited plan ID produced by the pipeline.

---

## Public API

```python
from aegis.pipeline import run_pipeline
from aegis.contracts.intent import RawIntent
from aegis.contracts.context import ExecutionContext
from aegis.contracts.policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.policy import build_safety_case, evaluate_policy, evaluate_policy_with_safety_case

result = run_pipeline(raw_intent, context)
# result.outcome: PipelineOutcome — ALLOWED | BLOCKED | INVALID | ERROR
# result.gate_decision: GateDecision | None
# result.audited_plan: AuditedPlan | None
# result.policy_admission: PolicyAdmissionRecord

enforced = run_pipeline(
    raw_intent,
    context,
    policy_admission=PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=policy,
        capability=capability,
        world_snapshot=snapshot,
    ),
)
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

- Stale or false world snapshot evidence.
- Real-world collision, dynamics, or human-proximity hazards.
- Any robot execution path outside the deterministic core.

Policy-v1 evaluator does **not** protect against:

- Incorrect, stale, or false evidence supplied by a caller.
- Real-world collision, dynamics, or human-proximity hazards outside the stub data.
- Missing future pipeline policy wiring.
- Treating a SafetyCase as execution permission.

Pipeline policy admission wiring does **not** protect against:

- False evidence supplied by a caller.
- Physical collision, dynamics, human-proximity hazards, or robot actuation outside the deterministic core.
- Any approval path outside `run_pipeline` that does not explicitly use policy admission.

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

**Phase 2 Part 4 candidate:** Policy-gate hardening or deterministic capability extraction.
**Phase 3+:** Adapter integration, simulation, formal verification, middleware, and
hardware work after the deterministic policy core is proven independently.
