# Aegis Master Specification - Phase 1 + Phase 2 + Phase 3 Part 1

## Purpose

Aegis is a safety gateway platform. Its Phase 1 component is **DIG — the Deterministic
Intent Gateway**: a pure-Python pipeline that converts untrusted, high-level intent into
a validated, auditable command plan.

Phase 2 begins Aegis's evolution from deterministic command integrity into deterministic
safety-policy admission. Phase 2 Part 1 added the immutable Policy-v1 contract
foundation. Phase 2 Part 2 added a pure evaluator over those contracts. Phase 2 Part 3
wired that evaluator into the pipeline admission path after audit and before final gate
approval. Phase 2 Part 4 hardens that boundary so pipeline approval requires enforced,
integrity-passed policy admission and cannot be skipped, forged, mismatched, or degraded.
Phase 2 Part 5 adds a deterministic freshness gate: ENFORCE approval now requires an
explicit world snapshot that is FRESH at an explicit caller-supplied evaluation time.
Phase 2 Part 6 adds a deterministic trust and attestation boundary: fresh but
unauthenticated world state cannot approve physical or DIG-relevant plans under ENFORCE
mode.
Phase 2 Part 7 hardens that boundary: arbitrary verifier objects and arbitrary trust
policies cannot become approval authority unless they pass deterministic verifier adapter
certification and trust-policy configuration validation. Phase 2 Part 8 adds world snapshot
admissibility before freshness and trust. Phase 2 Part 9 adds decision traces and approval
receipts to every orchestrated pipeline result. Phase 2 Part 10 adds a deterministic
scenario runner and evil-twin coverage gate above the sealed pipeline. Phase 2 Part 11
seals authority drift, policy versioning, context authority, resource bounds, and contract
coverage. Phase 3 Part 1 adds a deterministic non-executing adapter boundary and ROS 2
message mapping contract after allowed, receipt-valid pipeline results.

Aegis does not execute robot commands. The sealed pipeline produces receipt-bound decisions.
The Phase 3 Part 1 adapter boundary produces a checksum-bound `ExecutionAdapterEnvelope`
from an already allowed `PipelineResult`; it models ROS 2 mapping as data only and does not
claim real-world physical safety.

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

## Phase 2 Part 4 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Policy-backed approval predicate for `PipelineOutcome.ALLOWED` | Physical safety proof or certification |
| Admission integrity binding for audit ID, plan ID, plan checksum, policy result, world snapshot, and capability | Live sensors or world-state ingestion |
| Disabled/missing admission fail-closed before final gate | Warn-only, observe-only, or shadow approval modes |
| Strict security decision enum parsing | Unicode normalization of allow-equivalent decisions |
| Regression and adversarial bypass audit coverage | ROS 2, simulation, hardware, or runtime actuation |

Honest status after Part 4: Aegis can deterministically prove, by contract and test, that
`PipelineOutcome.ALLOWED` is policy-backed, SafetyCase-bound, admission-integrity-passed,
and gate-approved for the same audited plan.

Forbidden status after Part 4: Aegis proves semantic physical safety, collision safety,
runtime robot safety, or certification readiness.

---

## Phase 2 Part 5 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Deterministic `FreshnessPolicy` and `WorldSnapshotFreshnessResult` contracts | Real-world truth or source attestation |
| Freshness calculation from `evaluation_time_ms - WorldSnapshotStub.captured_at_ms` | Wall-clock, process, environment, sensor, middleware, or hardware time reads |
| Mandatory FRESH snapshot binding for ENFORCE approval paths | Optional `world_snapshot` on approval paths |
| Freshness checksum binding through `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord` | Trusting cached or caller-forged freshness evidence |
| Fail-closed handling for missing, stale, future-dated, malformed, or contradictory freshness evidence | Live world-state ingestion, simulation safety, ROS 2, hardware, or actuation |

Honest status after Part 5: Aegis can deterministically prove that an allowed pipeline
result was backed by caller-supplied snapshot evidence whose age was within the configured
freshness bound at the caller-supplied evaluation time.

Forbidden status after Part 5: Aegis proves that the snapshot reflects physical reality,
that a sensor was trustworthy, that middleware or simulation is safe, or that a robot action
is physically safe.

---

## Phase 2 Part 6 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Deterministic `WorldSnapshotEvidenceEnvelope`, `WorldSnapshotTrustPolicy`, attestation, verifier result, and trust result contracts | Proving physical-world truth or sensor correctness |
| Trust evaluation after freshness and before policy evaluation | Live evidence ingestion, middleware calls, filesystem reads, network calls, hardware reads, or wall-clock reads |
| Source ID, source type, trust domain, and capability allowlist checks | Dynamic trust registries, external policy lookup, or implicit trust from metadata |
| Optional required attestation verification through an injected deterministic verifier result | Implementing cryptographic service calls inside the core |
| Trust checksum binding through `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord` | ROS 2, simulation safety, collision checking, actuation, or certification |
| Fail-closed handling for missing, malformed, contradictory, disallowed, invalid, replayed, expired, or unsupported trust evidence | Treating freshness as trust |

Honest status after Part 6: Aegis can deterministically prove that an allowed pipeline
result was backed by fresh snapshot evidence whose provenance, declared source, domain,
capability, and required attestation satisfied an explicit trust policy.

Forbidden status after Part 6: Aegis proves physical-world truth, sensor correctness,
middleware safety, ROS safety, collision safety, actuator safety, or robot safety.

## Phase 2 Part 7 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Deterministic `AttestationVerifierAdapterMetadata` and `VerifierAdapterCertificationResult` contracts | Cryptographic service calls, key management, or external verifier registries |
| Required positive and negative verifier certification vectors with deterministic replay | Proving real-world truth or real cryptographic assurance beyond the injected adapter contract |
| Deterministic `TrustPolicyConfigValidationResult` for runtime domain, verifier metadata, capability, and ENFORCE context | Dynamic policy lookup, filesystem config loading, network config, or environment-derived config |
| Binding verifier certification/config checksums through trust result, policy result, SafetyCase, and admission record | ROS 2, simulation safety, collision checking, actuation, or certification |
| Fail-closed handling for uncertified verifier adapters and invalid trust-policy configuration | Treating arbitrary verifier output as approval authority |

Honest status after Part 7: Aegis can deterministically prove that an allowed pipeline
result was backed by fresh and trusted snapshot evidence, a certified verifier adapter,
and a valid trust-policy configuration bound into policy admission integrity.

Forbidden status after Part 7: Aegis proves physical-world truth, cryptographic soundness,
sensor correctness, middleware safety, ROS safety, collision safety, actuator safety, or
robot safety.

## Phase 2 Part 8 Scope

| In Scope | Out of Scope |
|----------|--------------|
| World snapshot admissibility before freshness/trust/policy | Semantic truth of world facts |
| Required checksum, fact, and capability-scope checks | Live sensing or middleware |
| Fail-closed missing, empty, malformed, undeclared, or mismatched snapshot evidence | Physical safety proof |

Honest status after Part 8: Aegis can deterministically reject structurally inadmissible
supplied world snapshot evidence before it can become policy authority.

## Phase 2 Part 9 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Deterministic `DecisionTrace` and `ApprovalReceipt` on pipeline results | Signed external receipts |
| Hash-linked stage checksums and predecessor links | Physical robot safety claims |
| Receipt validation for full and partial decision paths | Simulation or runtime actuation |

Honest status after Part 9: Aegis can make every orchestrated pipeline decision
reconstructable and tamper-evident at the return boundary.

## Phase 2 Part 10 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Immutable scenario contracts and canonical scenario matrix | Simulation engine or robot runtime |
| Real `run_pipeline` execution for every scenario | ROS 2, hardware, sensors, middleware, network, filesystem, async, or LLM calls |
| Outcome, reason, terminal-stage, trace, receipt, and checksum validation | Physical robot safety or semantic truth claims |
| Evil-twin rejection for forged, mismatched, replayed, overclaimed, confusable, checksum-corrupted, and direct-gate-only evidence | External signing or actuation |
| Required-category coverage gate | Replacing unit, contract, adversarial, or invariant tests |

Honest status after Part 10: Aegis can deterministically execute a closed scenario matrix
through the real pure pipeline and prove each scenario by both pipeline outcome and
receipt-bound decision path.

## Phase 2 Part 11 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Versioned policy checksums and context authority bindings | External policy registries or signing infrastructure |
| Contract drift and scenario coverage sentinels | Replacing contract, unit, adversarial, or invariant tests |
| Deterministic resource-bound validation | Runtime execution resource scheduling |
| Approval receipt policy/context bindings | Physical safety or certification claims |

Honest status after Part 11: Aegis can fail closed on approval-authority drift,
policy-version drift, missing context authority, resource-bound violations, and missing
coverage for required scenario categories.

## Phase 3 Part 1 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Immutable execution adapter and ROS 2 mapping contracts | ROS imports or runtime middleware dependencies |
| Pure `build_execution_adapter_envelope()` API after allowed pipeline result | Publishing topics, calling services, executing actions, or starting nodes |
| Explicit QoS, namespace, primitive, message type, field map, required fields, and forbidden fields as data | Motion planning, collision checking, simulation, teleoperation, visualization, fleet management |
| Adapter mapping checksums and adapter receipts | Physical safety, actuator safety, certification, or signed external authorization |
| Scenario category coverage for ADR-0015 adapter cases | Adding adapter execution into `run_pipeline()` |

Honest status after Part 1: Aegis can deterministically convert an allowed, receipt-valid
pipeline result into a non-executing adapter evidence envelope with explicit ROS 2 mapping
evidence.

---

## Non-Goals

- No production safety claims. Phase 1 correctness is bounded by typed contracts,
  deterministic replay, property-based invariant tests, unit/adversarial tests, and
  quality gates.
- No real-world robot safety certification.
- No claim that Policy-v1 contracts prove semantic physical safety.
- No claim that freshness proves real-world truth, source attestation, live sensing correctness, simulation safety, middleware safety, or actuator safety.
- No claim that trust attestation proves physical-world truth, sensor correctness,
  middleware safety, simulation safety, collision safety, actuator safety, or certification.
- No claim that a READY adapter envelope is execution permission, robot safety, simulation
    safety, or ROS middleware safety.
- No LLM SDK dependencies anywhere in the deterministic core.
- No ROS 2, hardware, or network I/O inside `src/aegis/`.

---

## Layer Architecture

```
[Intent Boundary]   →   [Validation]   →   [Planning]   →   [Audit]   →   [Gate]
   intent/               validation/        planning/        audit/         gate/
   (stub)
```

Phase 2 inserts freshness-, verifier-, config-, and trust-backed policy admission after
audit and before the final gate:

```text
RawIntent → ValidationResult → CommandPlan → AuditedPlan
    → WorldSnapshotFreshnessResult
    → VerifierAdapterCertificationResult
    → TrustPolicyConfigValidationResult
    → WorldSnapshotTrustResult
    → PolicyAdmissionRecord(PolicyEvaluationResult + SafetyCase)
    → GateDecision
```

Disabled mode is observable but non-approved and does not call the final gate. Enforced
mode requires explicit policy and capability inputs and fails closed when admission is
missing, denied, stale, mismatched, forged, malformed, contradictory, or internally errored.
ENFORCE approval additionally requires an explicit `world_snapshot`, an explicit
`evaluation_time_ms`, FRESH freshness binding, certified verifier binding, valid
trust-policy config binding, and TRUSTED evidence binding across policy result,
SafetyCase, and admission record.

The scenario runner lives above the orchestrator. It does not replace the pipeline and does
not create approvals. It executes `ScenarioDefinition` values through `run_pipeline`,
validates expectations with `ScenarioRunResult`, aggregates with `ScenarioSuiteResult`, and
uses `CoverageGateResult` to prove the required scenario categories are represented.

Phase 3 Part 1 adds a separate adapter boundary after the pipeline return value. It does not
modify `run_pipeline()` and does not execute runtime actions:

```text
PipelineResult(ALLOWED, receipt VALID)
    → ExecutionAdapterMapping
    → RuntimeTarget
    → Ros2MessageMapping
    → ExecutionAdapterEnvelope
```

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
| Execution adapter | `aegis.execution` | None | Phase 3 Part 1 non-executing adapter-boundary validation |

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
    validate WorldSnapshotStub freshness using caller-supplied evaluation_time_ms
    if freshness is not FRESH → non-approved PipelineResult, gate not reached
    certify injected attestation verifier adapter metadata and behavior
    if verifier is not CERTIFIED → non-approved PipelineResult, gate not reached
    validate WorldSnapshotTrustPolicy config for verifier metadata, runtime domain, and capability
    if trust policy config is not VALID → non-approved PipelineResult, gate not reached
    evaluate WorldSnapshotEvidenceEnvelope against WorldSnapshotTrustPolicy
    if trust is not TRUSTED → non-approved PipelineResult, gate not reached
    evaluate Policy + Capability + optional WorldSnapshotStub
    bind freshness, verifier/config authority, and trust evidence into PolicyEvaluationResult
    build SafetyCase bound to AuditedPlan audit ID, plan, policy result, world snapshot, capability, freshness, verifier/config authority, and trust
    assert PolicyAdmissionRecord integrity against AuditedPlan and SafetyCase
    if decision != ALLOW → non-approved PipelineResult, gate not reached
else:
    return PipelineOutcome.BLOCKED with disabled admission record, gate not reached
    ↓
gate_audited_plan(audited_plan) → GateDecision
    ↓
run_pipeline returns PipelineResult(..., gate_decision, policy_admission)
    ↓  [separate Phase 3 Part 1 API only]
build_execution_adapter_envelope(pipeline_result, adapter_mapping, target_runtime)
    ↓
ExecutionAdapterEnvelope(status=READY | BLOCKED | INVALID | ERROR)
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
25. Disabled mode is not represented as a policy `ALLOW` and cannot produce approval.
26. SafetyCase admission binding uses the actual audited plan ID produced by the pipeline.
27. `PipelineOutcome.ALLOWED` requires enforced policy `ALLOW`, SafetyCase binding,
    admission integrity `PASSED`, and matching allowed gate decision.
28. Forged, stale, mismatched, skipped, malformed, or contradictory admission records fail closed.
29. Security decision strings are exact; confusable, case-changed, or whitespace-marked `ALLOW` variants are rejected.
30. `PipelineOutcome.ALLOWED` requires freshness status `FRESH` for the admitted world snapshot.
31. Freshness age is computed only as `evaluation_time_ms - WorldSnapshotStub.captured_at_ms`.
32. `evaluation_time_ms` is caller-supplied; the deterministic core never derives it from wall-clock time.
33. Freshness snapshot identity, observed time, status, and checksum match across `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`.
34. Missing, stale, future-dated, malformed, contradictory, or unchecked freshness evidence fails closed before final gate approval.
35. `PipelineOutcome.ALLOWED` requires world snapshot trust status `TRUSTED` for the admitted world snapshot.
36. Trust result, evidence envelope, attestation, trust policy, source ID, source type, and trust domain bindings match across `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`.
37. Fresh but missing, unauthenticated, disallowed, malformed, contradictory, invalid, expired, replayed, unsupported, or non-TRUSTED evidence fails closed before policy evaluation can approve.
38. `PipelineOutcome.ALLOWED` requires verifier certification status `CERTIFIED` and trust-policy config status `VALID`.
39. Verifier certification checksum, verifier ID, verifier metadata checksum, and trust-policy config validation checksum match across `WorldSnapshotTrustResult`, `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`.
40. Missing, malformed, unsafe, non-deterministic, or uncertified verifier adapters fail closed before trust evaluation can approve.
41. Empty, wildcard, mismatched, disabled-attestation, or runtime-incompatible trust-policy configurations fail closed before trust evaluation can approve.
42. `ExecutionAdapterEnvelopeStatus.READY` requires an allowed, receipt-valid `PipelineResult`.
43. Non-allowed, receipt-invalid, checksum-mutated, or adapter-invalid inputs never produce a READY adapter envelope.
44. READY adapter envelopes bind policy checksum, context authority checksum, SafetyCase ID, audited plan ID, plan checksum, adapter mapping checksum, runtime target checksum, ROS 2 mapping checksum, QoS checksum, and adapter authority.
45. Non-ready adapter envelopes never carry a command payload.
46. ROS 2 mapping contracts are inert data and never import ROS packages, open middleware handles, publish topics, call services, execute actions, or start nodes.
47. Adapter field maps are explicit; no implicit runtime message fields, reflection, fuzzy matching, or middleware defaults are allowed.
48. Forbidden runtime override fields never produce a READY adapter envelope.

---

## Public API

```python
from aegis.pipeline import run_pipeline
from aegis.execution import build_execution_adapter_envelope
from aegis.contracts.intent import RawIntent
from aegis.contracts.context import ExecutionContext
from aegis.contracts.execution_adapter import ExecutionAdapterMapping
from aegis.contracts.ros2_mapping import RuntimeTarget, Ros2MessageMapping
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
    evaluation_time_ms=caller_supplied_evaluation_time_ms,
    world_snapshot_evidence=evidence_envelope,
    world_snapshot_trust_policy=trust_policy,
    attestation_verifier=verifier,
    runtime_trust_domain=runtime_domain,
)

adapter_envelope = build_execution_adapter_envelope(
    enforced,
    adapter_mapping,
    target_runtime,
)
# adapter_envelope.status: READY | BLOCKED | INVALID | ERROR
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

Policy admission hardening does **not** protect against:

- False but internally consistent caller-supplied evidence.
- Physical collision, dynamics, human-proximity hazards, or robot actuation outside the deterministic core.
- Direct consumers that misuse `gate_audited_plan` as full policy approval rather than receipt integrity verification.

World snapshot freshness does **not** protect against:

- Fresh but unauthenticated or disallowed evidence.
- Physical-world truth, sensor correctness, middleware safety, simulation safety, or actuation safety.

World snapshot trust does **not** protect against:

- A trusted source being wrong about the physical world.
- Sensor faults, perception errors, middleware faults, collision hazards, actuator faults, or certification requirements.
- Approval paths outside `run_pipeline` that ignore trust-backed policy admission.

Verifier certification and trust-policy config validation do **not** protect against:

- A certified verifier implementation being semantically wrong beyond the required deterministic vectors.
- Key management, cryptographic library defects, or external trust registry compromise.
- Physical-world truth, sensor correctness, middleware safety, collision hazards, actuator faults, or certification requirements.

Execution adapter envelopes and ROS 2 message mappings do **not** protect against:

- Physical collision, dynamics, actuator, middleware, simulator, or deployment hazards.
- A future runtime adapter ignoring the envelope contract.
- External signing, cryptographic identity, or authorization outside the deterministic evidence packet.
- ROS 2 package correctness, DDS behavior, node lifecycle behavior, or QoS behavior at runtime.

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

**Phase 3 next candidates:** runtime adapter test doubles, dry-run adapter receipts, and deterministic simulator boundary contracts.
**Later phases:** Adapter integration, simulation, formal verification, middleware, and
hardware work after the deterministic adapter authority boundary is proven independently.
