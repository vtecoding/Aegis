# Pipeline Orchestrator v1 Specification

## Summary

Pipeline Orchestrator v1 is the single deterministic public API that composes all five Phase 1
Aegis layers in their canonical order and returns a typed `PipelineResult`.  It is not an
executor, simulator, or robot adapter.  Its purpose is to provide a clean, importable integration
boundary for demos, CLI wrappers, future simulator adapters, and eventually robot-action layers.
Phase 2 Part 3 adds policy admission between audit and gate. Phase 2 Part 4 hardens that
boundary so final pipeline approval is impossible without valid enforced policy admission.
Phase 2 Part 5 adds deterministic world snapshot freshness before policy evaluation.
Phase 2 Part 6 adds deterministic world snapshot trust and attestation before policy
evaluation.
Phase 2 Part 7 adds deterministic verifier adapter certification and trust-policy
configuration validation before trust evaluation.
Phase 2 Part 9 adds deterministic decision traces and approval receipts so every
returned pipeline decision is reconstructable and tamper-evident.
Phase 2 Part 10 adds a scenario runner above the orchestrator; it consumes `PipelineResult`
evidence but does not change `run_pipeline` semantics.

---

## Goals

- Compose the Phase 1 pipeline in a single deterministic function:
  `RawIntent + ExecutionContext → validate_intent → plan_validated_intent → build_audited_plan → gate_audited_plan → PipelineResult`
- Return a typed, immutable `PipelineResult` that captures the outcome at every layer.
- Propagate all `AegisError` subclasses without swallowing them.
- Be fully deterministic: same inputs always produce the same `PipelineResult`.
- Provide the public entry point `run_pipeline(raw_intent, context, *, policy_admission=None) -> PipelineResult`.
- In policy-enforced mode, evaluate Policy-v1 after audit and before final gate approval.
- Require policy-backed admission integrity for any `PipelineOutcome.ALLOWED` result.
- In policy-enforced mode, require caller-supplied `evaluation_time_ms` and a FRESH world snapshot before policy evaluation can approve.
- In policy-enforced mode, require caller-supplied trust evidence and `TRUSTED` world
    snapshot provenance before policy evaluation can approve.
- In policy-enforced mode, require a certified verifier adapter and valid trust-policy
    configuration before trust evaluation can approve.
- Return a deterministic `DecisionTrace`, `ApprovalReceipt`, and
    `ApprovalReceiptValidationResult` for every orchestrated pipeline result.
- Require valid receipt integrity for any `PipelineOutcome.ALLOWED` result.

---

## Non-Goals

- No scenario fixtures — that is the scenario runner's job.
- No scenario verdicts or coverage gates inside `run_pipeline`; ADR-0013 keeps them in
    `aegis.scenarios` above the orchestrator.
- No simulation, no robot adapter, no execution of commands.
- No ROS 2, no hardware interfaces, no network or filesystem I/O.
- No LLM SDK dependencies.
- No retry logic, no timeouts, no async I/O.
- No mutable state across invocations.
- No CLI entry point in v1.
- No global policy, environment-loaded policy, filesystem-loaded policy, or dynamic policy registry.
- No wall-clock fallback for freshness. The core never derives `evaluation_time_ms` from system time.
- No proof that snapshot freshness means real-world truth, source attestation, live sensing correctness, simulation safety, middleware safety, or actuator safety.
- No proof that trusted snapshot evidence means physical-world truth, sensor correctness,
  middleware safety, simulation safety, collision safety, actuator safety, or certification.
- No proof that verifier certification implies real-world cryptographic soundness beyond
    the deterministic adapter contract and injected verifier implementation.
- No claim that approval receipts prove physical robot safety or semantic truth of world facts.
- No signed receipts or external receipt export in v1.

---

## Contracts

### `src/aegis/contracts/pipeline.py`

All models are frozen, slotted dataclasses.

#### `PipelineOutcome`

```python
class PipelineOutcome(StrEnum):
    ALLOWED  = "allowed"   # Plan passed gate — safe to hand off
    BLOCKED  = "blocked"   # Plan produced but gate rejected it
    INVALID  = "invalid"   # Validation failed — never planned
    ERROR    = "error"     # Unexpected non-AegisError exception
```

#### `PipelineResult`

| Field | Type | Description |
|-------|------|-------------|
| `outcome` | `PipelineOutcome` | Final pipeline outcome |
| `validation_result` | `ValidationResult \| None` | Validation outcome; `None` only on `ERROR` |
| `plan` | `CommandPlan \| None` | Command plan; populated when planning succeeded |
| `audited_plan` | `AuditedPlan \| None` | Audit receipt; populated when auditing succeeded |
| `gate_decision` | `GateDecision \| None` | Gate decision; populated when gate ran |
| `policy_admission` | `PolicyAdmissionRecord` | Disabled or enforced policy admission state |
| `decision_trace` | `DecisionTrace \| None` | Hash-linked stage trace produced by the orchestrator |
| `approval_receipt` | `ApprovalReceipt \| None` | Tamper-evident receipt binding the decision trace to pipeline evidence |
| `receipt_validation` | `ApprovalReceiptValidationResult \| None` | Machine-checkable receipt validation result |

**Outcome derivation rules:**
- `ALLOWED` — policy admission is `ENFORCE`, policy decision is `ALLOW`, SafetyCase and
    admission bindings pass integrity checks, `gate_decision.status == GateDecisionStatus.ALLOWED`,
    and approval receipt integrity is `VALID`
- `BLOCKED` — policy admission is disabled, missing, or denied; or the gate blocks after
    policy-backed admission
- `INVALID` — validation failed before planning, or policy admission produced `PolicyDecision.INVALID`
- `ERROR` — an unexpected non-`AegisError` exception was raised

`AegisError` subclasses (`ValidationError`, `PlanningError`, `AuditError`, `GateError`) are
**not** caught — they propagate to the caller.  Only unexpected exceptions produce `ERROR`.

---

## API

### `src/aegis/pipeline/__init__.py`

```python
def run_pipeline(
    raw_intent: RawIntent,
    context: ExecutionContext,
    *,
    policy_admission: PolicyAdmissionInput | None = None,
    evaluation_time_ms: int | None = None,
    freshness_policy: FreshnessPolicy = DEFAULT_FRESHNESS_POLICY,
    world_snapshot_evidence: WorldSnapshotEvidenceEnvelope | None = None,
    world_snapshot_trust_policy: WorldSnapshotTrustPolicy | None = None,
    attestation_verifier: AttestationVerifier | None = None,
    runtime_trust_domain: TrustDomain = TrustDomain.SIMULATION,
) -> PipelineResult:
    """Run raw intent through the full Phase 1 Aegis pipeline.

    Composes validate_intent → plan_validated_intent → build_audited_plan →
    optional world snapshot freshness → optional policy admission →
    gate_audited_plan → decision trace → approval receipt deterministically.

    In ENFORCE mode, evaluation_time_ms is required. It is caller-supplied and
    never derived from wall-clock time. Trust evidence, trust policy, certified verifier,
    and valid trust-policy config are also required before policy evaluation can approve.

    AegisError subclasses propagate to the caller unchanged.

    Returns:
        PipelineResult with outcome ALLOWED, BLOCKED, INVALID, or ERROR.
    """
```

---

## Status Determination

| Condition | `outcome` | Fields populated |
|-----------|-----------|-----------------|
| Validation failed | `INVALID` | `validation_result` |
| Validation passed, policy disabled or omitted | `BLOCKED` | validation, plan, audit, disabled policy record; no gate decision |
| Policy ENFORCE lacks world snapshot or evaluation time | `BLOCKED` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE has stale or future-dated snapshot | `BLOCKED` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE has malformed or contradictory freshness metadata | `INVALID` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE lacks trust evidence, trust policy, verifier, or required attestation | `BLOCKED` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE has uncertified verifier or invalid trust-policy config | `BLOCKED` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE has disallowed source/domain/capability or invalid attestation | `BLOCKED` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE has malformed or contradictory trust evidence | `INVALID` | validation, plan, audit, denied policy record; no gate decision |
| Policy ENFORCE returns ALLOW, integrity passes, and gate allows | `ALLOWED` | all layer fields plus enforced policy record |
| Policy ENFORCE returns ALLOW and gate allows, but receipt validation fails | `ERROR` | computed fields plus failed receipt validation; no approval |
| Policy ENFORCE denies before gate | `BLOCKED`, `INVALID`, or `ERROR` | validation, plan, audit, policy record |
| Policy ENFORCE allows but gate blocks | `BLOCKED` | validation, plan, audit, policy record, blocked gate decision |
| Unexpected non-`AegisError` exception | `ERROR` | as many as were computed before the exception |

---

## Error Propagation Policy

`run_pipeline` does **not** catch `AegisError` subclasses.  The caller (CLI, scenario runner,
future adapter) is responsible for handling typed Aegis errors.  This keeps the pipeline core
free from error-swallowing and preserves the audit trail semantics.

Only `except Exception` in a narrow recovery path may produce `PipelineOutcome.ERROR`.  This
is documented here and intentionally mirrors the scenario runner's harness boundary policy:
it exists so callers get a typed result instead of an unhandled exception for unforeseen
failures.

---

## Invariants

- `outcome == ALLOWED` implies `gate_decision is not None and gate_decision.status == "allowed"`
- `outcome == ALLOWED` implies policy admission is enforced, allowed, integrity-passed, and bound to the same audited plan as the gate decision
- `outcome == ALLOWED` implies freshness status is `FRESH` and the freshness checksum is bound through policy result, SafetyCase, and admission record
- `outcome == ALLOWED` implies trust status is `TRUSTED` and trust checksums/source/domain bindings are bound through policy result, SafetyCase, and admission record
- `outcome == ALLOWED` implies verifier certification status is `CERTIFIED`, trust-policy config status is `VALID`, and their checksums/metadata bindings are bound through policy result, SafetyCase, and admission record
- `outcome == ALLOWED` implies `approval_receipt.status == VALID` and `receipt_validation.status == VALID`
- `outcome == ALLOWED` implies the decision trace contains the full ordered chain: raw intent, validation, planning, audit, admissibility, freshness, verifier certification, trust-policy config, trust, policy evaluation, SafetyCase, admission, and gate decision
- `outcome == ALLOWED` implies every decision trace predecessor link, stage checksum, trace checksum, and approval receipt checksum matches canonical recomputation
- `outcome == ALLOWED` implies all receipt-bound identities match the concrete `PipelineResult` fields
- Blocked or invalid receipts must not contain fake checksums for stages that did not execute
- `outcome == BLOCKED` implies a blocked gate decision or denied enforced policy admission
- `outcome == INVALID` implies `plan is None and audited_plan is None and gate_decision is None`
    unless the invalid state is produced by policy admission or malformed freshness after audit
- `outcome == ERROR` implies no AegisError subclass was involved
- Same `raw_intent` + same `context` → same `PipelineResult`, always.
- `run_pipeline` does not mutate `raw_intent` or `context`.
- Policy `ALLOW` is necessary but not sufficient for final approval.
- Disabled policy admission is not a policy `ALLOW` result and cannot produce final approval.
- Admission records with stale, mismatched, forged, malformed, skipped, or contradictory bindings cannot produce final approval.
- Missing, stale, future-dated, malformed, contradictory, or unchecked freshness evidence cannot produce final approval.
- Missing, unauthenticated, disallowed, malformed, contradictory, invalid, replayed,
    unsupported, or non-TRUSTED trust evidence cannot produce final approval.
- Missing, malformed, unsafe, non-deterministic, or uncertified verifier adapters cannot
    produce final approval.
- Empty, wildcard, mismatched, disabled-attestation, or runtime-incompatible trust-policy
    configurations cannot produce final approval.
- `run_pipeline` never reads current time; freshness uses only caller-supplied `evaluation_time_ms`.
- `run_pipeline` never reads external trust state; trust evaluation uses only explicit
    evidence, explicit trust policy, certified verifier metadata, injected verifier output,
    and explicit runtime trust domain.

---

## Release Gate

```
outcome == ALLOWED for valid, supported intents only when enforced policy admission allows and gate integrity also allows
freshness_status == FRESH for every outcome == ALLOWED
world_snapshot_trust_status == TRUSTED for every outcome == ALLOWED
verifier_certification_status == CERTIFIED for every outcome == ALLOWED
trust_policy_config_status == VALID for every outcome == ALLOWED
approval_receipt_status == VALID for every outcome == ALLOWED
receipt_validation_status == VALID for every outcome == ALLOWED
decision_trace_full_chain_present for every outcome == ALLOWED
world_snapshot_freshness_wall_clock_reads = 0
world_snapshot_trust_external_state_reads = 0
disabled_policy_admission_allowed_count = 0
outcome == INVALID for all invalid or unsupported intents
gate_integrity_mismatch_count = 0 (via scenario runner)
deterministic replay passes
canonical ADR-0013 scenario suite passes through the scenario runner
scenario coverage gate includes every required category
```
