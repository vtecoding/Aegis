# Aegis Phase 1 + Policy-v1 Part 4 Test Matrix

Maps each invariant and failure mode to its test coverage across all test tiers.
"✓" = covered. "—" = not applicable for that tier.

---

## Invariant Coverage

| Invariant | Unit | Contract | Hypothesis | Adversarial | Integration |
|-----------|------|----------|------------|-------------|-------------|
| INV-01: Pipeline determinism | ✓ | ✓ | ✓ | — | ✓ |
| INV-02: No hidden I/O | — | — | ✓ | — | — |
| INV-03: Unknown commands blocked | ✓ | — | ✓ | ✓ | ✓ |
| INV-04: Malformed boundary rejected | — | ✓ | ✓ | ✓ | — |
| INV-05: Checksum binds steps only | ✓ | — | ✓ | ✓ | — |
| INV-06: Audit ID binds checksum+context | ✓ | — | ✓ | ✓ | — |
| INV-07: Gate cannot mutate plan | — | ✓ | ✓ | — | — |
| INV-08: Gate blocks tampered plan | ✓ | — | ✓ | ✓ | — |
| INV-09: ALLOWED requires gate ran | ✓ | ✓ | ✓ | — | ✓ |
| INV-10: INVALID implies no plan | ✓ | ✓ | — | ✓ | ✓ |
| INV-11: Validation side-effect-free | ✓ | — | ✓ | — | — |
| INV-12: Planning deterministic | ✓ | — | ✓ | ✓ | — |
| INV-13: AegisErrors propagate | ✓ | — | — | ✓ | — |
| INV-14: Unexpected → ERROR outcome | ✓ | — | — | ✓ | — |
| INV-15: Contracts immutable | — | ✓ | ✓ | ✓ | — |
| INV-16: Unknown capability no allow | — | ✓ | — | ✓ | — |
| INV-17: Unknown policy rule no allow | — | ✓ | — | — | — |
| INV-18: Policy default not ALLOW | — | ✓ | ✓ | — | — |
| INV-19: World snapshot evidence only | — | ✓ | ✓ | — | — |
| INV-20: SafetyCase not permission | — | ✓ | — | — | — |
| INV-21: No matching policy rule never allows | ✓ | — | ✓ | ✓ | — |
| INV-22: Unknown policy constraint never allows | ✓ | — | ✓ | ✓ | — |
| INV-23: Failed required constraint blocks | ✓ | — | ✓ | ✓ | — |
| INV-24: Failed optional constraint requires review | ✓ | — | ✓ | ✓ | — |
| INV-25: Policy evaluator has no hidden state reads | ✓ | — | — | ✓ | — |
| INV-26: SafetyCase ID deterministic | ✓ | — | — | — | — |
| INV-27: SafetyCase evidence not permission | ✓ | ✓ | — | — | — |
| INV-POLICY-WIRE-001: Enforced approval requires policy allow | ✓ | — | ✓ | — | ✓ |
| INV-POLICY-WIRE-002: Missing policy does not fall back | ✓ | — | ✓ | ✓ | — |
| INV-POLICY-WIRE-003: Missing capability does not fall back | ✓ | — | ✓ | — | — |
| INV-POLICY-WIRE-004: Policy allow cannot bypass gate | ✓ | — | — | ✓ | — |
| INV-POLICY-WIRE-005: Policy block prevents approval | ✓ | — | ✓ | ✓ | — |
| INV-POLICY-WIRE-006: Policy review prevents approval | ✓ | — | ✓ | ✓ | — |
| INV-POLICY-WIRE-007: Policy invalid prevents approval | ✓ | ✓ | — | — | — |
| INV-POLICY-WIRE-008: Policy error prevents approval | ✓ | — | — | — | — |
| INV-POLICY-WIRE-009: SafetyCase binds audited plan | ✓ | — | ✓ | ✓ | ✓ |
| INV-POLICY-WIRE-010: Metadata cannot override admission | ✓ | — | ✓ | ✓ | — |
| INV-POLICY-WIRE-011: Disabled is not policy allow | ✓ | ✓ | ✓ | ✓ | ✓ |
| INV-POLICY-WIRE-012: Admission visible in result | ✓ | ✓ | — | — | ✓ |
| INV-POLICY-HARDEN-001: ALLOWED requires policy-backed approval | ✓ | ✓ | ✓ | ✓ | ✓ |
| INV-POLICY-HARDEN-002: Admission integrity binds context | ✓ | ✓ | ✓ | ✓ | ✓ |
| INV-POLICY-HARDEN-003: Admission contradictions fail closed | ✓ | ✓ | — | ✓ | ✓ |
| INV-POLICY-HARDEN-004: Security decision strings are strict | — | ✓ | — | ✓ | — |

---

## Failure Mode Coverage

| Failure Mode | Unit | Contract | Adversarial | Integration |
|--------------|------|----------|-------------|-------------|
| FM-01: Invalid raw intent boundary | — | ✓ | ✓ | — |
| FM-02: Unsupported command | ✓ | — | ✓ | ✓ |
| FM-03: Malformed parameters | ✓ | — | ✓ | — |
| FM-04: Hostile metadata stripped | — | — | ✓ | ✓ |
| FM-05: Planning rejects invalid result | ✓ | — | ✓ | — |
| FM-06: Checksum mismatch blocked | ✓ | — | ✓ | — |
| FM-07: Audit ID mismatch blocked | ✓ | — | ✓ | — |
| FM-08: Malformed audited plan blocked | — | — | ✓ | — |
| FM-09: Unexpected exception → ERROR | ✓ | — | ✓ | — |
| FM-10: AegisError propagation | ✓ | — | ✓ | — |
| FM-11: Config invariant violation | ✓ | — | — | — |
| FM-12: Policy-v1 contract rejection | ✓ | ✓ | ✓ | — |
| FM-13: Policy-v1 evaluator fail closed | ✓ | — | ✓ | — |
| FM-14: SafetyCase evidence/hash failure | ✓ | ✓ | — | — |
| FM-15: Policy required but missing | ✓ | — | ✓ | — |
| FM-16: Capability required but missing | ✓ | — | — | — |
| FM-17: Policy blocks audited plan | ✓ | — | ✓ | — |
| FM-18: Policy requires review | ✓ | — | ✓ | — |
| FM-19: Policy admission invalid | ✓ | ✓ | — | — |
| FM-20: Policy evaluator error | ✓ | — | — | — |
| FM-21: SafetyCase build failure | ✓ | — | — | — |
| FM-22: Policy admission bypass attempt | ✓ | — | ✓ | — |
| FM-23: Policy allow with gate failure | ✓ | — | ✓ | — |
| FM-24: Disabled mistaken for allow | ✓ | ✓ | ✓ | ✓ |
| FM-25: Policy admission integrity mismatch | ✓ | ✓ | ✓ | ✓ |
| FM-26: Confusable security decision values | — | ✓ | ✓ | — |
| FM-27: Malformed evaluator output | — | — | ✓ | — |

---

## Test File → Invariant / FM Cross-Reference

### `tests/invariants/`

| File | Invariants Covered |
|------|--------------------|
| `test_invariant_pipeline_determinism.py` | INV-01, INV-09, INV-10 |
| `test_invariant_validation_determinism.py` | INV-03, INV-11 |
| `test_invariant_planning_determinism.py` | INV-12 |
| `test_invariant_audit_determinism.py` | INV-05, INV-06 |
| `test_invariant_gate_determinism.py` | INV-07, INV-08 |
| `test_invariant_contract_determinism.py` | INV-02, INV-04, INV-15 |
| `test_invariant_policy_contracts.py` | INV-18, INV-19, FM-12 |
| `test_invariant_policy_evaluator.py` | INV-21, INV-22, INV-23, INV-24 |
| `test_invariant_policy_admission.py` | INV-POLICY-WIRE-001 through INV-POLICY-WIRE-003, INV-POLICY-WIRE-005, INV-POLICY-WIRE-006, INV-POLICY-WIRE-009 through INV-POLICY-WIRE-011 |
| `test_policy_admission_invariants.py` | INV-POLICY-HARDEN-001 through INV-POLICY-HARDEN-004 |
| `test_invariant_bootstrap.py` | Package imports resolve cleanly |

### `tests/contracts/`

| File | Contracts / Invariants Covered |
|------|-------------------------------|
| `test_intent_contract.py` | INV-04, INV-15 — RawIntent boundary |
| `test_context_contract.py` | INV-15 — ExecutionContext boundary |
| `test_validation_contract.py` | INV-09, INV-10, INV-15 — ValidationResult |
| `test_planning_contract.py` | INV-15 — CommandStep, CommandPlan |
| `test_audit_contract.py` | INV-07, INV-15 — AuditedPlan |
| `test_gate_contract.py` | INV-07, INV-09, INV-15 — GateDecision |
| `test_pipeline_contract.py` | INV-09, INV-10, INV-15 — PipelineResult |
| `test_errors_contract.py` | AegisError hierarchy immutability |
| `test_json_types_contract.py` | JSON boundary type safety |
| `test_policy_contracts.py` | INV-16, INV-17, INV-18, INV-19, INV-20, FM-12, FM-14 |
| `test_policy_admission_contract.py` | PolicyAdmissionInput, PolicyAdmissionRecord, disabled record invariants, integrity assertions, strict admission decisions, INV-POLICY-WIRE-011, INV-POLICY-WIRE-012, INV-POLICY-HARDEN-002 through INV-POLICY-HARDEN-004 |

### `tests/policy/`

| File | Contracts / Invariants Covered |
|------|-------------------------------|
| `test_policy_immutability.py` | INV-15, INV-16 — deep freeze and hostile metadata inertness |
| `test_policy_validation.py` | INV-18, INV-19, FM-12 — pure validation helper and determinism |
| `test_policy_evaluator.py` | INV-21, INV-22, INV-23, INV-24, FM-13 — matching and aggregation |
| `test_policy_evaluator_constraints.py` | FM-13 — built-in constraint semantics |
| `test_policy_evaluator_safety_case.py` | INV-26, INV-27, FM-14 — SafetyCase generation and canonical hashing |
| `test_policy_evaluator_adversarial.py` | INV-21, INV-22, INV-23, INV-24, FM-13 — hostile metadata and fail-closed cases |

### `tests/unit/`

| File | Functions / Invariants Covered |
|------|-------------------------------|
| `test_validation_schema_validator.py` | FM-02, FM-03 — schema layer |
| `test_validation_semantic_validator.py` | FM-02, FM-03 — semantic layer |
| `test_planning_command_planner.py` | FM-05, INV-12 |
| `test_planning_plan_hasher.py` | INV-05, INV-06 |
| `test_audit_builder.py` | INV-05, INV-06 |
| `test_audit_checksum.py` | INV-05, INV-06 |
| `test_gate_decision_gate.py` | FM-06, FM-07, FM-08, INV-08 |
| `test_pipeline_orchestrator.py` | INV-01, INV-09, INV-10, INV-13, INV-14, FM-09, FM-10 |
| `tests/pipeline/test_policy_admission_wiring.py` | FM-15 through FM-21, INV-POLICY-WIRE-001 through INV-POLICY-WIRE-008, INV-POLICY-WIRE-011, INV-POLICY-WIRE-012 |
| `tests/pipeline/test_policy_admission_gate_interaction.py` | FM-17, FM-18, FM-23, INV-POLICY-WIRE-004 |
| `tests/pipeline/test_policy_admission_bypass.py` | FM-22, FM-24, INV-POLICY-WIRE-010, INV-POLICY-HARDEN-003 |
| `test_config.py` | FM-11 |
| `test_logging.py` | `AegisLogEvent`, `make_log_event`, `serialise_log_event` |
| `test_bootstrap_import.py` | Package import smoke test |
| `test_verify_script.py` | Quality gate runner integrity |

### `tests/adversarial/`

| File | Failure Modes / Invariants Covered |
|------|------------------------------------|
| `test_raw_intent_adversarial_values.py` | FM-01, INV-04 |
| `test_validation_adversarial_inputs.py` | FM-02, FM-03, INV-03 |
| `test_planning_adversarial_inputs.py` | FM-04, FM-05 |
| `test_audit_adversarial_inputs.py` | INV-05, INV-06 |
| `test_gate_adversarial_inputs.py` | FM-06, FM-07, FM-08, INV-08 |
| `test_pipeline_adversarial_inputs.py` | FM-09, FM-10, INV-01, INV-13, INV-14 |
| `test_scenario_runner_adversarial.py` | FM-04, INV-03 end-to-end |
| `test_policy_admission_adversarial_bypass.py` | FM-15, FM-17, FM-22, FM-24 through FM-27, INV-POLICY-WIRE-010, INV-POLICY-HARDEN-001 through INV-POLICY-HARDEN-004 |

### `tests/integration/`

| File | Coverage |
|------|----------|
| `test_scenario_runner.py` | End-to-end pipeline for all scenario fixtures |
| `test_pipeline_policy_admission.py` | ENFORCE mode end-to-end allow, block, review, invalid, error, SafetyCase, integrity failure, disabled non-approval, and gate approval |

### `tests/regression/`

| File | Coverage |
|------|----------|
| `test_phase2_part3_policy_admission_wiring.py` | Phase 2 Part 3 admission wiring remains enforced while Part 4 disabled mode fails closed |

---

## Coverage Targets

| Module / Package | Target |
|------------------|--------|
| `src/aegis/contracts/` | 100% |
| `src/aegis/errors.py` | 100% |
| `src/aegis/config.py` | 100% |
| `src/aegis/logging.py` | 100% |
| All other `src/aegis/` | ≥ 90% |
| Overall | ≥ 90% |
