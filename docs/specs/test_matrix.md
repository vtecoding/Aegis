# Aegis Phase 1 + Policy-v1 Part 1 Test Matrix

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
| `test_policy_contracts.py` | INV-16, INV-17, INV-18, INV-19, INV-20, FM-12 |

### `tests/policy/`

| File | Contracts / Invariants Covered |
|------|-------------------------------|
| `test_policy_immutability.py` | INV-15, INV-16 — deep freeze and hostile metadata inertness |
| `test_policy_validation.py` | INV-18, INV-19, FM-12 — pure validation helper and determinism |

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

### `tests/integration/`

| File | Coverage |
|------|----------|
| `test_scenario_runner.py` | End-to-end pipeline for all scenario fixtures |

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
