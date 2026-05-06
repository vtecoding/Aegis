# Changelog

All notable changes to Aegis are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Policy admission hardening for Phase 2 Part 4: policy-backed approval predicate, explicit admission integrity checks, SafetyCase plan/policy/world/capability bindings, strict security decision enum parsing, and fail-closed handling for skipped, stale, forged, mismatched, malformed, errored, or contradictory admission records
- Contract, adversarial, integration, invariant, and regression tests proving `PipelineOutcome.ALLOWED` requires enforced policy admission, valid SafetyCase binding, admission integrity `PASSED`, and a matching allowed gate decision
- Pipeline policy admission wiring for Phase 2 Part 3: explicit `PolicyAdmissionInput` and `PolicyAdmissionRecord`, disabled legacy mode, enforced Policy-v1 evaluation after audit and before gate, SafetyCase binding to the actual audited plan ID, and fail-closed denial for policy `BLOCK`, `REQUIRE_REVIEW`, `INVALID`, `ERROR`, missing policy, and missing capability
- Contract, pipeline, adversarial, integration, and Hypothesis invariant tests for policy admission wiring, bypass resistance, gate interaction, deterministic SafetyCase binding, and disabled-mode observability
- Policy-v1 pure evaluator for deterministic Capability admission against immutable Policy rules, built-in fail-closed constraints, and deterministic SafetyCase generation
- Unit, adversarial, and Hypothesis invariant tests for Policy-v1 evaluator matching, constraint semantics, aggregation precedence, hostile metadata inertness, and SafetyCase canonical hashing
- Audit v1: deterministic `AuditedPlan` receipt wrapping any `CommandPlan` with a SHA-256 content checksum and a SHA-256 audit event identifier derived from checksum plus execution context
- Contract, unit, invariant, and adversarial tests for audit-v1 determinism, immutability, key-order invariance, and adversarial inputs
- Planning v1: immutable `CommandStep` and `CommandPlan` contracts, deterministic SHA-256 plan IDs, and one-step abstract command planning for valid `move`/`stop`/`inspect`/`wait` intents
- Contract, unit, invariant, and adversarial tests for planning-v1 determinism, mutation isolation, plan hashing, metadata dropping, and corrupted validation defenses
- Validation v1: schema and semantic validation for `RawIntent`, explicit JSON depth/key/string limits, and abstract `move`/`stop`/`inspect`/`wait` command vocabulary
- Unit, invariant, and adversarial tests for validation-v1 behavior
- Contracts v1 spine: `ExecutionContext`, JSON boundary types, `RawIntent`, validation result contracts, and typed Aegis errors
- Contract, invariant, and adversarial tests for deterministic contract behavior and boundary mutation protection
- Bootstrap tooling scaffold: `pyproject.toml`, `Makefile`, CI workflow, `.gitignore`
- Canonical `src/aegis/` DIG layer structure: `contracts/`, `intent/`, `validation/`, `planning/`, `audit/`, `gate/`
- `make verify` quality gate (pyright strict, ruff, pytest --cov, invariant suite)
- Bootstrap import test and invariant test

### Changed
- Disabled or missing policy admission no longer preserves legacy approval; it returns an explicit non-approved disabled admission record and skips the final gate
- `RawIntent` now rejects bool priority values instead of accepting them as integers

### Removed
- Non-canonical `src/aegis/core/` and `src/aegis/sim/` scaffolding (replaced by DIG layer structure)

---

*Releases appear below this line once tagged.*
