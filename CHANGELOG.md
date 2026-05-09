# Changelog

All notable changes to Aegis are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Verifier adapter and trust-policy configuration hardening for Phase 2 Part 7: deterministic `AttestationVerifierAdapterMetadata`, `VerifierAdapterCertificationResult`, `TrustPolicyConfigValidationResult`, required verifier certification vectors, runtime-domain config validation, and ENFORCE-mode blocking for missing, unsafe, malformed, non-deterministic, or uncertified verifier adapters and invalid trust-policy configs
- Trust authority evidence propagation through `WorldSnapshotTrustResult`, `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`, making `PipelineOutcome.ALLOWED` require certified verifier metadata and valid trust-policy config bindings in addition to FRESH and TRUSTED snapshot evidence
- Contract, integration, adversarial, and Hypothesis invariant tests proving arbitrary verifier objects, disabled-attestation policies, physical-runtime test sources, verifier key mismatches, and forged verifier/config admission bindings cannot produce approval
- World snapshot evidence trust and attestation boundary for Phase 2 Part 6: deterministic `WorldSnapshotEvidenceEnvelope`, `WorldSnapshotTrustPolicy`, `WorldSnapshotTrustResult`, source/domain/capability allowlist checks, injected attestation verifier results, and ENFORCE-mode blocking for fresh but missing, unauthenticated, disallowed, invalid, replayed, malformed, contradictory, or non-TRUSTED snapshot evidence
- Trust evidence propagation through `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`, making `PipelineOutcome.ALLOWED` require TRUSTED snapshot provenance and matching trust bindings in addition to FRESH snapshot evidence
- Contract, integration, adversarial, and Hypothesis invariant tests proving freshness does not imply trust, snapshot metadata cannot self-attest, trust bindings cannot be forged, and direct gate approval is not policy-backed approval
- World snapshot freshness gate for Phase 2 Part 5: deterministic `FreshnessPolicy`, `WorldSnapshotFreshnessResult`, freshness checksum binding, and ENFORCE-mode pipeline blocking for missing, stale, future-dated, malformed, contradictory, or unchecked snapshot evidence
- Freshness evidence propagation through `PolicyEvaluationResult`, `SafetyCase`, and `PolicyAdmissionRecord`, making `PipelineOutcome.ALLOWED` require FRESH snapshot identity, observed timestamp, status, and checksum bindings
- Contract, integration, adversarial, and Hypothesis invariant tests proving caller-supplied `evaluation_time_ms`, fail-closed freshness semantics, no wall-clock fallback, and rejection of reused or forged freshness evidence
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
- ENFORCE-mode approval paths now certify the injected verifier adapter and validate trust-policy configuration after freshness and before world snapshot trust evaluation
- ENFORCE-mode approval paths now require explicit world snapshot trust evidence, an explicit trust policy, and a TRUSTED trust result before policy evaluation can approve
- ENFORCE-mode approval paths now require an explicit `world_snapshot` and caller-supplied `evaluation_time_ms`; disabled or non-fresh admission paths remain non-approved and do not reach final gate approval
- Disabled or missing policy admission no longer preserves legacy approval; it returns an explicit non-approved disabled admission record and skips the final gate
- `RawIntent` now rejects bool priority values instead of accepting them as integers

### Removed
- Non-canonical `src/aegis/core/` and `src/aegis/sim/` scaffolding (replaced by DIG layer structure)

---

*Releases appear below this line once tagged.*
