# Changelog

All notable changes to Aegis are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Audit remediation hardening for release-gate and repository authority integrity:
  `scripts/verify.py` now fails closed on required-gate failure markers and malformed/missing
  structured coverage evidence, CI adds an independent coverage sanity step, and
  `InMemoryApprovalLedgerRepository` read APIs now return detached snapshot/head objects to
  prevent external mutation of repository-owned canonical state.
- Regression coverage for false-pass and detached-read mutation classes:
  verify-stage aggregation tests, coverage-fail-closed tests, detached-read adversarial tests,
  and CAS behavior checks after detached reads.
- Approval-ledger repository contract boundary for Phase 3 / ADR-0027: deterministic
  `ApprovalLedgerRepositoryAuthorityEvidence` and checksum-bound `RepositoryCommitResult`,
  explicit repository interface semantics (`read_current_state`, `propose_append`,
  `commit_transition`), and `InMemoryApprovalLedgerRepository` reference adapter enforcing
  compare-and-swap commit proofs, stale/lost/fork/rollback/cross-epoch rejection, forged transition
  blocking, and unavailable-repository fail-closed behavior without introducing durable storage
- Contract, integration, adversarial, invariant, and governance coverage for ADR-0027 including
  repository checksum-field sentinels, scenario category registration, adapter authority manifest
  registration, and deterministic proof checks for CAS commit obligations
- Canonical approval-ledger state boundary for Phase 3 / ADR-0026: checksum-bound
  `ApprovalLedgerStateSnapshot`, `ApprovalLedgerStateTransition`, and `LedgerStateValidationResult`
  contracts; deterministic `build_/validate_` state snapshot and transition functions; optional
  `append_to_approval_ledger_state()` helper; and quarantine-release wiring for
  `approval_ledger_state_snapshot`, `approval_ledger_state_source_id`, and
  `approval_ledger_state_enforced` with explicit
  `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID` and
  `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED` fail-closed reasons
- Governance, scenario, and authority-manifest coverage for ADR-0026 including strict field
  sentinels, canonical-state scenario categories (valid, stale/forked, rollback/skip, cross-epoch
  graft, source drift), and adapter manifest registration for state snapshot, state transition,
  and validation result contracts
- Contract, integration, adversarial, invariant, and governance tests proving canonical state
  replay resistance, head/snapshot/epoch/source binding, transition monotonicity, constructor
  hardening, and enforced-mode state-snapshot requirement behavior
- Ledger head, epoch manifest, and enforced release mode for Phase 3 / ADR-0025:
  `ApprovalLedgerHead` binds epoch, context authority, chain tip, and genesis in a
  checksum-bound head contract; `build_approval_ledger_head()` validates the prior chain and
  emits the canonical head; `append_to_approval_ledger_head()` returns an
  `ApprovalLedgerAppendResult` (new entry + new head + chain validation) in one atomic step;
  `validate_approval_ledger_head()` returns `VALID`/`BLOCKED` with a closed `ApprovalLedgerHeadReason`;
  `LedgerEpochManifest` binds one session epoch to context authority and backend admission;
  `evaluate_quarantine_release()` gains `approval_ledger_head` and `approval_ledger_session_epoch`
  kwargs and returns `COMMAND_QUARANTINE_APPROVAL_LEDGER_ENFORCED_MODE_BYPASS` when a head is
  supplied but prior entries are `None`, or `COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID`
  when head validation fails
- Contract, integration, adversarial, invariant, and governance tests proving head checksum
  determinism, epoch isolation, context authority binding, tip and sequence enforcement, stale
  head rejection, cross-context grafting rejection, direct construction blocking, enforced-mode
  bypass blocking, and scenario category coverage for all five ADR-0025 categories
- Deterministic tamper-evident approval ledger for Phase 3 / ADR-0024: canonical genesis head,
  hash-linked `ApprovalLedgerEntry` rows binding each `QuarantineReleaseDecision` checksum to the
  prior tip, `append_approval_ledger_entry()` construction gate, `validate_approval_ledger_chain()`
  checksum-bound chain validation, optional `approval_ledger_prior_entries` enforcement on
  `evaluate_quarantine_release()`, and `COMMAND_QUARANTINE_APPROVAL_LEDGER_CHAIN_INVALID` for
  ledger failures mapped from closed `ApprovalLedgerReason` codes
- Contract, integration, adversarial, invariant, and governance tests proving genesis and entry
  checksum determinism, append-only linkage, quarantine release blocking on tampered prefixes,
  runtime object injection rejection, adapter field manifest registration, and scenario category
  coverage for ledger positives, tamper, and injection paths
- Runtime Command Quarantine and Operator Approval Receipt for Phase 3 / ADR-0022: immutable checksum-bound `CommandQuarantineEnvelope`, `OperatorApprovalReceipt`, and `QuarantineReleaseDecision` contracts, `quarantine_runtime_command()` for placing every lease-valid dispatch item into quarantine by default, `build_operator_approval_receipt()` for explicit operator approval/rejection evidence, and `evaluate_quarantine_release()` for fail-closed dry-run-only release decisions
- Contract, integration, adversarial, governance, and invariant tests proving missing/rejected/stale/overbroad/drifted/malformed approvals block release, evidence drift across dispatch, backend admission, descriptor, registry, manifest, certification, replay proof, lease, and context authority fails closed, runtime object/callable injection is rejected, direct released-decision construction is blocked, scenario sentinels cover ADR-0022 categories, and forbidden runtime import scans remain clean
- Runtime Backend Interface Contract and Null Backend Certification for Phase 3 Part 4 / ADR-0018: immutable checksum-bound `RuntimeBackendDescriptor`, `BackendCertificationResult`, and `BackendDryRunReceipt` contracts, descriptor-only `RuntimeBackendContract`, `NullRuntimeBackend`, `certify_runtime_backend()`, and `build_backend_dry_run_receipt()` for binding firewall-allowed `DRY_RUN_ONLY` dispatch plans to a non-executing null backend
- Contract, integration, adversarial, governance, and invariant tests proving backend certification requires an `ALLOWED_DRY_RUN` firewall decision, rejects non-null backend kind, execution/I/O/async claims, runtime object/callable/client/mutable-state injection, capability/runtime-kind scope drift, certification checksum drift, and any receipt execution count above zero while keeping forbidden runtime import scans clean
- Runtime Adapter Dry-Run Contract and Dispatch Firewall for Phase 3 Part 3 / ADR-0017: immutable checksum-bound `RuntimeDispatchItem`, `RuntimeDispatchPlan`, `DispatchFirewallDecision`, and `RuntimeDispatchReceipt` contracts, `build_runtime_dispatch_plan()` for deriving inert `DRY_RUN_ONLY` dispatch intent only from PASSED adapter replay proof, and `evaluate_dispatch_firewall()` for failing closed on swapped, stale, mutated, malformed, oversized, non-dry-run, or runtime-object-injected plans
- Contract, integration, adversarial, governance, and invariant tests proving replay proof is required, exact envelope binding is enforced, direct dispatch plan construction is rejected, dispatch mode cannot become executable, sequence gaps/duplicates block, payload/QoS/namespace/message/field-map drift blocks, runtime object injection blocks, scenario sentinels cover ADR-0017 categories, and forbidden runtime import scans remain clean
- Execution Adapter Boundary and ROS 2 Message Mapping Contract for Phase 3 Part 1 / ADR-0015: immutable checksum-bound `RuntimeTarget`, `Ros2QoSProfileSpec`, `Ros2MessageMapping`, `ExecutionAdapterMapping`, `ExecutionAdapterEnvelope`, and `AdapterReceipt` contracts, pure adapter mapping validators, and `build_execution_adapter_envelope()` for converting only an allowed receipt-valid `PipelineResult` into a non-executing adapter envelope
- Contract, unit, integration, adversarial, governance, and invariant tests proving adapter envelopes bind policy/context/receipt evidence, reject non-allowed or receipt-invalid pipeline results, fail closed on command/capability/namespace/QoS/field-map/checksum/resource mismatches, forbid dangerous runtime override fields, reject direct READY construction from fragments, and keep ROS 2 concepts as inert data with zero ROS imports
- Authority drift, policy versioning, context authority, resource bounds, and contract coverage gates for Phase 2 Part 11 / ADR-0014: versioned policy checksums, explicit `ContextAuthority`, direct approval receipt policy/context bindings, governance manifests, contract drift sentinel, stage/category/checksum coverage sentinel, and deterministic resource-bound validation
- Governance, adversarial, and invariant tests proving authority manifests stay aligned with dataclass fields, policy identity is checksum-bound, missing or mismatched context authority cannot approve, forged receipts cannot omit context bindings, and the release stage/category coverage registries fail closed on drift
- Deterministic Scenario Runner and Evil-Twin Coverage Gate for Phase 2 Part 10 / ADR-0013: immutable scenario contracts, canonical scenario fixtures, real `run_pipeline` scenario execution, expectation validation against both pipeline outcome and receipt-proven decision path, required category coverage, stable scenario/suite checksums, and evil-twin rejection for forged, mismatched, replayed, overclaimed, confusable, checksum-corrupted, and direct-gate-only evidence
- Scenario contract, runner, coverage, integration, adversarial, and invariant tests proving all required ADR-0013 categories are represented, allowed paths carry valid full receipts, blocked paths stop at expected upstream stages without late approval artifacts, direct gate allow is not full pipeline approval, replayed receipts fail closed, and deterministic repeat checksums are stable
- Decision Trace and Approval Receipt v1 for Phase 2 Part 9 / ADR-0012: deterministic `DecisionTraceStep`, `DecisionTrace`, `ApprovalReceipt`, and `ApprovalReceiptValidationResult` contracts binding raw intent, validation, plan, audit, admissibility, freshness, verifier/config authority, trust, policy result, SafetyCase, admission, gate, and receipt checksums
- Pipeline receipt wiring that attaches a decision trace, approval receipt, and receipt validation to every orchestrated `PipelineResult`, and downgrades would-be approvals to `ERROR` with `APPROVAL_RECEIPT_INTEGRITY_FAILED` when receipt integrity fails
- Contract, integration, adversarial, invariant, and regression tests proving no `PipelineOutcome.ALLOWED` can exist without a valid receipt, missing/reordered/duplicated/forged stages fail closed, partial blocked/invalid receipts cannot claim unreached stages, replayed receipts cannot bind to a different plan, and direct gate allow is not full pipeline approval
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
- README project status now reflects Phase 2 release completion and Phase 3 Part 1 adapter-boundary work instead of the stale Phase 1-only status
- Scenario category coverage now includes ADR-0015 adapter-boundary categories while keeping adapter envelope construction as a separate post-pipeline API
- ENFORCE-mode approval paths now require explicit versioned policy identity and matching context authority before an ALLOW decision can reach the gate; blocked and invalid paths preserve their upstream failure evidence without requiring context authority
- Approval receipts now directly bind policy checksum and context authority checksum in addition to decision-trace stage outputs
- Scenario runner exports now include the ADR-0013 pipeline scenario APIs while preserving the legacy JSON fixture runner used by Phase 1 demo tests
- `PipelineOutcome.ALLOWED` now requires valid decision trace and approval receipt integrity in addition to policy-backed admission integrity and final gate approval
- ENFORCE-mode approval paths now certify the injected verifier adapter and validate trust-policy configuration after freshness and before world snapshot trust evaluation
- ENFORCE-mode approval paths now require explicit world snapshot trust evidence, an explicit trust policy, and a TRUSTED trust result before policy evaluation can approve
- ENFORCE-mode approval paths now require an explicit `world_snapshot` and caller-supplied `evaluation_time_ms`; disabled or non-fresh admission paths remain non-approved and do not reach final gate approval
- Disabled or missing policy admission no longer preserves legacy approval; it returns an explicit non-approved disabled admission record and skips the final gate
- `RawIntent` now rejects bool priority values instead of accepting them as integers

### Removed
- Non-canonical `src/aegis/core/` and `src/aegis/sim/` scaffolding (replaced by DIG layer structure)

---

*Releases appear below this line once tagged.*
