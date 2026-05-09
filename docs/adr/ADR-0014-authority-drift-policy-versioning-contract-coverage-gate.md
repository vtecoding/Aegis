# ADR-0014: Authority Drift, Policy Versioning, and Contract Coverage Gate

## Context

Phase 2 approval evidence had grown beyond a simple policy result. Approval now depends on
policy identity, world snapshot admissibility, freshness, trust, verifier certification,
trust-policy configuration, SafetyCase bindings, decision trace stages, receipts, and scenario
coverage. Any new authority field that is not explicitly named and checksum-bound can drift into
the approval path without test or receipt coverage.

## Decision

Aegis will seal Phase 2 with an explicit authority drift gate:

- Every approval-path contract has a static authority field manifest.
- `Policy` carries versioned identity: `policy_version`, `policy_schema_version`,
  `policy_checksum`, `policy_authority`, optional effective time, optional superseded checksum,
  rules, capabilities, default decision, and metadata.
- `ContextAuthority` is an explicit caller-provided authority contract. It binds context ID,
  request ID, evaluation time, caller authority, deployment domain, schema version, and checksum.
- `PipelineOutcome.ALLOWED` requires context authority whose `evaluation_time_ms` matches the
  caller-supplied `evaluation_time_ms`; blocked and invalid paths remain lightweight.
- `PolicyEvaluationResult`, `SafetyCase`, `PolicyAdmissionRecord`, `DecisionTrace`, and
  `ApprovalReceipt` bind policy identity and context authority checksums.
- Deterministic resource bounds apply before canonical hashing or policy evaluation for
  authority-bearing structures.
- Governance sentinels fail when dataclass fields, stage registries, scenario categories, or
  checksum coverage registries drift without explicit coverage.

## Consequences

- New approval authority cannot be added silently; it must appear in manifests, checksum coverage,
  receipts, scenarios, and tests.
- Policy identity is replayable and independently recomputable.
- Context authority is explicit and injectable; the deterministic core still reads no wall clock,
  environment, filesystem, network, sensors, middleware, or hardware.
- Existing blocked-path diagnostics remain stable because context authority is mandatory only for
  would-be approvals.

## Alternatives Considered

- Rely on code review for authority drift. Rejected because authority fields must fail closed in
  automated gates.
- Store context authority only in receipt metadata. Rejected because admission integrity must bind
  it before gate approval.
- Require context authority at the start of every ENFORCE run. Rejected because stale, invalid, or
  untrusted paths should preserve their upstream failure evidence without extra authority inputs.