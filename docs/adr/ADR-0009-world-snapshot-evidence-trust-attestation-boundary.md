# ADR-0009: World Snapshot Evidence Trust and Attestation Boundary

## Status

Accepted — Phase 2 Part 6

## Context

ADR-0008 and Phase 2 Part 5 established that ENFORCE-mode approval requires a FRESH
`WorldSnapshotStub` at a caller-supplied `evaluation_time_ms`. Freshness proves only that
the supplied snapshot is within an age bound. It does not prove provenance, source
identity, attestation validity, or that the evidence is appropriate for physical-runtime
plans.

That leaves a bypass: a caller can provide a fresh but unauthenticated snapshot and ask the
deterministic policy evaluator to approve a plan as if the evidence were trustworthy.
For DIG-relevant or physical-runtime decisions, freshness without explicit trust evidence
must fail closed.

## Decision

Aegis introduces a deterministic world snapshot trust boundary after freshness validation
and before policy evaluation.

ENFORCE-mode approval now requires:

- A caller-supplied `WorldSnapshotEvidenceEnvelope` bound to the same snapshot checksum.
- A caller-supplied `WorldSnapshotTrustPolicy` that declares allowed source IDs, source
  types, trust domains, and capabilities.
- A deterministic `WorldSnapshotTrustResult` with status `TRUSTED`.
- A valid `WorldSnapshotAttestation` and injected synchronous verifier result when the
  trust policy requires attestation.
- Trust fields bound through `PolicyEvaluationResult`, `SafetyCase`, and
  `PolicyAdmissionRecord`.
- Policy-admission integrity verification that rejects stale, forged, mismatched, missing,
  contradictory, or non-TRUSTED trust bindings.

The deterministic core does not read sensors, files, networks, process state, wall-clock
time, or environment state to establish trust. Verifier output is injected through an
explicit synchronous callable and is itself treated as deterministic evidence.

Fresh but unauthenticated world state therefore blocks before policy evaluation in
`ENFORCE` mode.

## Consequences

**Positive:**

- Freshness and trust are separate proofs: fresh evidence is not automatically trusted.
- `PipelineOutcome.ALLOWED` has an auditable provenance-policy binding, not only a
  freshness binding.
- Trust failures are visible as policy admission denial reasons and never reach the final
  gate as approvals.
- Attestation verification remains adapter-injected and deterministic from the core's
  perspective.

**Negative:**

- ENFORCE callers must provide trust evidence and policy fixtures in addition to freshness
  inputs.
- Tests and scenario fixtures that model approval must explicitly construct trusted
  evidence.
- This does not prove that a source is physically truthful; it proves only that supplied
  evidence satisfied the configured deterministic trust policy.

## Alternatives Considered

**Treat freshness as trust:** Rejected. A fresh snapshot can still be unauthenticated,
forged, from a disallowed domain, or inappropriate for physical runtime.

**Let the policy evaluator inspect trust metadata directly:** Rejected. Trust is an
admission precondition and must fail closed before semantic policy evaluation can approve.

**Call external attestation services from the core:** Rejected. Network, filesystem,
environment, process, middleware, sensor, and hardware reads are forbidden inside the
deterministic core.

**Use metadata flags inside `WorldSnapshotStub`:** Rejected. Snapshot facts are caller
evidence and cannot self-authorize trust.