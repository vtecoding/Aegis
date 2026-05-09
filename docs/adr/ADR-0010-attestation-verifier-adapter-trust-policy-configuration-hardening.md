# ADR-0010: Attestation Verifier Adapter Contract & Trust Policy Configuration Hardening

## Status

Accepted

## Context

ADR-0009 made world snapshot trust mandatory for `ENFORCE` approval by requiring explicit
evidence, a trust policy, and attestation verification when policy requires attestation.
That created a remaining authority gap: an arbitrary object with a `verify()` method or an
arbitrary trust policy could become the effective approval authority if it produced a
passing result at runtime.

Aegis is a deterministic safety gateway. Approval authority must be explicit, replayable,
and bound into the same evidence chain as plan, freshness, trust, policy, and SafetyCase
material.

## Decision

Aegis must not accept an arbitrary verifier object or arbitrary trust policy as approval
authority. Both must pass deterministic certification before they can participate in
`ENFORCE` approval.

The deterministic core now introduces two contracts:

- `AttestationVerifierAdapterMetadata` and `VerifierAdapterCertificationResult` certify a
  metadata-bearing verifier adapter against required positive and negative attestation
  vectors.
- `TrustPolicyConfigValidationResult` validates that a supplied `WorldSnapshotTrustPolicy`
  is appropriate for the verifier metadata, runtime trust domain, capability, and
  `ENFORCE` context.

`run_pipeline()` performs verifier certification and trust-policy config validation after
freshness succeeds and before world snapshot trust evaluation. Certification or config
failure blocks policy evaluation and final gate execution.

`WorldSnapshotTrustResult`, `PolicyEvaluationResult`, `SafetyCase`, and
`PolicyAdmissionRecord` now carry verifier certification checksum, trust-policy config
validation checksum, verifier ID, and verifier metadata checksum. Admission integrity
requires these bindings to match before an allowed record can become policy-backed approval
evidence.

## Consequences

- `ENFORCE` approval requires a certified verifier adapter and a valid trust-policy config.
- Missing verifier metadata, missing verifier, unsafe physical-runtime verifier metadata,
  accepted negative certification vectors, malformed verifier results, and non-determinism
  fail closed before trust evaluation.
- Empty or wildcard trust policy authority, physical-runtime test sources, physical-runtime
  simulation domains, disabled attestation in `ENFORCE`, verifier algorithm/key mismatch,
  and capability/runtime conflicts fail closed before trust evaluation.
- Trust authority proof material is audit-visible and integrity-checked across the existing
  admission evidence chain.

## Alternatives Considered

- **Trust verifier output alone.** Rejected because a passing verification result without
  certified adapter identity leaves approval authority implicit.
- **Validate trust policy only inside the trust evaluator.** Rejected because policy config
  failures should block before trust evaluation and before policy admission semantics can
  observe a partially trusted result.
- **Do not bind certification/config checksums into admission.** Rejected because admission
  integrity must prove the exact authority evidence used for approval.

## Non-Goals

- This ADR does not add ROS 2, hardware, filesystem, network, database, or LLM dependencies.
- This ADR does not claim physical-world truth, cryptographic soundness beyond the injected
  verifier contract, certification readiness, or real robot safety.
- This ADR does not make the gate layer execute side effects beyond the existing pure gate
  approval boundary.