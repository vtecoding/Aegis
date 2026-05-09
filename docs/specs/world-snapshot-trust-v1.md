# World Snapshot Trust v1 Specification

## Summary

World Snapshot Trust v1 adds a deterministic provenance, verifier certification, trust
policy configuration, and attestation boundary for `WorldSnapshotStub` evidence. It runs
after freshness validation and before policy evaluation in ENFORCE mode.

Freshness answers: is the supplied snapshot recent enough at the caller-supplied
evaluation time?

Trust answers: is the supplied snapshot evidence from an allowed source, source type,
trust domain, capability, certified verifier adapter, valid trust-policy configuration,
and attestation path for this admission decision?

Both must pass before a pipeline result can be `ALLOWED`.

## Goals

- Keep trust evaluation pure, deterministic, and replayable.
- Require explicit evidence envelopes and explicit trust policies for ENFORCE approval.
- Require deterministic verifier adapter certification before trust evaluation.
- Require deterministic trust-policy configuration validation before trust evaluation.
- Bind trust evidence checksums through `PolicyEvaluationResult`, `SafetyCase`, and
  `PolicyAdmissionRecord`.
- Fail closed for missing, malformed, contradictory, disallowed, replayed, expired,
  not-yet-valid, invalid, or unverifiable attestation evidence.
- Preserve the boundary between deterministic provenance-policy enforcement and any later
  physical-world truth source.

## Non-Goals

- No live sensor, simulator, middleware, filesystem, network, database, environment, or
  hardware reads inside `src/aegis/`.
- No claim that trusted evidence is physically true.
- No ROS 2, hardware, actuator, collision, dynamics, or certification safety claim.
- No cryptographic implementation inside the deterministic core beyond canonical checksums
  of explicit input.

## Contracts

### `WorldSnapshotEvidenceEnvelope`

The evidence envelope binds caller-supplied provenance to one snapshot checksum.

Required evidence includes:

- `snapshot_id`
- `snapshot_checksum`
- `source_id`
- `source_type`
- `trust_domain`
- `capability`
- optional `WorldSnapshotAttestation`
- optional immutable metadata

Metadata is inert. It can be recorded and hashed, but it cannot turn missing or invalid
attestation into trust.

### `WorldSnapshotTrustPolicy`

The trust policy declares deterministic allowlists for:

- source IDs
- source types
- trust domains
- capabilities

It also declares whether attestation is required and whether replay detection is enforced.
The policy is checksummed and bound into every trusted result.

### `WorldSnapshotTrustResult`

The trust result carries:

- `status`
- `reason_code`
- snapshot, envelope, policy, attestation, verifier-result, verifier certification, and
  trust-policy config validation checksums
- verifier ID and verifier metadata checksum
- source, source type, trust domain, and capability evidence

Only `status == TRUSTED` can support ENFORCE approval. Every other status blocks before
policy evaluation.

## Pipeline Ordering

```text
RawIntent
  -> ValidationResult
  -> CommandPlan
  -> AuditedPlan
  -> WorldSnapshotFreshnessResult
  -> VerifierAdapterCertificationResult
  -> TrustPolicyConfigValidationResult
  -> WorldSnapshotTrustResult
  -> PolicyEvaluationResult + SafetyCase
  -> PolicyAdmissionRecord integrity check
  -> GateDecision
```

Trust is evaluated only after a snapshot is fresh. If freshness is missing or non-FRESH,
trust evaluation is not used to recover approval.

## Failure Modes

Trust evaluation fails closed for:

- missing evidence envelope
- missing trust policy
- missing required verifier
- missing, malformed, unsafe, non-deterministic, or uncertified verifier adapter
- invalid trust-policy configuration
- snapshot checksum mismatch
- disallowed source ID
- disallowed source type
- disallowed trust domain
- disallowed capability
- missing required attestation
- invalid, expired, not-yet-valid, replayed, or unsupported attestation
- malformed or contradictory evidence

Malformed or contradictory trust evidence produces `PipelineOutcome.INVALID` after audit.
Other non-TRUSTED statuses produce `PipelineOutcome.BLOCKED`. Gate approval is never
reached for either class.

## Invariants

- `PipelineOutcome.ALLOWED` implies `world_snapshot_trust_status == "TRUSTED"` on the
  admission record, policy result, and SafetyCase.
- `PipelineOutcome.ALLOWED` implies non-empty trust result, evidence envelope, and trust
  policy checksums.
- `PipelineOutcome.ALLOWED` implies `verifier_certification_status == "CERTIFIED"` and
  `trust_policy_config_status == "VALID"` on the admission record.
- `PipelineOutcome.ALLOWED` implies verifier certification checksum, verifier ID, verifier
  metadata checksum, and trust-policy config validation checksum are bound consistently
  through trust result, policy result, SafetyCase, and admission record.
- `PipelineOutcome.ALLOWED` implies source ID, source type, and trust domain are bound
  consistently through policy result, SafetyCase, and admission record.
- Fresh but missing or non-TRUSTED world snapshot evidence cannot produce final approval.
- Snapshot metadata cannot self-attest trust.
- An arbitrary verifier object or arbitrary trust policy cannot act as ENFORCE approval
  authority without deterministic certification.

## Test Coverage

- `tests/contracts/test_world_snapshot_trust_contract.py`
- `tests/contracts/test_attestation_verifier_contract.py`
- `tests/contracts/test_trust_policy_config_contract.py`
- `tests/integration/test_pipeline_trust_authority_hardening.py`
- `tests/adversarial/test_attestation_verifier_adapter_bypass.py`
- `tests/invariants/test_attestation_verifier_hardening_invariants.py`
- `tests/integration/test_pipeline_world_snapshot_trust.py`
- `tests/adversarial/test_world_snapshot_trust_bypass.py`
- `tests/invariants/test_world_snapshot_trust_invariants.py`
- `tests/contracts/test_policy_admission_contract.py`
- `tests/contracts/test_pipeline_contract.py`

## Known Limitations

Trust v1 proves deterministic provenance-policy enforcement over explicit evidence only.
It does not prove physical-world truth, sensor correctness, middleware safety, simulation
safety, collision safety, actuator safety, or robot safety certification.