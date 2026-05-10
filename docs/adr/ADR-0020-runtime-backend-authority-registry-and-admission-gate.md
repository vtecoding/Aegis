# ADR-0020: Runtime Backend Authority Registry & Adapter Admission Gate

## Status

Accepted for Phase 3 Part 6.

## Context

ADR-0018 certifies the descriptor-only `NullRuntimeBackend`. ADR-0019 proves that null
backend certification and dry-run receipt evidence replay with `executed_count == 0`.
Those ADRs prove null-backend non-execution under deterministic replay, not runtime
safety and not authority to add future real backends.

Aegis needs a closed authority registry and admission gate before any backend sprawl is
possible. A backend must not become admissible merely because a descriptor, object, client,
callable, or future module exists.

## Decision

Aegis adds ADR-0020 backend authority admission:

```text
RuntimeBackendDescriptor
  -> BackendCertificationResult(CERTIFIED_NULL)
  -> BackendReplayProofResult(PASSED)
  -> BackendAuthorityManifest(NULL_BACKEND_V1, ADMITTED_NULL_ONLY)
  -> BackendAuthorityRegistry
  -> BackendAdmissionDecision(ADMITTED | BLOCKED)
```

`BackendAuthorityManifest` declares the only admitted backend kind, backend version,
mode scope, runtime-kind scope, capability scope, certification requirement, replay
requirement, execution/I/O/async boundary, admission status, and manifest checksum. For
ADR-0020 the only valid manifest is scoped to `NULL_BACKEND_V1`, requires ADR-0018
`CERTIFIED_NULL`, requires ADR-0019 strict backend replay, and allows no execution, I/O,
or async behavior.

`BackendAuthorityRegistry` is an immutable checksum-bound registry of authority manifests.
For ADR-0020 it contains exactly the null backend manifest for the supplied descriptor
scope. `BackendAdmissionRequest` carries descriptor, certification, replay proof,
authority manifest, and registry checksum. `admit_runtime_backend()` emits a
checksum-bound `BackendAdmissionDecision`.

Admission succeeds only when all evidence agrees exactly: backend kind is
`NULL_BACKEND_V1`, backend version matches `runtime-backend-v1`, certification is
`CERTIFIED_NULL`, replay proof is `PASSED`, descriptor/manifest scopes match exactly,
registry checksum matches the closed manifest set, and no execution, I/O, async, wildcard,
mutable manifest, callable, client, or runtime object authority is present.

## Consequences

- `NULL_BACKEND_V1` is the only admitted backend kind.
- Unknown and non-null backend kinds fail closed until explicit registry, certification,
  replay, scenario, and governance requirements exist.
- Manifest, registry, and admission decisions are checksum-bound.
- Scope overclaim, wildcard authority, runtime object injection, mutable manifest
  injection, descriptor/manifest mismatch, certification/manifest mismatch, and
  replay/manifest mismatch fail closed.
- The claim remains narrow: ADR-0020 prevents unsafe backend admission. It does not prove
  runtime, middleware, simulator, hardware, physical, collision, certification, or robot
  safety.

## Non-Goals

- No ROS backend, simulator backend, real runtime backend, runtime execution, actuation,
  DDS, publishing, services, actions, hardware, network, filesystem, environment reads,
  async runtime, or queues.
- No physical safety, middleware safety, collision safety, external certification, or
  runtime safety claim.

## Verification

```bash
python scripts\verify.py verify
```
