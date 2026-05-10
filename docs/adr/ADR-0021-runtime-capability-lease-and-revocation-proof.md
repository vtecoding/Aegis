# ADR-0021: Runtime Capability Lease & Revocation Proof

## Status

Accepted.

## Context

ADR-0020 admits a deterministic null backend authority, but admission alone is not enough for any future runtime boundary. A backend needs a checksum-bound, explicit, revocable lease before it can participate in later runtime evidence flows.

The lease must bind the admitted backend descriptor, admission decision, authority manifest, closed registry, certification result, replay proof, dispatch plan, firewall decision, context authority, scope, and caller-supplied epoch. The deterministic core still must not read wall clocks, environment, filesystem, network, queues, async runtimes, middleware, simulators, hardware, or ROS packages.

## Decision

Aegis adds ADR-0021 runtime capability lease contracts and evaluators:

- `RuntimeCapabilityLease` is issued only through `issue_runtime_capability_lease` for an `ADMITTED` `NULL_BACKEND_V1` backend.
- `LeaseValidationResult` validates current evidence against the lease without wall-clock fallback.
- `LeaseRevocationDecision` deterministically records revocation or non-revocation with a reason code and stage.

A valid lease requires all bound evidence checksums to match exactly, scope to be non-empty and subset-bounded, the backend kind to remain `NULL_BACKEND_V1`, the lease status to be `ACTIVE_NULL_ONLY`, and the caller-supplied current epoch to equal the lease epoch.

## Consequences

- Registry, manifest, descriptor, admission, certification, replay, dispatch, firewall, context authority, scope, and epoch drift fail closed.
- Wildcard scope, empty scope, runtime object injection, callable injection, mutable lease escape hatches, and direct public construction of a valid lease are blocked.
- Scenario and governance sentinels now include ADR-0021 lease categories and checksum-field coverage.
- This does not add ROS, simulator, hardware, filesystem, network, async, queueing, execution, actuation, or physical safety claims.

## Alternatives Considered

- Treat backend admission as sufficient authority. Rejected because admission has no lease epoch, context authority binding, or revocation decision surface.
- Add time-based lease expiration inside the deterministic core. Rejected because wall-clock reads violate the determinism authority rule.
- Allow broader lease scope than the admitted backend manifest. Rejected because runtime capability authority must remain least-privilege and subset-bounded.
