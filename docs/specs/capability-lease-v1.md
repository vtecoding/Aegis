# Runtime Capability Lease & Revocation Proof v1

## Scope

Capability Lease v1 adds deterministic, checksum-bound leases for admitted runtime backends. It does not execute commands, publish messages, start nodes, open sockets, read files, read environment variables, call hardware, use async scheduling, read clocks, generate random IDs, import ROS/runtime SDKs, or make physical safety claims.

## Contracts

- `RuntimeCapabilityLease` binds backend descriptor, admission decision, authority manifest, registry, certification, replay proof, dispatch plan, firewall decision, context authority, leased scope, explicit lease epoch, `ACTIVE_NULL_ONLY`, and lease checksum.
- `LeaseValidationResult` records `VALID`, `INVALID`, or `REVOKED`, reason code, current registry/manifest/context checksums, scope match, evidence-chain match, and validation checksum.
- `LeaseRevocationDecision` records `REVOKED` or `NOT_REVOKED`, reason code, lease checksum, revoked evidence checksum, revocation stage, and revocation checksum.

## Valid Lease Requirements

`LeaseValidationResult.status == VALID` requires all of the following:

- lease is an exact `RuntimeCapabilityLease` instance produced by the builder
- lease status is `ACTIVE_NULL_ONLY`
- lease checksum recomputes
- backend kind is exactly `NULL_BACKEND_V1`
- admission decision status is exactly `ADMITTED`
- admission decision checksum recomputes
- descriptor checksum recomputes
- authority manifest checksum recomputes
- registry checksum matches the manifest set
- certification checksum recomputes and is `CERTIFIED_NULL`
- replay proof checksum recomputes and is `PASSED`
- dispatch plan checksum recomputes and remains `DRY_RUN_ONLY`
- firewall decision checksum recomputes and remains `ALLOWED_DRY_RUN`
- context authority checksum exactly matches the lease
- current caller-supplied lease epoch equals the lease epoch
- leased capabilities and runtime kinds are non-empty, explicit, non-wildcard, and subset-bounded by manifest and dispatch scope

## Failure Reasons

- `CAPABILITY_LEASE_UNKNOWN_BACKEND_KIND`
- `CAPABILITY_LEASE_BACKEND_NOT_NULL`
- `CAPABILITY_LEASE_BACKEND_NOT_ADMITTED`
- `CAPABILITY_LEASE_ADMISSION_DECISION_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_REGISTRY_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_MANIFEST_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_DESCRIPTOR_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_CERTIFICATION_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_REPLAY_PROOF_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_DISPATCH_PLAN_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_FIREWALL_DECISION_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_CONTEXT_AUTHORITY_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_CAPABILITY_OVERCLAIM`
- `CAPABILITY_LEASE_RUNTIME_KIND_OVERCLAIM`
- `CAPABILITY_LEASE_WILDCARD_SCOPE`
- `CAPABILITY_LEASE_EMPTY_SCOPE`
- `CAPABILITY_LEASE_STALE_EPOCH`
- `CAPABILITY_LEASE_RUNTIME_OBJECT_INJECTION`
- `CAPABILITY_LEASE_CHECKSUM_DRIFT`
- `CAPABILITY_LEASE_STATUS_INVALID`
- `DIRECT_CAPABILITY_LEASE_CONSTRUCTION`

## Scenario Categories

- `CAPABILITY_LEASE_NULL_POSITIVE`
- `CAPABILITY_LEASE_REQUIRES_ADMISSION`
- `CAPABILITY_LEASE_SCOPE_SUBSET`
- `CAPABILITY_LEASE_REGISTRY_DRIFT`
- `CAPABILITY_LEASE_MANIFEST_DRIFT`
- `CAPABILITY_LEASE_CERTIFICATION_DRIFT`
- `CAPABILITY_LEASE_REPLAY_DRIFT`
- `CAPABILITY_LEASE_CONTEXT_AUTHORITY_DRIFT`
- `CAPABILITY_LEASE_WILDCARD_SCOPE`
- `CAPABILITY_LEASE_REVOCATION`

## Invariants

- Repeated lease issue over identical evidence produces the same lease checksum.
- Repeated validation and revocation over identical evidence produce the same result checksums.
- `VALID` is impossible without an admitted `NULL_BACKEND_V1` backend and exact evidence-chain match.
- Any bound field change changes the lease checksum or prevents validation.
- Any current evidence drift invalidates or revokes the lease.
- No stale epoch validates.
- Lease issue and validation do not mutate source evidence.

## Release Gate

Capability Lease v1 is complete only when an admitted null backend can receive a checksum-bound lease, validation fails on any registry/manifest/admission/certification/replay/dispatch/firewall/context/scope/epoch drift, revocation is deterministic and reason-coded, wildcard and overbroad leases are blocked, scenario/governance sentinels cover ADR-0021, forbidden runtime imports remain absent, and `python scripts\verify.py verify` passes.
