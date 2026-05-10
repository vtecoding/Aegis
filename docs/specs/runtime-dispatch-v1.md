# Runtime Dispatch Dry-Run v1

## Scope

Runtime Dispatch Dry-Run v1 derives inert dispatch intent from a replay-verified
`ExecutionAdapterEnvelope`. It does not execute commands, publish messages, start nodes,
open sockets, read files, read environment variables, call hardware, use async scheduling,
read clocks, generate random IDs, or import ROS/runtime SDKs.

## Contracts

- `RuntimeDispatchItem` describes one command as inert data: strict sequence, capability,
  runtime kind, runtime name, namespace, message type, QoS checksum, payload checksum,
  payload byte size, and field-map checksum.
- `RuntimeDispatchPlan` binds a source envelope checksum, source replay proof checksum,
  runtime target checksum, mapping checksum, `DRY_RUN_ONLY` mode, dispatch items,
  resource bounds, and plan checksum.
- `DispatchFirewallDecision` returns `ALLOWED_DRY_RUN` or `BLOCKED` with reason, plan
  checksum, proof checksum, blocked stage, and decision checksum.
- `RuntimeDispatchReceipt` binds the plan and firewall decision as a dry-run receipt.

## Allowed Dry-Run Requirements

`DispatchFirewallDecision.status == ALLOWED_DRY_RUN` requires all of the following:

- adapter replay proof status is `PASSED`
- replay proof checksum recomputes
- envelope checksum recomputes
- replay proof expected and replayed envelope checksums match the exact envelope
- plan source envelope checksum and source replay proof checksum match the current evidence
- dispatch mode is exactly `DRY_RUN_ONLY`
- runtime target checksum matches the source envelope
- mapping checksum matches the source envelope
- dispatch item sequence values are strict and gapless
- runtime kind is `topic`, `service`, or `action` as inert enum data only
- runtime name, namespace, message type, QoS checksum, payload checksum, payload byte size,
  and field-map checksum match ADR-0015 mapping evidence
- payload size remains within deterministic bounds
- dispatch items contain no runtime objects, callable handles, mutable payloads, backend
  clients, or ROS/DDS objects

## Failure Reasons

- `RUNTIME_DISPATCH_REPLAY_PROOF_NOT_PASSED`
- `RUNTIME_DISPATCH_REPLAY_PROOF_CHECKSUM_MISMATCH`
- `RUNTIME_DISPATCH_ENVELOPE_CHECKSUM_MISMATCH`
- `RUNTIME_DISPATCH_CROSS_ENVELOPE_REPLAY_PROOF_SWAP`
- `RUNTIME_DISPATCH_RUNTIME_TARGET_MISMATCH`
- `RUNTIME_DISPATCH_MAPPING_MISMATCH`
- `RUNTIME_DISPATCH_NAMESPACE_MISMATCH`
- `RUNTIME_DISPATCH_QOS_MISMATCH`
- `RUNTIME_DISPATCH_MESSAGE_TYPE_MISMATCH`
- `RUNTIME_DISPATCH_PAYLOAD_BOUNDS_EXCEEDED`
- `RUNTIME_DISPATCH_PAYLOAD_MISMATCH`
- `RUNTIME_DISPATCH_FIELD_MAP_DRIFT`
- `RUNTIME_DISPATCH_SEQUENCE_GAP`
- `RUNTIME_DISPATCH_DUPLICATE_SEQUENCE`
- `RUNTIME_DISPATCH_UNKNOWN_RUNTIME_KIND`
- `RUNTIME_DISPATCH_MODE_NOT_DRY_RUN_ONLY`
- `RUNTIME_DISPATCH_PLAN_CHECKSUM_MISMATCH`
- `RUNTIME_DISPATCH_OBJECT_INJECTION`
- `DIRECT_RUNTIME_DISPATCH_BYPASS`

## Scenario Categories

- `RUNTIME_DISPATCH_DRY_RUN_POSITIVE`
- `RUNTIME_DISPATCH_REPLAY_PROOF_REQUIRED`
- `RUNTIME_DISPATCH_CROSS_ENVELOPE_SWAP`
- `RUNTIME_DISPATCH_MAPPING_DRIFT`
- `RUNTIME_DISPATCH_PAYLOAD_BOUNDS`
- `RUNTIME_DISPATCH_SEQUENCE_INTEGRITY`
- `RUNTIME_DISPATCH_MODE_FIREWALL`
- `RUNTIME_DISPATCH_RUNTIME_OBJECT_INJECTION`

## Invariants

- Same replay-verified envelope and proof produce the same dispatch plan checksum.
- Repeated firewall evaluation for the same plan/evidence produces the same decision
  checksum.
- `ALLOWED_DRY_RUN` is impossible without a PASSED replay proof for the exact envelope.
- Any bound field change changes the plan checksum or blocks at the firewall.
- Runtime dispatch planning does not mutate source envelope or replay proof evidence.
- No runtime backend exists in v1.

## Release Gate

Runtime Dispatch Dry-Run v1 is complete only when positive dry-run planning passes, proof
swaps and evidence mutations fail closed, direct construction bypass is rejected, runtime
object injection blocks, scenario coverage includes all ADR-0017 categories, forbidden
runtime imports remain absent, and `python scripts\verify.py verify` passes.
