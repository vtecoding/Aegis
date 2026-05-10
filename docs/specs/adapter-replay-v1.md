# Adapter Replay Proof Harness v1

## Scope

Adapter Replay Proof Harness v1 deterministically rebuilds an ADR-0015 adapter envelope and adapter
receipt from a source `PipelineResult` and the mapping/runtime evidence carried by the expected envelope.
It does not execute commands, import ROS, publish messages, start nodes, open sockets, read files, read
environment variables, call hardware, use async scheduling, read clocks, or generate random IDs.

## Contracts

- `AdapterReplayRequest` binds source pipeline evidence, expected READY envelope, expected adapter receipt,
  `STRICT_ADAPTER_REPLAY_V1`, and a closed mutation profile.
- `AdapterReplayProofResult` binds the replay status, deterministic reason, source checksum, expected and
  replayed envelope checksums, expected and replayed receipt checksums, mapping/runtime/QoS/namespace/receipt
  sub-checks, mutation detection, failure stage, and proof checksum.

## Status Semantics

- `PASSED` means the replayed envelope and receipt are checksum-equivalent to the expected evidence and every
  sub-check is known and true.
- `FAILED` means replay ran and detected mismatched evidence.
- `BLOCKED` means replay was not allowed to compare outputs because authority evidence was missing or invalid.

## Strict Profile

`STRICT_ADAPTER_REPLAY_V1` requires deterministic canonical serialization and forbids runtime I/O, clocks,
random IDs, environment reads, filesystem reads, network calls, ROS imports, async, and hidden global mutable
state.

## Mutation Coverage

The replay proof harness covers evil twins for pipeline receipt drift, policy result drift, SafetyCase drift,
context authority mismatch, policy identity mismatch, world snapshot admissibility/freshness/trust mismatch,
command plan mutation, capability mutation, ROS message type mutation, field map mutation, QoS mutation,
namespace mutation, runtime target mutation, adapter receipt replay-target mutation, adapter receipt checksum
mutation, stale READY-envelope receipts, cross-pipeline swaps, and resource-bound mutations.

## Release Gate

Adapter replay is complete only when positive replay passes, all mutation classes fail closed without exception
reliance, scenario coverage includes adapter replay categories, forbidden runtime imports remain absent, and
`python scripts\verify.py verify` passes.
