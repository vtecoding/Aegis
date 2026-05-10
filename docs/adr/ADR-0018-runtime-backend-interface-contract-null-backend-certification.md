# ADR-0018: Runtime Backend Interface Contract & Null Backend Certification

## Status

Accepted for Phase 3 Part 4.

## Context

ADR-0015 constructs deterministic adapter evidence. ADR-0016 replays and reconstructs
that evidence. ADR-0017 derives inert dry-run dispatch intent and admits it only through
the dispatch firewall. Those boundaries prove evidence integrity and dispatch-intent
admissibility, not runtime behavior.

Before any ROS adapter, node, publisher, subscriber, service/action client, DDS entity,
simulator bridge, network boundary, filesystem boundary, hardware boundary, async runtime,
or execution queue exists, Aegis needs the future backend interface shape to be explicit
and certified as non-executing.

## Decision

Aegis adds a descriptor-only runtime backend certification boundary after an
`ALLOWED_DRY_RUN` dispatch firewall decision:

```text
RuntimeDispatchPlan
  -> DispatchFirewallDecision(ALLOWED_DRY_RUN)
  -> RuntimeBackendDescriptor
  -> NullRuntimeBackend
  -> BackendCertificationResult(CERTIFIED_NULL)
  -> BackendDryRunReceipt
```

`RuntimeBackendContract` exposes only immutable descriptor evidence. It does not expose
publish, send, call, execute, queue, async, client, node, middleware, network, filesystem,
environment, simulator, or hardware operations.

`NullRuntimeBackend` is the only implemented backend. Its descriptor must declare
`backend_kind == NULL_BACKEND_V1`, `backend_mode == DRY_RUN_CERTIFICATION_ONLY`, exact
capability and runtime-kind scope for the dispatch plan, and false execution, I/O, and
async capability flags.

`certify_runtime_backend()` fails closed unless the dispatch plan is still `DRY_RUN_ONLY`,
the firewall decision is `ALLOWED_DRY_RUN`, plan and decision checksums recompute, backend
descriptor checksum recomputes, backend kind and mode are the null certification values,
all non-execution guarantees are true, no callable/client/runtime/mutable object is
exposed, the concrete backend is `NullRuntimeBackend`, and declared capability/runtime-kind
scope exactly matches the dispatch plan.

`build_backend_dry_run_receipt()` emits a receipt only for `CERTIFIED_NULL` certification.
The receipt binds the dispatch plan checksum, firewall decision checksum, backend
certification checksum, backend descriptor checksum, observed inert dispatch-item IDs,
`executed_count == 0`, and blocked execution count.

## Consequences

- Future runtime backend integration must pass an explicit certification boundary before
  it can be connected to dispatch intent.
- Backend certification is deterministic and checksum-bound to dispatch intent, firewall
  admission, backend identity, backend capability/runtime-kind scope, and non-execution
  guarantees.
- Runtime object, callable, client, mutable-state, execution-capability, I/O-capability,
  async-capability, backend-kind, scope, certification-checksum, and receipt execution drift
  fail closed.
- The claim remains narrow: Aegis can certify that the only implemented backend is a null,
  descriptor-only, dry-run observer for already firewalled dispatch intent. No runtime,
  middleware, robot, hardware, collision, physical, or external certification claim is made.

## Non-Goals

- No ROS node.
- No publisher, subscriber, service client, action client, DDS, simulator bridge, network,
  filesystem, environment, wall-clock, async, randomness, hardware, or actuation.
- No execution queue or runtime command dispatch.
- No robot safety, collision safety, middleware safety, execution safety, or certification
  readiness claim.

## Verification

```bash
python scripts\verify.py verify
```
