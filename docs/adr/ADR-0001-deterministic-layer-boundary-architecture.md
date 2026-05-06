# ADR-0001: Deterministic Layer-Boundary Architecture

## Status

Accepted — Phase 1

## Context

Aegis is a safety gateway that must interpose between an untrusted AI caller and a physical
robot effector. Any non-determinism in the pipeline — random output, environment-dependent
branching, or hidden mutable state — makes the system non-replayable and non-auditable.
A non-replayable safety system cannot be reasoned about, certified, or formally verified.

The core design question was: how should the internal pipeline be structured so that
determinism is a property of the architecture rather than a property of individual
programmer discipline?

## Decision

The DIG pipeline is structured as five ordered layers:

```
intent/ → validation/ → planning/ → audit/ → gate/
```

Each layer is a separate Python package. Layers communicate only through typed contracts
defined in `contracts/`. No layer may import from a layer ahead of it in the flow.
Only the `gate/` layer is permitted to produce side-effects.

All non-deterministic values (timestamps, request IDs, policy versions, run IDs) must be
injected by the caller through `ExecutionContext` before pipeline entry. The deterministic
core never calls `datetime.now()`, `uuid.uuid4()`, `random.*`, `os.environ`, or any I/O.

Repeating the same `(raw_intent, context)` pair produces an equal `PipelineResult` every time.

## Consequences

**Positive:**
- Every pipeline run is replayable from logs alone (input + context → exact output).
- Property-based tests (Hypothesis) can assert determinism formally.
- The audit trail is cryptographically bound to exact inputs, not wall-clock time.
- Layers are independently replaceable as long as contracts are honoured.
- Future formal verification tooling can operate on pure functions.

**Negative:**
- All non-deterministic values must be threaded explicitly — verbosity increases at call sites.
- The `intent/` parsing layer is deferred to Phase 2 because it may eventually need LLM
  normalisation, which is incompatible with core determinism (see ADR-0005).

## Alternatives Considered

**Single-module pipeline with an event bus:** Rejected. Event buses introduce ordering
ambiguity and hidden coupling. Layer boundaries enforce separation at the import graph level.

**Pydantic `BaseModel` validation on each layer boundary:** Considered; deferred to a
hybrid approach (see ADR-0002). Layer boundaries use typed frozen dataclasses; Pydantic
is used only at the external JSON ingestion boundary.

**Async pipeline with task graph:** Rejected for Phase 1. Async I/O is incompatible
with pure deterministic functions and adds unnecessary complexity before the core is proven.
