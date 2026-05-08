# ADR-0006: No Side Effects Inside the Core Pipeline

## Status

Accepted — Phase 1

## Context

A safety pipeline that produces side effects inside its core functions (file writes,
network calls, database inserts, log flushes, hardware signals) is harder to test,
harder to replay, and harder to reason about. Side effects introduce ordering
dependencies that undermine determinism.

The design question was: where should the boundary between pure pipeline and side-effecting
adapter live?

## Decision

The DIG core pipeline (`validation/`, `planning/`, `audit/`, `gate/`, `pipeline/`) is
**side-effect-free**. Functions in these packages:

- Do not write to files, databases, or network sockets.
- Do not read from environment variables, files, or network sockets at runtime.
- Do not flush or configure logging handlers.
- Do not call hardware interfaces.
- Do not mutate any value visible outside the function scope.

The **only** exception is `gate/`: the gate layer is architecturally permitted to produce
side effects in future phases (e.g. triggering an actuator after an ALLOWED decision).
In Phase 1, even the gate layer is pure.

Side effects live exclusively in adapter layers outside `src/aegis/`:
- A future CLI adapter emits output.
- A future ROS 2 adapter publishes to a topic.
- An outer harness flushes log events to a sink.

Log events are value objects created inside the core (see ADR-0008) but emitted only
by outer adapters.

## Consequences

**Positive:**
- Every core function is testable in complete isolation with no fixtures, mocks, or
  teardown.
- Pipeline runs are fully replayable from input alone.
- No hidden I/O means coverage tools accurately reflect test completeness.

**Negative:**
- Outer adapters must be written to bridge from the pure core to real-world effectors.
  This is additional code at Phase 2.
- Log events are data, not emitted logs; a developer accustomed to `logger.info()` in
  the middle of business logic must adopt a different pattern.

## Alternatives Considered

**Structured logging inside core functions via `structlog`:** Deferred. `structlog` is an
allowed dependency but must not be called inside pure pipeline functions. It may be
called by outer adapters processing `AegisLogEvent` objects.

**Allow read-only filesystem config reads inside core:** Rejected. Any filesystem read
is a hidden dependency that makes tests require disk state. Config is injected through
`AegisConfig` (see ADR-0007).
