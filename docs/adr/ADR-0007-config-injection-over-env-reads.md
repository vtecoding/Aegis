# ADR-0007: Config Injection Over Global Environment Reads

## Status

Accepted — Phase 1

## Context

Pipeline functions need configuration values: maximum plan steps, supported commands,
audit algorithm, gate version, etc. Two access patterns were considered:

1. **Global environment reads** — pipeline functions call `os.environ["AEGIS_STRICT"]`
   or read a module-level singleton that lazily reads environment state.
2. **Explicit config injection** — a typed `AegisConfig` dataclass is constructed by the
   caller and passed into pipeline functions that need it.

## Decision

Configuration is represented by `AegisConfig`, a **frozen dataclass with deterministic
defaults** defined in `src/aegis/aegis_config.py`.

Rules:
- `AegisConfig` is constructed by the caller (test, CLI adapter, ROS 2 adapter).
- Pipeline functions that need config receive it as an explicit argument.
- `AegisConfig` must never read `os.environ`, files, or network sockets during
  construction or attribute access.
- There is no module-level mutable config singleton.
- Default values are hardcoded in the dataclass definition — they are versioned with
  the code and cannot be silently overridden by the environment.

Environment loading (e.g. reading `AEGIS_STRICT_MODE=true` from a `.env` file) is
the responsibility of the outer adapter, which constructs an `AegisConfig` from its
own env-reading logic and injects it.

## Consequences

**Positive:**
- Config is explicit, inspectable, and diffable.
- Tests can inject non-default configs without environment mutation.
- No hidden coupling between pipeline behaviour and deployment environment.
- `AegisConfig` is part of the deterministic replay tuple: same input + same context +
  same config → same output.

**Negative:**
- Functions that need config must accept it as a parameter, increasing call-site verbosity.
- Phase 1 does not yet thread `AegisConfig` through the pipeline; that is a near-term
  task once the first configurable policy decision (e.g. max plan steps) is needed.

## Alternatives Considered

**`os.environ` reads inside pipeline functions:** Rejected. Violates the no-side-effects
rule (ADR-0006) and makes functions non-deterministic across different shell environments.

**Pydantic `BaseSettings` with `.env` file parsing:** Rejected for core. Pydantic
`BaseSettings` is appropriate for adapter-layer config loading but must not be imported
into the deterministic core.

**`functools.lru_cache`-backed config singleton:** Rejected. A cached singleton is still
a form of hidden global state. Tests that need different configs would require cache
invalidation hacks.
