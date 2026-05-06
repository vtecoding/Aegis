# ADR-0005: Phase 1 Intent Layer Intentionally Stubbed

## Status

Accepted — Phase 1

## Context

The DIG architecture specifies five layers: `intent/`, `validation/`, `planning/`,
`audit/`, `gate/`. In practice, an intent parsing layer would normalise free-form input
(natural language, LLM JSON output, voice commands) into the structured `RawIntent`
contract before validation begins.

The question for Phase 1 was: should `intent/` be implemented, or deferred?

## Decision

`src/aegis/intent/` exists as a package but is **implementation-empty** in Phase 1.
The `__init__.py` documents this explicitly and exports nothing.

Callers construct `RawIntent` directly. `RawIntent`'s own `__init__` validates:
- Non-empty, stripped `command` string
- Non-empty, stripped `source_id` string
- Priority in `[1, 10]` (bool rejected)
- Caller-provided, timezone-aware UTC `submitted_at`
- Recursively frozen JSON-compatible parameters

This boundary validation is sufficient for Phase 1 because all callers in Phase 1
(tests, scenario runner, future CLI adapter) are trusted Python callers constructing
`RawIntent` explicitly.

## Consequences

**Positive:**
- The `intent/` package is reserved in the package namespace. Future implementers
  cannot accidentally pollute it.
- No Phase 1 code paths depend on intent parsing logic that does not yet exist.
- The architecture is honest: the stub signals that intent parsing is deferred, not
  forgotten.

**Negative:**
- A real-world deployment would need an intent normalisation layer before `RawIntent`
  construction. That layer is not yet designed.
- If the intent layer eventually requires LLM normalisation, it will need careful
  isolation from the deterministic core (see ADR-0001) and a separate ADR.

## Alternatives Considered

**Implement a basic regex-based intent parser in Phase 1:** Rejected. Any intent parser
that accepts free-form text introduces scope that is not provably bounded in Phase 1.
It also risks creating a dependency path that would need to be unwound when the real
parser is designed.

**Remove `intent/` from the package tree entirely until Phase 2:** Rejected. Removing
it would make Phase 2 a structural refactor rather than an additive implementation.
Reserving the namespace is low-cost and avoids future merge conflicts.
