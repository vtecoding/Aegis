# ADR-0002: Immutable Frozen Dataclasses for Internal Contracts

## Status

Accepted — Phase 1

## Context

Internal pipeline contracts carry structured data between layers. Two candidate patterns
were considered: Pydantic `BaseModel` and stdlib `dataclasses.dataclass`.

The pipeline has strict determinism requirements. Internal contracts must be immutable
once constructed, carry no hidden side-effects on attribute access, and be verifiable
by pyright in strict mode without stubs.

## Decision

All internal contracts between pipeline layers (`contracts/`) use stdlib
`@dataclass(frozen=True, slots=True)`. Pydantic is **not** used for internal contracts.

Pydantic's `BaseModel` is permitted only as an ingestion adapter at the external JSON
boundary (if and when a JSON schema validator is added in a future phase). It must not
be used for contracts that flow between `validation/`, `planning/`, `audit/`, and `gate/`.

`frozen=True` guarantees immutability after construction. `slots=True` prevents attribute
addition at runtime. Both properties are verified statically by pyright strict mode.

`__post_init__` is used for construction-time invariant assertions on contracts that
carry invariant constraints (e.g. `ExecutionContext`, `RawIntent`, `PipelineResult`).

## Consequences

**Positive:**
- Contracts are immutable; no layer can mutate data owned by an upstream layer.
- pyright strict mode can fully type-check frozen dataclass hierarchies with no stubs.
- `__eq__` and `__hash__` are derived automatically, making contracts usable as dict keys.
- No Pydantic version drift risk inside the deterministic core.
- Construction-time validation via `__post_init__` is explicit and traceable.

**Negative:**
- No JSON schema generation from internal contracts; that capability belongs at the
  adapter boundary, not the core.
- Deeply nested frozen structures require careful `freeze_json_mapping` helpers at
  the boundary (implemented in `contracts/json_types.py`).

## Alternatives Considered

**Pydantic `BaseModel` for all contracts:** Rejected. Pydantic's model validator
execution order, `model_post_init` hooks, and field coercion are runtime behaviours that
are harder to reason about in strict pyright mode. Pydantic is well-suited for HTTP
schemas, not deterministic pipeline internals.

**Named tuples:** Rejected. Named tuples lack `__post_init__` semantics and cannot
carry invariant assertions cleanly. They also lose field-name documentation.

**TypedDict:** Rejected. TypedDicts are mutable and provide no construction-time
validation.
