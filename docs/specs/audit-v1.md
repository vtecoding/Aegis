# audit-v1 Specification

## Summary

`audit-v1` converts a `CommandPlan` produced by `planning-v1` into an `AuditedPlan` — a deterministic, immutable audit receipt that binds the plan content to a unique audit event identifier. It is a pure, side-effect-free transformation. No gate logic, no allow/block decisions, no file writes, no logs-as-authority, no network calls.

---

## Goals

- Produce a deterministic `AuditedPlan` from any valid `CommandPlan`
- `checksum`: SHA-256 of the executable plan payload (`plan_id` and concrete command steps)
- `audit_id`: SHA-256 of (`checksum` + `plan_id` + execution context fields: `request_id`, `submitted_at`, `policy_version`, `run_id`)
- Both hashes are derived exclusively from explicit input — no `datetime.now()`, no `uuid.uuid4()`, no `os.environ`
- Full coverage of `contracts/audit.py` (100%)

---

## Non-Goals

- Gate decisions (allow / block) — those belong in `gate/`
- File writes, log flushing, streaming — the audit layer emits a value object only
- Multiple plan steps per audit receipt — this spec covers one `CommandPlan` per `AuditedPlan`
- Policy evaluation — `audit-v1` records; it does not decide

---

## Contracts

### `src/aegis/contracts/audit.py`

```python
@dataclass(frozen=True, slots=True)
class AuditedPlan:
    plan: CommandPlan    # The plan this receipt covers
    audit_id: str        # SHA-256(checksum + plan_id + context fields)
    checksum: str        # SHA-256(plan_id + steps)
```

**Invariants:**
- `audit_id` must be non-empty after whitespace stripping
- `checksum` must be non-empty after whitespace stripping
- Both are immutable once set
- In practice, both will always be 64-character lowercase hexadecimal SHA-256 digests when produced by `build_audited_plan`

---

## API

### `src/aegis/audit/audit_builder.py`

```python
def build_audited_plan(plan: CommandPlan) -> AuditedPlan:
    ...
```

- **Input:** Any `CommandPlan`
- **Output:** An `AuditedPlan` with deterministic `checksum` and `audit_id`
- **Side effects:** None
- **Raises:** Nothing (all inputs are already validated `CommandPlan` objects)
- **Determinism:** `build_audited_plan(plan) == build_audited_plan(plan)` always

### `src/aegis/audit/checksum.py`

```python
def plan_checksum(plan: CommandPlan) -> str:
    """SHA-256 of canonical { plan_id, steps }."""

def plan_audit_id(plan: CommandPlan, checksum: str) -> str:
    """SHA-256 of canonical { checksum, plan_id, context }."""
```

---

## Checksum Fields

### `plan_checksum` covers

| Field | Notes |
|---|---|
| `plan.plan_id` | Opaque planner-assigned identity; encodes full planning event (command, params, source, priority, context) via `stable_plan_id` |
| `plan.steps[*].step_type.value` | Each step's type |
| `plan.steps[*].parameters` | Each step's parameters, keys sorted |
| `plan.steps[*].sequence` | Each step's sequence index |

**Design invariant:** `plan_id + same steps → same checksum`.  Caller context fields (`request_id`, `submitted_at`, `policy_version`, `run_id`) are intentionally excluded from the checksum payload — they are bound into `audit_id` instead.  Intent fields (`command`, `parameters`, `source_id`, `priority`) are not directly in the checksum payload; they influence it indirectly through `plan_id` (which is produced by `stable_plan_id` and encodes the full planning event).

### `plan_audit_id` covers

| Field | Notes |
|---|---|
| `checksum` | The plan_checksum result |
| `plan.plan_id` | The planner-assigned identity |
| `plan.intent.context.request_id` | Caller-provided request identifier |
| `plan.intent.context.submitted_at` | ISO 8601 UTC string (`Z` suffix) |
| `plan.intent.context.policy_version` | Policy version string |
| `plan.intent.context.run_id` | Optional run identifier (may be `None`) |

---

## Canonicalization Rules

The same rules as `planning-v1` `plan_hasher`:

1. JSON mapping keys are sorted (`sort_keys=True`)
2. No whitespace between tokens (`separators=(",", ":")`)
3. UTF-8 encoded (`ensure_ascii=False`)
4. `datetime` → ISO 8601 UTC with `Z` suffix (e.g. `"2026-01-01T00:00:00Z"`)
5. `StrEnum` values → their `.value` string (not the enum member name)
6. `Mapping` → `dict` with sorted keys, recursively
7. `tuple` → `list`, recursively

These rules ensure key-order invariance: reordering JSON object keys in intent parameters produces the same hash.

---

## Determinism Rules

The following are forbidden inside `src/aegis/audit/`:

| Forbidden | Why |
|---|---|
| `datetime.now()` / `datetime.utcnow()` | Non-deterministic time generation |
| `uuid.uuid4()` | Non-deterministic ID generation |
| `random.*` / `secrets.*` | Non-deterministic randomness |
| `os.environ` reads | Environment-derived state |
| File system reads | External state |
| Network calls | External state |
| `hash()` (Python's built-in) | Not stable across interpreter runs |

All non-deterministic values are provided through `plan.intent.context` (`ExecutionContext`), which is injected by the caller.

---

## Failure Modes

| Scenario | Behaviour |
|---|---|
| `AuditedPlan(audit_id="")` | `ValueError("audit_id must be non-empty")` |
| `AuditedPlan(checksum="")` | `ValueError("checksum must be non-empty")` |
| `AuditedPlan(audit_id="   ")` | `ValueError("audit_id must be non-empty")` after strip |
| Plan with unicode source_id | Handled correctly; `ensure_ascii=False` preserves it |
| Plan with deeply nested parameters | Recursive `_canonical_json_value` handles arbitrary depth |

---

## Test Matrix

| Test file | Coverage |
|---|---|
| `tests/contracts/test_audit_contract.py` | `AuditedPlan` construction, immutability, equality, field names |
| `tests/unit/test_audit_checksum.py` | `plan_checksum` and `plan_audit_id` correctness and differentiation |
| `tests/unit/test_audit_builder.py` | `build_audited_plan` end-to-end |
| `tests/invariants/test_invariant_audit_determinism.py` | Hypothesis: determinism, immutability, key-order invariance |
| `tests/adversarial/test_audit_adversarial_inputs.py` | Unicode, injection strings, deep nesting, extreme priorities |

---

## Known Limitations

- `AuditedPlan` validates only non-emptiness of `audit_id` and `checksum`, not that they are valid SHA-256 hex strings. This is intentional: the contract is minimal; the test suite verifies the hash format.
- `checksum` does not cover the execution context fields directly. Two plans with identical `plan_id` and identical steps will always produce the same `checksum`, regardless of context. Different plan_ids (arising from different commands, source_ids, priorities, or contexts) will produce different checksums — but this is through `plan_id`, not through direct field expansion.
- `audit_id` binds the checksum to a specific request/context event. Same plan under a different `request_id` or `policy_version` will produce the same `checksum` but a different `audit_id`.
- `audit-v1` does not perform gate decisions. An `AuditedPlan` is not an approval; it is a receipt.
