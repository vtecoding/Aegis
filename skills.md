# skills.md — Aegis Agent Authority File
> **This is the canonical authority for all AI agents, Copilot sessions, and human contributors working on the Aegis codebase.**
> Read this file first. Always. Every session. Every Line.

---

## 0. Quick-Reference Card

| Question | Answer |
|----------|--------|
| What is this project? | Aegis — Deterministic Intent Gateway (DIG) |
| Current phase | **Phase 1: RELEASE-COMPLETE** → **Phase 2: Policy-v1** (next) |
| Primary language | Python 3.12+ |
| Test framework | pytest + Hypothesis (property-based) |
| Type checker | pyright --strict |
| Linter/formatter | ruff |
| Can I use ROS 2? | **No.** Not until Phase 2. |
| Can I use LLM SDKs in core? | **No.** Never in deterministic core. |
| Coverage floor | 90% line — 100% on contracts/ and errors.py |
| Run all checks | `python scripts/verify.py verify` (`make verify` delegates to it) |
| Who decides architecture? | Human (AI orchestrator). You propose; they confirm. |

---

## 1. Project Overview

**Aegis** is a safety gateway platform whose first major component is **DIG — the Deterministic Intent Gateway**.

### What DIG Does
DIG takes untrusted, high-level intent (e.g., "move robot arm to position X") and converts it through a validated, auditable pipeline into a **validated, auditable command plan** whose correctness is bounded by the current test matrix and policy rules.

### Why Determinism Matters
A system that produces different outputs for the same input cannot be deterministically reasoned about or made replayable. Aegis must be deterministic, replayable, and structured so formal verification can be introduced later. In Phase 1, correctness claims are limited to: typed contracts, deterministic replay, property-based invariant tests, unit tests, integration tests, and quality gates. Do not claim formal verification, production safety, or real-world robot safety until there is a dedicated formal methods or certification phase. Therefore:
- No randomness in the core pipeline (unless seeded and reproducible)
- No LLM inference in the core pipeline
- No network calls in the core pipeline
- No filesystem reads in the core pipeline (config is injected at startup)
- Same intent in → same command plan out. Every time.

### Determinism Authority Rule

The deterministic core must not generate time, IDs, randomness, filesystem state, network state, process state, or environment-derived values internally.

All non-deterministic values must be injected through explicit contracts such as `ExecutionContext`.

**Forbidden inside the core pipeline:**
- `datetime.now()`
- `datetime.utcnow()`
- `time.time()`
- `uuid.uuid4()`
- `random.*`
- `secrets.*`
- direct `os.environ` reads
- filesystem reads
- network calls
- database calls
- hardware calls

**Allowed inside the core pipeline:**
- deterministic hashes of explicit input
- timestamps passed through `ExecutionContext`
- request IDs passed through `ExecutionContext`
- policy versions passed through `ExecutionContext`
- seeded randomness only in tests, never production core unless explicitly specified in an ADR

Core pipeline functions must be deterministic under the tuple:

`explicit input + explicit ExecutionContext + explicit configuration + explicit environment state`

If a value is not explicit, the core must not depend on it.

### Why This Architecture
The layered pipeline (Intent → Validation → Planning → Audit → Gate) enforces:
- **Fail-early:** Invalid intent is rejected at the earliest possible boundary
- **Least privilege:** Each layer can only see what it needs
- **Auditability:** Every decision is logged in the audit layer before any side-effect
- **Replaceability:** Layers are swappable as long as contracts are honoured

---

## 2. Current Phase: Phase 1 — Core Pipeline

### Phase 1 Goals
- [x] Implement the full DIG pipeline in pure Python
- [x] 90%+ test coverage with property-based invariant tests
- [x] All 5 layers have typed contracts in `contracts/`
- [x] Full Hypothesis invariant suite for determinism properties
- [x] ADRs written for all major architectural decisions (ADR-0001–0008)
- [x] `scripts/verify.py verify` passes cleanly with zero warnings

### Phase 1 Hard Constraints
```
ALLOWED:
  - Python 3.12+ stdlib
  - pydantic >= 2.0 (contracts and validation only)
  - hypothesis (invariant/property tests)
  - pytest, pytest-cov
  - ruff (lint + format)
  - pyright (type checking, strict mode)
  - structlog (structured logging)

FORBIDDEN (until Phase 2):
  - rclpy, rclcpp, any ROS 2 package
  - openai, anthropic, langchain, or any LLM SDK
  - asyncio in the core pipeline (permitted in tooling only)
  - requests, httpx, or any HTTP client in src/
  - Any database client in src/
  - Any hardware interface library
```

### Phase 1 — Release Statement

Phase 1 is **RELEASE-COMPLETE**. This release completes the deterministic Aegis kernel.
It does not include physical safety policy evaluation, environment awareness, simulation,
ROS integration, or runtime actuation guards.

**Phase 1 proves:**
- Deterministic intent-to-gate pipeline
- Typed immutable contracts
- Tamper-evident audit binding
- Pure approval boundary
- Governance documentation
- Invariant-backed test discipline

**Phase 1 does not prove:**
- Semantic physical safety
- Policy enforcement at scale
- Environment-aware decisions
- Runtime safety monitoring
- Simulation or collision checking
- Middleware integration
- Real robot actuation control

### Phase 2: Policy-v1 (Next Phase — Do Not Implement Until Phase 1 Tag Is Cut)

Phase 2 introduces policy-backed semantic safety. The core question Phase 2 must answer:

> Given a proposed plan, declared policy, and an immutable world snapshot — should this action be allowed, blocked, or require review?

This is the jump from *secure command validator* to *deterministic safety-policy admission engine*.

**Phase 2 contracts to introduce (in `contracts/`):**
- `Policy` — declared rule set governing allowed commands and parameters
- `PolicyRule` — a single evaluable rule with condition and consequence
- `Capability` — a named permitted action class
- `Constraint` — a typed bound on a parameter or state
- `WorldSnapshotStub` — immutable, injected snapshot of environment state (Phase 2 stub; Phase 3+ real)
- `PolicyEvaluationResult` — typed result: `ALLOWED | BLOCKED | REQUIRES_REVIEW`
- `SafetyCase` — structured justification for a gate decision referencing policy and snapshot

**Phase 2 new layer:**
- `src/aegis/policy/` — Layer 2.5: inserted between Validation and Planning. Evaluates policy rules against validated intent and world snapshot. Pure and deterministic. No I/O.

**Phase 2 hard constraints (same as Phase 1 plus):**
- `WorldSnapshotStub` must be injected — never read from environment in core
- Policy rules must be serialisable and replayable
- No ROS 2, no LLM, no network in the policy layer
- Policy evaluation must be deterministic: same intent + same policy + same snapshot → same result

**Phase 2 forbidden (still):**
- ROS 2 integration (Phase 3)
- Hardware interface layer (Phase 3)
- Real-time audit streaming (Phase 3)
- LLM policy generation in core (never)

---

## 3. Agent Capability Registry

This section defines what each type of AI agent interaction is authorised to do without human confirmation.

### Agent Autonomy Boundary

Autonomous permission applies only when the change does not alter:
- public contracts
- package structure
- phase boundaries
- dependency policy
- gate behaviour
- safety semantics
- documented invariants
- quality gates
- canonical naming conventions
- architecture layer boundaries

If any of those are affected, the agent must produce a proposal and wait for human confirmation.

### 3.1 Autonomous (No Confirmation Needed)
The agent may proceed without asking:

| Task | Scope |
|------|-------|
| Write new unit tests | Anywhere in `tests/unit/` |
| Write new invariant tests | Anywhere in `tests/invariants/` |
| Write new regression tests | `tests/regression/` — must name file after issue |
| Implement a function whose spec exists in `docs/specs/` | Match spec exactly |
| Fix a failing test where the fix is < 10 lines | Must not change public API |
| Add docstrings | Any file |
| Fix type errors flagged by pyright | Any file |
| Fix ruff lint errors | Any file |
| Refactor internals with no behavioural change | Must keep all tests green |
| Update CHANGELOG.md | For any completed fix |
| Write ADRs | For decisions already made and discussed |
| Add `pytest.mark.parametrize` cases to existing tests | Any test file |

### 3.2 Propose Then Confirm
The agent must write a proposal and wait for human approval:

| Task | Why |
|------|-----|
| New module or package | Affects workspace structure |
| New entry in `contracts/` | Breaks existing consumers if wrong |
| Adding a new dependency | Must stay within phase constraints |
| Deleting or renaming a public function/class | Breaking change |
| Modifying pipeline layer boundaries | Architectural decision |
| Any change that drops coverage below 90% | Quality gate |
| Anything that crosses a phase boundary | Phase gating is explicit |

### 3.3 Hard Stops (Never Do Without Explicit Instruction)
| Task |
|------|
| Add ROS 2 / robotics dependencies |
| Add LLM SDK to `src/` |
| Modify `gate/` execution logic without a paired ADR |
| Delete test files |
| Disable or skip tests without issue reference |
| Add `# type: ignore` without justification comment |
| Add any form of global singleton to the core pipeline |

---

## 4. Architecture Deep-Dive

### 4.1 Layer Map

```
┌─────────────────────────────────────────────────────────┐
│                    DIG Pipeline                          │
│                                                         │
│  ┌──────────┐   ┌────────────┐   ┌──────────────┐      │
│  │  Intent  │──▶│ Validation │──▶│   Planning   │      │
│  │  Layer   │   │   Layer    │   │    Layer     │      │
│  └──────────┘   └────────────┘   └──────────────┘      │
│       │                                   │             │
│   IntentCommand              CommandPlan──┤             │
│                                           ▼             │
│                              ┌─────────────────────┐   │
│                              │    Audit Layer       │   │
│                              └─────────────────────┘   │
│                                           │             │
│                                    AuditedPlan          │
│                                           │             │
│                              ┌─────────────────────┐   │
│                              │   Execution Gate     │   │
│                              │  (side-effects here) │   │
│                              └─────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Contract Types (in `src/aegis/contracts/`)

All inter-layer data is typed. These are the authoritative types.

**All non-deterministic values (time, IDs, environment state) must be provided by the caller through `ExecutionContext`. They must never be generated inside the core pipeline.**

```python
# contracts/context.py
@dataclass(frozen=True)
class ExecutionContext:
    request_id: str                 # Provided by caller; never generated in core
    submitted_at: datetime          # Provided by caller; UTC
    policy_version: str             # Explicit policy version for validation/gate decisions
    run_id: str | None = None       # Optional caller-provided run/session id

# contracts/intent.py
@dataclass(frozen=True)
class IntentCommand:
    command: str                    # Required — never None
    parameters: Mapping[str, JsonValue]  # Boundary-parsed; narrowed before internal use
    source_id: str                  # Who/what submitted this intent
    context: ExecutionContext       # Caller-injected context; never generated in core
    priority: int                   # 1 (highest) to 10 (lowest)

# contracts/validation.py
@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    intent: IntentCommand
    violations: tuple[Violation, ...]  # Empty if is_valid; immutable

# contracts/planning.py
@dataclass(frozen=True)
class CommandPlan:
    steps: tuple[CommandStep, ...]  # Ordered, non-empty, immutable
    intent: IntentCommand           # Original intent preserved
    context: ExecutionContext       # Passed through; not regenerated
    plan_id: str                    # Deterministic hash derived from explicit input

# contracts/audit.py
@dataclass(frozen=True)
class AuditedPlan:
    plan: CommandPlan
    audit_id: str                   # Deterministic hash derived from plan + context
    checksum: str                   # SHA-256 of canonical plan content

# contracts/gate.py
@dataclass(frozen=True)
class GateDecision:
    approved: bool
    plan: AuditedPlan
    reason: str                     # Always populated
    context: ExecutionContext       # Passed through; not regenerated
```

### Contract Strictness Rule

Raw external input may use JSON-compatible values at the boundary. Internal contracts must not expose unrestricted `dict[str, Any]`.

Use:
- typed dataclasses
- Pydantic boundary models
- enums
- discriminated unions
- immutable collections where practical
- `Mapping[str, JsonValue]` only at raw input boundaries

Recommended JSON-safe type alias for boundary documentation:

```python
JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
```

Every transition from raw input to internal contract must narrow types. `Any` is allowed only: at raw boundary parsing, with a justification comment, and when immediately narrowed before crossing into internal contracts.

### 4.3 Import Rules

```python
# LEGAL imports per layer:
# intent/     → contracts.intent (write), stdlib
# validation/ → contracts.intent (read), contracts.validation (write), stdlib
# planning/   → contracts.validation (read), contracts.planning (write), stdlib
# audit/      → contracts.planning (read), contracts.audit (write), stdlib
# gate/       → contracts.audit (read), contracts.gate (write), stdlib + I/O

# ILLEGAL (forward imports — never allowed):
# intent/ importing from validation/, planning/, audit/, gate/
# validation/ importing from planning/, audit/, gate/
# etc.

# ALWAYS LEGAL (any layer):
# aegis.errors
# aegis.logging
# aegis.constants
# aegis.config
```

### 4.4 Determinism Invariants

These are the properties Hypothesis tests must verify:

1. **Pipeline determinism:** `pipeline(intent, context, config, env_state) == pipeline(intent, context, config, env_state)` for all valid intents and contexts
2. **Context isolation:** If `context` differs, output may differ only in fields explicitly derived from context. If `context` is identical, output must be identical.
3. **Key-order invariance:** Reordering irrelevant raw JSON keys produces the same canonical result after parsing.
4. **Validation completeness:** If `validate(intent).is_valid`, then `plan(validate(intent))` never raises
5. **Audit immutability:** `audit(plan).checksum` is stable across repeated calls with identical input
6. **Deterministic violation ordering:** `validate(intent).violations` is ordered deterministically — same intent always produces violations in the same order
7. **Plan ID determinism:** `plan_id` and `audit_id` are deterministic hashes — same inputs always produce the same IDs
8. **Gate monotonicity:** An approved plan is never rejected on re-evaluation with same inputs
9. **Layer isolation:** No function in layer N modifies an object owned by layer N-1
10. **No caller-object mutation:** Core pipeline functions must not mutate any object passed by the caller

Hypothesis determinism tests must verify all of the above properties.

### 4.5 Canonical Repository Layout

The canonical package layout is `src/aegis/...`. No production package may exist at repository root.

```
src/
└── aegis/
    ├── contracts/          # Shared typed contracts between layers — no logic
    ├── intent/             # Layer 1: Intent parsing and normalisation
    ├── validation/         # Layer 2: Schema and semantic validation
    ├── planning/           # Layer 3: Safe command plan construction
    ├── audit/              # Layer 4: Immutable audit record construction
    ├── gate/               # Layer 5: Final execution gate; side-effects live here only
    ├── errors.py           # Typed exception hierarchy
    ├── logging.py          # Structured logging setup (aegis.logging)
    ├── constants.py        # Constants only — no magic numbers elsewhere
    └── config.py           # Explicit config models/injection

tests/
├── invariants/
├── contracts/
├── unit/
├── integration/
├── regression/
├── adversarial/
└── conftest.py

docs/
├── specs/
├── adr/
└── diagrams/
```

**Correct:**
- `src/aegis/contracts/`
- `src/aegis/intent/`
- `src/aegis/validation/`
- `src/aegis/planning/`
- `src/aegis/audit/`
- `src/aegis/gate/`

**Incorrect:**
- `aegis/` at repository root
- Implementation files at repository root

---

## 5. Task Routing Guide

Use this table to decide which tool or workflow to use for a given task. This is the AI orchestrator's routing table.

| Task Type | Primary Tool | Workflow |
|-----------|-------------|----------|
| Write/fix tests | Copilot Agent (Edit mode) | §9.1 in instructions |
| Implement a specced function | Copilot Agent (Edit mode) | §9.1 in instructions |
| Debug a failing test | Copilot Chat (`/fix`) | Paste test output |
| Explain existing code | Copilot Chat (`/explain`) | Select code block |
| Refactor internals | Copilot Agent (Edit mode) | §9.3 in instructions |
| New architecture decision | Copilot Chat → ADR | §9.4 in instructions |
| Review a change | Copilot Chat (`/review`) | Full diff |
| Generate property tests | Copilot Chat + Hypothesis prompt | Use `.github/prompts/invariant-test.prompt.md` |
| Write a spec | Copilot Chat | Use `.github/prompts/spec-writer.prompt.md` |
| Generate commit message | Copilot (inline) | Format in §13 of instructions |
| Understand a layer | Copilot Chat (`/explain`) | Point at the layer directory |

---

## 6. Common Code Patterns

### 6.1 Standard Layer Entry Point

```python
# validation/schema_validator.py
from __future__ import annotations

from aegis.contracts.intent import IntentCommand
from aegis.contracts.validation import ValidationResult, Violation
from aegis.errors import ValidationError
from aegis.logging import get_logger

log = get_logger(__name__)


def validate_intent(intent: IntentCommand) -> ValidationResult:
    """Validate an IntentCommand against the DIG schema.

    Args:
        intent: The intent command to validate.

    Returns:
        A ValidationResult with is_valid=True and empty violations if valid.

    Raises:
        ValidationError: If the intent is structurally invalid (not a
            semantic failure — structural failures are unrecoverable).
    """
    violations: list[Violation] = []

    # Structural check — unrecoverable, raise immediately
    if intent.command is None:
        raise ValidationError(
            message="Intent.command is required and must not be None",
            field="command",
            received=intent,
            layer="validation",
        )

    # Semantic checks — accumulate violations, return result
    if not intent.command.strip():
        violations.append(Violation(field="command", reason="Command must not be empty or whitespace"))

    if intent.priority not in range(1, 11):
        violations.append(Violation(field="priority", reason=f"Priority must be 1-10, got {intent.priority}"))

    log.info("intent_validated", is_valid=not violations, violation_count=len(violations))

    return ValidationResult(
        is_valid=len(violations) == 0,
        intent=intent,
        violations=tuple(violations),
    )
```

### 6.2 Standard Invariant Test

```python
# tests/invariants/test_invariant_validation_determinism.py
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.contracts.intent import IntentCommand
from aegis.validation.schema_validator import validate_intent
from tests.factories import intent_command_strategy


@given(intent_command_strategy())
@settings(max_examples=500)
def test_invariant_validation_is_deterministic(intent: IntentCommand) -> None:
    """validate_intent must return identical results for identical inputs."""
    result_1 = validate_intent(intent)
    result_2 = validate_intent(intent)
    assert result_1 == result_2, (
        f"Non-deterministic validation: got {result_1} then {result_2} "
        f"for intent {intent!r}"
    )
```

### 6.3 Standard Regression Test

```python
# tests/regression/test_issue_42_null_command_crashes_validator.py
"""
Regression test for GitHub issue #42.
null `command` field was propagating past validation into planning.
Fix: ValidationError raised immediately in validate_intent.
"""
import pytest

from aegis.contracts.intent import IntentCommand
from aegis.errors import ValidationError
from aegis.validation.schema_validator import validate_intent
from tests.factories import make_intent_command


def test_issue_42_null_command_raises_validation_error() -> None:
    """Null command must raise ValidationError, not propagate silently."""
    intent = make_intent_command(command=None)  # type: ignore[arg-type]

    with pytest.raises(ValidationError) as exc_info:
        validate_intent(intent)

    assert exc_info.value.field == "command"
    assert exc_info.value.layer == "validation"
```

---

## 7. Anti-Patterns Reference

These are patterns seen in the wild that are banned in Aegis. If Copilot generates any of these, reject and regenerate:

```python
# ❌ Silent catch
try:
    result = validate_intent(intent)
except Exception:
    result = None  # BANNED — hides failures

# ❌ Generic file names
# utils.py, helpers.py, manager.py, processor.py — BANNED

# ❌ Global mutable state
_cache: dict[str, Any] = {}  # BANNED — module-level mutable

# ❌ Untyped Any without justification
def process(data: Any) -> Any:  # BANNED — use real types

# ❌ Magic numbers
if priority > 10:  # BANNED — use constants.MAX_PRIORITY

# ❌ Input mutation
def normalize(intent: IntentCommand) -> None:
    intent.command = intent.command.strip()  # BANNED — frozen dataclass AND wrong contract

# ❌ Import from a downstream layer
# In intent/parser.py:
from aegis.validation.schema_validator import validate_intent  # BANNED — forward import

# ❌ Untracked deferred work
# TODO: fix this later  # BANNED — must be: # TODO(#42): fix this later

# ❌ Debug prints
print(f"DEBUG: {intent}")  # BANNED — use log.debug(...)
```

---

## 7.1 Module Naming Decision

Because the package namespace is already `aegis`, module files inside `src/aegis/` do not need an `aegis_` prefix.

**Prefer:**
- `src/aegis/contracts/intent.py`
- `src/aegis/validation/schema_validator.py`
- `src/aegis/planning/command_planner.py`
- `src/aegis/audit/audit_builder.py`
- `src/aegis/gate/decision_gate.py`

**Avoid:**
- `src/aegis/aegis_intent_schema.py`
- `src/aegis/aegis_safety_engine.py`
- `src/aegis/utils.py`
- `src/aegis/helpers.py`

Names must describe responsibility, not vibes. This also resolves the `{layer}_{noun}.py` vs `{noun}_{layer}.py` naming fork: use the noun-first form that best describes the module's single responsibility.

---

## 8. Dependency Management

```toml
# pyproject.toml — authoritative source
[project]
requires-python = ">=3.12"

[project.dependencies]
pydantic = ">=2.0,<3.0"
structlog = ">=24.0"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "hypothesis>=6.100",
    "ruff>=0.4",
    "pyright>=1.1.360",
]
```

**Adding a new dependency:**
1. Check Phase 1 constraints in §2
2. Propose in chat with justification
3. Wait for human confirmation
4. Add to `pyproject.toml` — never install ad-hoc

---

## 9. Verification Reference

Canonical gate logic lives in `scripts/verify.py`. `make verify` is the Unix/CI wrapper and must delegate to the same runner. On Windows, run the runner directly with the active virtual environment Python.

```powershell
.\.venv\Scripts\python.exe scripts\verify.py verify
```

```makefile
# Key targets — wrappers around scripts/verify.py
make verify          # Run all quality gates through the canonical runner
make test            # Run all tests
make test-invariants # Run only Hypothesis invariant suite
make test-adversarial # Run only adversarial boundary tests
make typecheck       # pyright through the canonical runner
make lint            # ruff check
make format          # ruff format
make coverage        # pytest --cov with HTML report
make clean           # Remove build artifacts
```

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **DIG** | Deterministic Intent Gateway — the core product |
| **Intent** | High-level, untrusted instruction from an external source |
| **Command Plan** | Validated, ordered set of safe steps derived from an intent |
| **Invariant** | A property that must be true for all valid inputs — tested with Hypothesis |
| **Contract** | A typed dataclass/model defining data exchanged between layers |
| **Gate** | The final execution layer — the only layer allowed to produce side-effects |
| **Phase** | A development stage with specific constraints on allowed dependencies |
| **ADR** | Architecture Decision Record — formal record of an architectural choice |
| **Violation** | A semantic validation failure — not an exception, a data structure |
| **AuditedPlan** | A CommandPlan with an immutable audit record attached |

---

## 10.1 Documentation Consistency Rule

If `skills.md`, `.github/copilot-instructions.md`, docs, specs, tests, and source code disagree, resolve the conflict before implementation.

**Authority order:**
1. Human instruction in current task
2. `skills.md`
3. `.github/copilot-instructions.md`
4. `docs/specs/`
5. tests
6. source code

Do not implement against stale docs. Do not silently choose one conflicting source. Flag the conflict in the response.

---

## 11. File Checklist — Before Committing

```
[ ] pyright --strict passes with zero errors
[ ] ruff check passes with zero warnings
[ ] ruff format --check passes
[ ] pytest tests/ passes — zero failures, zero unexpected skips
[ ] pytest tests/invariants/ passes — all property tests green
[ ] python scripts/verify.py verify passes as the canonical gate
[ ] Coverage >= 90% overall, 100% on contracts/ and errors.py
[ ] No forbidden patterns from §7
[ ] All new public functions have docstrings
[ ] CHANGELOG.md updated if this is a bug fix
[ ] ADR written if this is an architectural decision
[ ] Commit message follows §13 format in copilot-instructions.md
[ ] No TODO/FIXME without issue number
```

---

*Last updated: see git log. This file is maintained by the human AI orchestrator. If you are an AI agent and this file disagrees with other instructions, this file wins.*