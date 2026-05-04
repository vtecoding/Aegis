# Aegis — Deterministic Intent Gateway (DIG)

> **Phase 1: Core Pipeline bootstrap.** No robotics integration. No LLM integration. No production safety claims.

## What Is Aegis?

Aegis is a safety gateway platform. Its first component is **DIG (Deterministic Intent Gateway)**: a pure-Python pipeline that converts untrusted, high-level intent into a validated, auditable command plan.

The pipeline is deterministic: given the same input and the same `ExecutionContext`, it always produces the same output. This makes it replayable, testable, and structured for future formal analysis.

## Current Status

| Property | Status |
|----------|--------|
| Phase | Phase 1 — Core Pipeline |
| Robotics (ROS 2) | Not started — Phase 2 |
| LLM SDK in core | Forbidden — all phases |
| Production safety claims | None — not yet proven |
| Validation command | `python scripts/verify.py verify` (`make verify` delegates to it) |

Correctness claims in Phase 1 are bounded by: typed contracts, deterministic replay, property-based invariant tests, unit tests, and quality gates passing cleanly.

## Pipeline

```
Intent → Validation → Planning → Audit → Execution Gate
```

Each layer is a separate Python package under `src/aegis/`. Data flows forward only. No layer imports from a layer ahead of it. Cross-layer data uses typed contracts defined in `src/aegis/contracts/`.

## Development

### Prerequisites

- Python 3.12+
- `pip install -e ".[dev]"`

### Quality Gate

Canonical gate logic lives in `scripts/verify.py`. `make verify` is the Unix/CI wrapper.

Unix/CI:

```bash
make verify
```

Windows direct command, using the active virtual environment Python:

```powershell
.\.venv\Scripts\python.exe scripts\verify.py verify
```

This runs (in order): `pyright --project pyproject.toml`, `ruff check`, `ruff format --check`, `pytest --cov`, `pytest tests/invariants`.

All gates must be green before any PR merges.

### Individual Targets

```bash
make test            # Run all tests
make test-invariants # Run Hypothesis invariant suite only
make test-adversarial # Run adversarial boundary tests only
make typecheck       # pyright --strict
make lint            # ruff check
make format          # ruff format (applies changes)
make coverage        # pytest --cov with HTML report
make clean           # Remove build artefacts
```

## Repository Layout

```
src/aegis/
├── contracts/    # Typed contracts between layers — no logic
├── intent/       # Layer 1: Intent parsing
├── validation/   # Layer 2: Schema and semantic validation
├── planning/     # Layer 3: Command plan construction
├── audit/        # Layer 4: Audit record construction
├── gate/         # Layer 5: Execution gate (only layer with side-effects)
├── errors.py     # Typed exception hierarchy
├── logging.py    # Structured logging
├── constants.py  # All constants
└── config.py     # Config injection

tests/
├── invariants/   # Hypothesis property tests
├── contracts/    # Contract conformance tests
├── unit/         # Pure function tests
├── integration/  # End-to-end pipeline tests
├── regression/   # One file per bug, named by issue number
└── adversarial/  # Hostile inputs (required — Aegis is a gateway for untrusted intent)
```

## Governance

Canonical authority: `skills.md`. Agent instructions: `.github/copilot-instructions.md`.

If those two files disagree with anything else in the repo, they win (in that order).
