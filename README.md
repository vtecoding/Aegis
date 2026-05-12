# Aegis — Deterministic Intent Gateway (DIG)

> **Phase 3: Runtime evidence chain through ADR-0022 command quarantine.** No robot execution. No ROS imports. No executable runtime backend. No production safety claims.

## What Is Aegis?

Aegis is a safety gateway platform. Its first component is **DIG (Deterministic Intent Gateway)**: a pure-Python pipeline that converts untrusted, high-level intent into a validated, auditable command plan.

The pipeline is deterministic: given the same input and the same explicit evidence, it always produces the same output. This makes it replayable, testable, and structured for future formal analysis.

## Current Status

Release seal status: **NOT SEALED** until `python scripts/verify.py verify` passes with no required-gate failures.

| Property | Status |
|----------|--------|
| Phase | Phase 3 runtime evidence chain in progress through ADR-0027 repository authority boundary |
| Contracts | v1 implemented through approval receipts, policy/context authority, scenario coverage, execution adapter/ROS 2 mapping, runtime dispatch, backend admission, capability leases, and command quarantine contracts |
| Validation | v1 implemented — schema limits, allowed abstract commands, semantic violations |
| Planning | v1 implemented — deterministic one-step command plans and stable SHA-256 plan IDs |
| Audit | v1 implemented — deterministic `AuditedPlan` receipts with SHA-256 checksum and audit_id |
| Policy admission | Enforced approval requires policy, freshness, verifier/config, trust, SafetyCase, decision trace, and valid approval receipt evidence |
| Execution adapter | Phase 3 data-only adapter envelope, deterministic replay proof, dry-run dispatch firewall, null-backend admission, capability lease, and command quarantine; no publishing or runtime execution |
| Robotics (ROS 2) | Modelled as inert mapping data only — no ROS imports or node execution |
| LLM SDK in core | Forbidden — all phases |
| Production safety claims | None — not yet proven |
| Validation command | `python scripts/verify.py verify` (`make verify` delegates to it) |

Correctness claims are bounded by: typed contracts, deterministic replay, property-based invariant tests, unit/adversarial tests, scenario coverage, receipt validation, and quality gates passing cleanly. Aegis currently proves deterministic structural authority only; it does not claim human/user authentication, PKI signatures, legal non-repudiation, durable persistence, or real robot/runtime safety.

## Pipeline

```
Intent → Validation → Planning → Audit → Policy Admission → Execution Gate → Adapter Boundary
```

Each layer is a separate Python package under `src/aegis/`. Data flows forward only. No layer imports from a layer ahead of it. Cross-layer data uses typed contracts defined in `src/aegis/contracts/`.

The Phase 3 adapter path is a separate pure API after `PipelineResult(ALLOWED)`:

```python
build_execution_adapter_envelope(pipeline_result, adapter_mapping, target_runtime)
prove_adapter_replay(adapter_replay_request)
build_runtime_dispatch_plan(envelope, replay_proof)
evaluate_dispatch_firewall(plan, envelope, replay_proof)
admit_runtime_backend(admission_request)
issue_runtime_capability_lease(...)
quarantine_runtime_command(...)
build_operator_approval_receipt(...)
evaluate_quarantine_release(...)
```

It returns checksum-bound adapter, dry-run dispatch, backend admission, lease, quarantine, and approval/release evidence. It does not publish ROS messages, call services, execute actions, move robots, open sockets, contact an executable runtime backend, queue work, or claim physical safety.

Supported imports for external callers are package-level exports such as `aegis.execution` and
`aegis.contracts`. Direct `aegis_*` implementation-module imports are private compatibility
details and may intentionally break outside the supported API.

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
python scripts\verify.py verify
```

This runs (in order): `pyright --project pyproject.toml`, `ruff check`, `ruff format --check`, `pytest tests --cov`, and `pytest tests/invariants`. The full coverage pass includes adversarial tests.

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
├── execution/    # Phase 3: non-executing adapter, replay, and dispatch dry-run validation
├── aegis_errors.py     # Typed exception hierarchy
├── aegis_logging.py    # Structured logging
├── aegis_constants.py  # All constants
└── aegis_config.py     # Config injection

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
