# ADR-0013: Deterministic Scenario Runner and Evil-Twin Coverage Gate

## Status

Accepted

## Context

ADR-0012 made individual pipeline decisions receipt-verifiable by returning a
hash-linked `DecisionTrace`, an `ApprovalReceipt`, and a receipt validation result from
the orchestrated pipeline. That proves one decision boundary, but release evidence also
needs a deterministic suite that repeatedly exercises canonical known-good, known-bad,
and adversarial cases through the real `run_pipeline` path.

A final enum match is not enough. A scenario passes only when the pipeline result and the
receipt-proven decision path independently match the expected outcome, reason, stopping
stage, required stages, forbidden stages, and checksum recomputation. Evil-twin cases must
also prove that forged, stale, mismatched, replayed, overclaimed, or direct-gate-only
evidence fails closed.

## Decision

Add a first-class deterministic scenario layer in `src/aegis/scenarios/`:

- `contracts.py` defines immutable `ScenarioDefinition`, `ScenarioExpectation`,
  `ScenarioRunResult`, `ScenarioSuiteResult`, `CoverageGateResult`, scenario categories,
  violations, and closed evil-twin mutation kinds.
- `fixtures.py` defines the canonical ADR-0013 scenario matrix and deterministic fixture
  factory using real policy, snapshot, trust, verifier, and intent contracts.
- `runner.py` adds `run_pipeline_scenario`, `run_scenario_suite`, and
  `run_canonical_scenario_suite`, all of which call the real `run_pipeline` path.
- `validators.py` validates actual outcome, reason, terminal stage, stage path,
  receipt validity, trace validity, forbidden late artifacts, and stable checksums.
- `coverage.py` implements a required-category coverage gate over the closed scenario
  matrix.

Receipt-forgery scenarios are modeled as deterministic evil twins above the pipeline:
the runner first executes the real pipeline and then applies an enum-selected mutation to
the returned trace or receipt. The expectation validator must classify that evidence as
receipt-integrity failure. This keeps the pipeline path real while avoiding callable or
plugin-based mutation injection.

The legacy JSON demo scenario API remains available for Phase 1 fixture tests.

## Consequences

- Every required scenario category must be represented or the coverage gate fails.
- Allowed scenarios must prove a valid full receipt path and stable checksums.
- Blocked scenarios must prove the expected upstream stopping stage and absence of late
  approval artifacts.
- Evil-twin scenarios must fail closed without becoming full pipeline approvals.
- Direct gate `ALLOWED` evidence is explicitly rejected as a full pipeline approval.
- The scenario layer remains in-process, deterministic, pure, and CI-friendly.

## Non-Goals

- No ROS 2, simulation runtime, hardware, sensors, middleware, network calls, filesystem
  reads, async jobs, LLM calls, external signing, or runtime actuation.
- No physical robot safety claim.
- No semantic truth claim about supplied world facts.
- No replacement for unit, contract, integration, adversarial, or invariant tests.
- No log-derived authority.

## Alternatives Considered

- Signed receipts now: rejected because signatures over insufficiently exercised receipt
  models create false authority.
- Simulation next: rejected because simulation would expand scope before deterministic
  decision-boundary evidence has evil-twin coverage.
- Pytest fixtures only: rejected because Aegis needs a reusable scenario artifact for
  release gates and future audit evidence bundles.
- Plugin-based scenario runner: rejected because flexibility increases bypass surface;
  the current phase uses a closed required category matrix.