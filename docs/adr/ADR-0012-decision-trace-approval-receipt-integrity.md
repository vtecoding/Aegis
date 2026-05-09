# ADR-0012: Decision Trace, Approval Receipt, and Release Evidence Integrity

## Status

Accepted

## Context

ADR-0009 prevents bad world snapshot evidence from reaching policy, ADR-0010 prevents bad verifier/config authority from manufacturing trusted evidence, and ADR-0011 closes the admissibility gap before freshness and trust. Aegis can now block or allow through a deterministic admission chain, but an external consumer still needs a tamper-evident proof of exactly why a final pipeline decision happened.

A plain final enum is not enough. A future integration must not be able to claim that the pipeline allowed a plan without proving that validation, planning, audit, admissibility, freshness, verifier certification, trust-policy configuration, world snapshot trust, policy evaluation, SafetyCase, policy admission, and gate decision all bound to the same canonical evidence chain.

## Decision

Add deterministic Decision Trace and Approval Receipt v1 contracts to every orchestrated `PipelineResult` returned by `run_pipeline`.

Each `DecisionTraceStep` records a canonical stage name, status, reason, input checksum, output checksum, predecessor checksum, immutable JSON metadata, and a deterministic stage checksum. A `DecisionTrace` is valid only when stages are unique, ordered according to the canonical pipeline chain, predecessor links are intact, each stage checksum matches recomputation, and the trace checksum matches all stage checksums.

Each `ApprovalReceipt` binds the final outcome to the raw intent, validation result, command plan, audited plan, world snapshot evidence, admissibility, freshness, verifier certification, trust-policy config validation, trust result, policy result, SafetyCase, policy admission record, gate decision, and decision trace checksums that actually ran. Partial blocked or invalid results may omit stages that were not reached, but they must not carry fake late-stage checksums.

`PipelineOutcome.ALLOWED` now requires:

- a valid `DecisionTrace`
- a valid `ApprovalReceipt`
- valid `ApprovalReceiptValidationResult`
- the full required stage chain from raw intent through final gate
- receipt bindings that match the concrete `PipelineResult` fields

If the policy/admission/gate chain reaches ALLOW but receipt validation fails, the orchestrator must return `PipelineOutcome.ERROR` with `APPROVAL_RECEIPT_INTEGRITY_FAILED` rather than returning an unprovable approval.

## Consequences

- Final approvals are externally auditable without trusting logs, process memory, comments, or developer claims.
- Direct gate decisions cannot be misrepresented as full pipeline approvals.
- Missing, reordered, duplicated, forged, stale, mismatched, or partial allow-grade receipt stages fail closed.
- Receipt construction remains deterministic and pure: no I/O, clocks, randomness, network calls, middleware, simulation, hardware, LLMs, or background jobs.
- This does not prove physical robot safety, semantic truth of world facts, cryptographic soundness of future signatures, or real-world sensor correctness.

## Alternatives Considered

- **Scenario runner first:** Rejected for this phase. Scenario reports are useful, but without receipt integrity they still verify final outcomes rather than externally auditable approval evidence.
- **Signed receipts now:** Rejected for this phase. Signing an incomplete receipt would give cryptographic authority to incomplete evidence. Structural integrity comes first.
- **Runtime logging:** Rejected. Logs are observability artifacts; the receipt is part of the deterministic contract.