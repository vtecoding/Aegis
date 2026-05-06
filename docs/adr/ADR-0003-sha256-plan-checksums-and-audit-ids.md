# ADR-0003: SHA-256 for Plan Checksums and Audit Identifiers

## Status

Accepted — Phase 1

## Context

The audit layer must produce a tamper-evident receipt for every command plan that passes
through the pipeline. Two values are required:

1. A **content checksum** that binds to the executable steps in the plan, so any mutation
   of plan steps invalidates the receipt.
2. An **audit ID** that uniquely identifies the specific audit event, binding the checksum
   to the plan identity and the execution context.

The gate layer then recomputes both values from the original inputs and compares them to
the stored values — providing integrity verification before any downstream action.

The design questions were: which hash algorithm, which field set, and in what order?

## Decision

Both checksums use **SHA-256** (via Python stdlib `hashlib.sha256`).

**`plan_checksum`** hashes a canonical JSON encoding of the executable steps only:
- `step_type.value` for each step
- `parameters` with keys sorted deterministically
- `sequence` for each step
- `plan_id` and execution context fields are **excluded**

**`plan_audit_id`** hashes a canonical JSON encoding of:
- `checksum` (the `plan_checksum` result)
- `plan_id`
- `context.request_id`, `context.submitted_at` (ISO-8601), `context.policy_version`,
  `context.run_id` (or `null`)

This separation means:
- Two plans with identical executable steps always share the same `checksum`.
- The `audit_id` distinguishes them because it binds context.

The gate verifies both independently and in order: `checksum` first, then `audit_id`.

JSON encoding uses `separators=(",", ":")` (no whitespace) and `sort_keys=True` to
guarantee a canonical byte sequence regardless of Python dict insertion order.

## Consequences

**Positive:**
- SHA-256 is widely available, collision-resistant, and well-understood.
- Pure stdlib: no external cryptography dependency.
- Canonical JSON encoding makes the hash stable across Python versions.
- Step-only checksum means audit receipts are comparable across different callers
  submitting the same logical command.
- Gate recomputation is a full integrity proof, not a signature check — no key material
  is required or stored.

**Negative:**
- SHA-256 produces 64-character hex strings; these are stored as plain strings in
  contracts. A future phase could encode them as bytes for compactness.
- The canonical JSON encoding must be maintained in sync between `audit/checksum.py`
  and any external system that tries to recompute checksums independently.

## Alternatives Considered

**HMAC-SHA-256 with a secret key:** Rejected for Phase 1. Key management is out of scope
until Phase 2 introduces a trust boundary. The gate is currently an integrity check within
a single process, not a cross-system authenticity proof.

**MD5 or SHA-1:** Rejected. Collision vulnerabilities are documented. Safety infrastructure
must not use deprecated hash algorithms.

**Custom rolling hash or CRC:** Rejected. Non-standard hash functions require justification
and audit. SHA-256 is NIST-standard and universally understood.

**Protobuf canonical encoding instead of JSON:** Considered for future phases. Not adopted
for Phase 1 because the rest of the pipeline uses JSON-typed contracts.
