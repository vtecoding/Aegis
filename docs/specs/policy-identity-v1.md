# Policy Identity v1 Specification

## Summary

Policy Identity v1 makes policy authority explicit and checksum-bound for Phase 2 approvals.

## Goals

- Bind policy ID, version, schema version, authority, effective time, supersession checksum,
  rules, capabilities, default decision, and metadata into one deterministic SHA-256 checksum.
- Preserve the legacy `version` alias for existing callers while making `policy_version` the
  explicit authority field.
- Propagate policy identity through policy evaluation, SafetyCase, policy admission, decision
  trace, and approval receipt bindings.

## Non-Goals

- No policy registry or filesystem-loaded policy source.
- No wall-clock effective-time evaluation inside the deterministic core.
- No semantic claim that a policy proves physical robot safety.

## Approval Requirements

An allowed approval must carry:

- `policy_id`
- `policy_version`
- `policy_schema_version`
- `policy_checksum`
- `policy_authority`

The checksum is recomputed with canonical JSON using sorted keys, compact separators, and
`allow_nan=False`. A supplied checksum must match recomputation.