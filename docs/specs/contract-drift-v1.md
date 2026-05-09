# Contract Drift v1 Specification

## Summary

Contract Drift v1 is the ADR-0014 governance sentinel for approval-path authority fields. It is
pure, deterministic, and test-only/governance-only; it does not participate in runtime execution.

## Goals

- Maintain an explicit manifest for every approval-path contract.
- Classify dataclass fields as authoritative or non-authoritative.
- Fail when dataclass fields are added without manifest coverage.
- Fail when manifests name fields that no longer exist.
- Require every manifest to name the checksum or identity function that binds its authority.

## Non-Goals

- No runtime policy decisions.
- No dynamic schema discovery outside imported dataclass metadata.
- No external registry, filesystem reads, network calls, or mutable global state.

## Contracts

- `AuthorityFieldManifest` records contract name, authoritative fields, non-authoritative fields,
  checksum function, and reason.
- `ApprovalPathContract` pairs a dataclass type with its manifest.
- `evaluate_contract_drift()` returns `ContractDriftResult` with stable error strings.
- `assert_no_contract_drift()` raises `ValueError` when drift exists.

## Invariants

- Every dataclass field is classified exactly once.
- Every manifest targets the dataclass it is paired with.
- Duplicate manifests for the same contract fail.
- Missing checksum function or reason fails.