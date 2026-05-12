# ADR-0025: Ledger Head, Epoch, Authority, and Enforced Release

## Status

Accepted.

## Context

ADR-0024 introduced a hash-linked `ApprovalLedgerEntry` chain, allowing callers to supply an
optional `approval_ledger_prior_entries` tuple for tamper-evident ordering evidence. However, the
chain alone does not bind epoch, session context authority, or enforce that the head is the
current canonical snapshot of ledger state. A caller that supplies a head from an old epoch, a
head derived from a different authority context, or a head that does not match the current prior
entries prefix can silently bypass the intended epoch isolation.

Additionally, the pre-ADR-0025 path allows `approval_ledger_head=None` with
`approval_ledger_prior_entries` non-None, meaning the ledger head gate is optional and may be
omitted. Callers that supply a head but omit prior entries must be blocked, as this combination
bypasses both the chain validation and the head epoch binding simultaneously.

The deterministic core must still not add filesystem persistence, network transport, async
scheduling, authentication providers, digital signatures, PKI, ROS, runtime execution, queues,
or physical safety claims.

## Decision

Aegis adds ADR-0025 deterministic ledger head, epoch manifest, and enforced release contracts:

- `ApprovalLedgerHead` binds `ledger_contract_version`, `session_epoch`, `latest_sequence_index`,
  `latest_entry_checksum`, `genesis_checksum`, `context_authority_checksum`, and `head_checksum`.
  Direct construction without the internal construction token raises
  `APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION`. The `latest_sequence_index` is `-1` for an empty
  ledger prefix and equals the last entry's `sequence_index` otherwise.

- `build_approval_ledger_head(*, session_epoch, context_authority_checksum, prior_entries)` is
  the only public construction gate. It validates the prior prefix chain via
  `approval_ledger_prior_chain_block_reason()`, then emits a head whose tip, sequence, and genesis
  fields match the validated chain state.

- `append_to_approval_ledger_head(*, prior_entries, head, release_status, release_decision_checksum)`
  validates both the head-to-chain consistency and the chain prefix, appends one entry, and
  returns an `ApprovalLedgerAppendResult` binding the new entry, new head, and a chain validation
  result. Direct construction of `ApprovalLedgerAppendResult` is blocked.

- `validate_approval_ledger_head(*, head, prior_entries, context_authority_checksum, session_epoch)`
  returns an `ApprovalLedgerHeadValidationResult` with `VALID` or `BLOCKED` and one of the
  `ApprovalLedgerHeadReason` codes.

- `LedgerEpochManifest` binds `manifest_id`, `session_epoch`, `context_authority_checksum`, and
  `backend_admission_checksum`. Built by `build_ledger_epoch_manifest()`. No construction token
  is required; the builder is the sole gate.

- `approval_ledger_prior_chain_quarantine_head_block_reason(*, head, prior_entries,
  context_authority_checksum, session_epoch)` maps head validation failures to
  `CommandQuarantineReason`.

- In `evaluate_quarantine_release()` and `quarantine_release_block_reason()`, two new optional
  kwargs are added: `approval_ledger_head` and `approval_ledger_session_epoch`. When
  `approval_ledger_head` is supplied:
  - If `approval_ledger_prior_entries` is `None`, returns
    `COMMAND_QUARANTINE_APPROVAL_LEDGER_ENFORCED_MODE_BYPASS`.
  - Otherwise runs head validation; head failures map to
    `COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID`.
  - When `approval_ledger_head` is `None`, the pre-ADR-0025 path is unchanged.

- Two new `CommandQuarantineReason` codes:
  - `COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID`
  - `COMMAND_QUARANTINE_APPROVAL_LEDGER_ENFORCED_MODE_BYPASS`

- A new constant `APPROVAL_LEDGER_HEAD_CONTRACT_VERSION = "approval-ledger-head-v1"` is added
  to `aegis_constants.py`.

- Field sentinels are declared in `aegis_approval_ledger_head_fields.py`.

- `ApprovalLedgerHead`, `LedgerEpochManifest`, and `ApprovalLedgerAppendResult` are registered
  in `ADAPTER_AUTHORITY_CONTRACTS` in `aegis_adapter_fields.py`.

- Five new `ScenarioCategory` values are added:
  `APPROVAL_LEDGER_HEAD_POSITIVE`, `APPROVAL_LEDGER_HEAD_STALE_EPOCH`,
  `APPROVAL_LEDGER_HEAD_CONTEXT_DRIFT`, `APPROVAL_LEDGER_HEAD_TIP_MISMATCH`,
  `APPROVAL_LEDGER_HEAD_ENFORCED_MODE_BYPASS`.

## Consequences

- A head built from a prior epoch, a different context authority, or a mismatched chain tip is
  deterministically rejected before any release is emitted.
- Callers that supply a head but omit prior entries are blocked with an explicit reason code,
  preventing silent bypass of both the chain validation and epoch binding.
- The genesis head remains the deterministic anchor; any head referencing a different genesis is
  blocked immediately.
- The ledger does not authenticate operators, sign decisions, or prove robot safety; it only
  binds ordered release decision checksums under explicit epoch and context authority rules.
- Persistence, network transport, and PKI remain explicitly out of scope.

## Alternatives Considered

- Head as a simple tuple of checksums. Rejected because a typed dataclass with construction
  gating provides the same tamper-evidence guarantees as the ADR-0024 entry chain and maintains
  consistency with the rest of the evidence boundary pattern.
- Mandatory head on all releases. Rejected because this would be a breaking change to the
  pre-ADR-0024 call sites; opt-in enforced mode is sufficient.
- Separate epoch registry as mutable state. Rejected because hidden mutable state breaks
  replayable evidence and contradicts ADR-0023's explicit binding discipline.
