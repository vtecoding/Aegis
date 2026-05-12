"""Deterministic approval-ledger repository boundary for ADR-0027."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Literal, cast

from aegis.aegis_constants import APPROVAL_LEDGER_REPOSITORY_CONTRACT_VERSION
from aegis.execution.aegis_approval_ledger import ApprovalLedgerEntry
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerHead,
    LedgerEpochManifest,
    append_to_approval_ledger_head,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
    recompute_approval_ledger_head_checksum,
    recompute_ledger_epoch_manifest_checksum,
)
from aegis.execution.aegis_approval_ledger_state import (
    ApprovalLedgerStateSnapshot,
    ApprovalLedgerStateTransition,
    build_approval_ledger_state_snapshot,
    build_approval_ledger_state_transition,
    recompute_approval_ledger_state_transition_checksum,
    validate_approval_ledger_state_snapshot,
    validate_approval_ledger_state_transition,
)
from aegis.execution.aegis_capability_lease import checksum_or_fallback

type RepositoryCommitStatusValue = Literal["COMMITTED", "BLOCKED"]
type CanonicalApprovalLedgerRepositoryValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalApprovalLedgerRepositoryValue]
    | dict[str, CanonicalApprovalLedgerRepositoryValue]
)

_COMMIT_RESULT_TOKEN = object()


class ApprovalLedgerRepositoryReason(StrEnum):
    """Stable ADR-0027 repository boundary reason codes."""

    APPROVAL_LEDGER_REPOSITORY_COMMITTED = "APPROVAL_LEDGER_REPOSITORY_COMMITTED"
    APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION = (
        "APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION"
    )
    APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE = "APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE"
    APPROVAL_LEDGER_REPOSITORY_STALE_READ_ACCEPTED = (
        "APPROVAL_LEDGER_REPOSITORY_STALE_READ_ACCEPTED"
    )
    APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE = "APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE"
    APPROVAL_LEDGER_REPOSITORY_FORK_ACCEPTED = "APPROVAL_LEDGER_REPOSITORY_FORK_ACCEPTED"
    APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ACCEPTED = "APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ACCEPTED"
    APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED = (
        "APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED"
    )
    APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT = "APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT"
    APPROVAL_LEDGER_REPOSITORY_FORGED_APPEND_RESULT = (
        "APPROVAL_LEDGER_REPOSITORY_FORGED_APPEND_RESULT"
    )
    APPROVAL_LEDGER_REPOSITORY_COMMIT_WITHOUT_CAS_PROOF = (
        "APPROVAL_LEDGER_REPOSITORY_COMMIT_WITHOUT_CAS_PROOF"
    )
    APPROVAL_LEDGER_REPOSITORY_COMMIT_HEAD_MISMATCH = (
        "APPROVAL_LEDGER_REPOSITORY_COMMIT_HEAD_MISMATCH"
    )


@dataclass(frozen=True, slots=True)
class ApprovalLedgerRepositoryAuthorityEvidence:
    """Deterministic authority inputs for repository append proposal."""

    prior_entries: tuple[ApprovalLedgerEntry, ...]
    ledger_head: ApprovalLedgerHead
    ledger_epoch_manifest: LedgerEpochManifest
    state_source_id: str
    authority_evidence_checksum: str


@dataclass(frozen=True, slots=True, init=False)
class RepositoryCommitResult:
    """Checksum-bound CAS commit proof for one proposed transition."""

    status: RepositoryCommitStatusValue
    reason_code: str
    expected_previous_snapshot_checksum: str
    previous_snapshot_checksum: str
    committed_snapshot_checksum: str
    committed_transition_checksum: str
    repository_epoch_manifest_checksum: str
    expected_previous_snapshot_matched: bool
    transition_valid: bool
    new_snapshot_became_current: bool
    stale_write_rejected: bool
    fork_rejected: bool
    rollback_rejected: bool
    cross_epoch_rejected: bool
    commit_result_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        expected_previous_snapshot_checksum: object,
        previous_snapshot_checksum: object,
        committed_snapshot_checksum: object,
        committed_transition_checksum: object,
        repository_epoch_manifest_checksum: object,
        expected_previous_snapshot_matched: object,
        transition_valid: object,
        new_snapshot_became_current: object,
        stale_write_rejected: object,
        fork_rejected: object,
        rollback_rejected: object,
        cross_epoch_rejected: object,
        commit_result_checksum: str | None = None,
        _commit_token: object | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason_code)
        if normalized_status == "COMMITTED":
            if _commit_token is not _COMMIT_RESULT_TOKEN:
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMIT_WITHOUT_CAS_PROOF
                )
            if (
                normalized_reason
                != ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMITTED
            ):
                raise ValueError("COMMITTED result requires APPROVAL_LEDGER_REPOSITORY_COMMITTED")
        normalized_expected = _normalize_required_checksum(
            expected_previous_snapshot_checksum, "expected_previous_snapshot_checksum"
        )
        normalized_previous = _normalize_required_checksum(
            previous_snapshot_checksum, "previous_snapshot_checksum"
        )
        normalized_snapshot = _normalize_required_checksum(
            committed_snapshot_checksum, "committed_snapshot_checksum"
        )
        normalized_transition = _normalize_required_checksum(
            committed_transition_checksum, "committed_transition_checksum"
        )
        normalized_manifest = _normalize_required_checksum(
            repository_epoch_manifest_checksum, "repository_epoch_manifest_checksum"
        )
        expected_matched = _normalize_bool(
            expected_previous_snapshot_matched, "expected_previous_snapshot_matched"
        )
        transition_valid_flag = _normalize_bool(transition_valid, "transition_valid")
        became_current = _normalize_bool(new_snapshot_became_current, "new_snapshot_became_current")
        stale_rejected = _normalize_bool(stale_write_rejected, "stale_write_rejected")
        fork_rejected_flag = _normalize_bool(fork_rejected, "fork_rejected")
        rollback_rejected_flag = _normalize_bool(rollback_rejected, "rollback_rejected")
        cross_epoch_rejected_flag = _normalize_bool(cross_epoch_rejected, "cross_epoch_rejected")
        if normalized_status == "COMMITTED":
            required = (
                expected_matched,
                transition_valid_flag,
                became_current,
                stale_rejected,
                fork_rejected_flag,
                rollback_rejected_flag,
                cross_epoch_rejected_flag,
            )
            if not all(required):
                raise ValueError("COMMITTED result must prove all repository obligations")
        computed = repository_commit_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            expected_previous_snapshot_checksum=normalized_expected,
            previous_snapshot_checksum=normalized_previous,
            committed_snapshot_checksum=normalized_snapshot,
            committed_transition_checksum=normalized_transition,
            repository_epoch_manifest_checksum=normalized_manifest,
            expected_previous_snapshot_matched=expected_matched,
            transition_valid=transition_valid_flag,
            new_snapshot_became_current=became_current,
            stale_write_rejected=stale_rejected,
            fork_rejected=fork_rejected_flag,
            rollback_rejected=rollback_rejected_flag,
            cross_epoch_rejected=cross_epoch_rejected_flag,
        )
        normalized_commit_checksum = _normalize_supplied_checksum(
            commit_result_checksum, computed, "commit_result_checksum"
        )
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "expected_previous_snapshot_checksum", normalized_expected)
        object.__setattr__(self, "previous_snapshot_checksum", normalized_previous)
        object.__setattr__(self, "committed_snapshot_checksum", normalized_snapshot)
        object.__setattr__(self, "committed_transition_checksum", normalized_transition)
        object.__setattr__(self, "repository_epoch_manifest_checksum", normalized_manifest)
        object.__setattr__(self, "expected_previous_snapshot_matched", expected_matched)
        object.__setattr__(self, "transition_valid", transition_valid_flag)
        object.__setattr__(self, "new_snapshot_became_current", became_current)
        object.__setattr__(self, "stale_write_rejected", stale_rejected)
        object.__setattr__(self, "fork_rejected", fork_rejected_flag)
        object.__setattr__(self, "rollback_rejected", rollback_rejected_flag)
        object.__setattr__(self, "cross_epoch_rejected", cross_epoch_rejected_flag)
        object.__setattr__(self, "commit_result_checksum", normalized_commit_checksum)


@dataclass(frozen=True, slots=True)
class _StoredProposal:
    """Internal deterministic proposal evidence retained until commit."""

    transition: ApprovalLedgerStateTransition
    previous_snapshot: ApprovalLedgerStateSnapshot
    new_snapshot: ApprovalLedgerStateSnapshot
    new_head: ApprovalLedgerHead
    new_entry: ApprovalLedgerEntry
    prior_entries: tuple[ApprovalLedgerEntry, ...]


def build_approval_ledger_repository_authority_evidence(
    *,
    prior_entries: object,
    ledger_head: object,
    ledger_epoch_manifest: object,
    state_source_id: object,
) -> ApprovalLedgerRepositoryAuthorityEvidence:
    """Build deterministic authority evidence for proposing one append transition."""
    if not isinstance(prior_entries, tuple):
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
        )
    for item in cast(tuple[object, ...], prior_entries):
        if type(item) is not ApprovalLedgerEntry:
            raise ValueError(
                ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
            )
    if type(ledger_head) is not ApprovalLedgerHead:
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
        )
    if type(ledger_epoch_manifest) is not LedgerEpochManifest:
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
        )
    normalized_source = _normalize_required_text(state_source_id, "state_source_id")
    if ledger_head.head_checksum != recompute_approval_ledger_head_checksum(ledger_head):
        raise ValueError(ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT)
    if ledger_epoch_manifest.manifest_checksum != recompute_ledger_epoch_manifest_checksum(
        ledger_epoch_manifest
    ):
        raise ValueError(ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT)
    if ledger_epoch_manifest.session_epoch != ledger_head.session_epoch:
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED
        )
    if ledger_epoch_manifest.context_authority_checksum != ledger_head.context_authority_checksum:
        raise ValueError(ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT)
    checksum = approval_ledger_repository_authority_evidence_checksum(
        ledger_head_checksum=ledger_head.head_checksum,
        ledger_epoch_manifest_checksum=ledger_epoch_manifest.manifest_checksum,
        state_source_id=normalized_source,
        prior_entries_checksum=_prior_entries_checksum(
            cast(tuple[ApprovalLedgerEntry, ...], prior_entries)
        ),
    )
    return ApprovalLedgerRepositoryAuthorityEvidence(
        prior_entries=cast(tuple[ApprovalLedgerEntry, ...], prior_entries),
        ledger_head=ledger_head,
        ledger_epoch_manifest=ledger_epoch_manifest,
        state_source_id=normalized_source,
        authority_evidence_checksum=checksum,
    )


class InMemoryApprovalLedgerRepository:
    """Deterministic in-memory ADR-0027 repository with CAS commit semantics."""

    def __init__(
        self,
        *,
        initial_snapshot: object,
        initial_head: object,
        initial_prior_entries: object,
        ledger_epoch_manifest: object,
        state_source_id: object,
        repository_available: bool = True,
    ) -> None:
        if type(initial_snapshot) is not ApprovalLedgerStateSnapshot:
            raise ValueError(
                ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
            )
        if type(initial_head) is not ApprovalLedgerHead:
            raise ValueError(
                ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
            )
        if not isinstance(initial_prior_entries, tuple):
            raise ValueError(
                ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
            )
        for item in cast(tuple[object, ...], initial_prior_entries):
            if type(item) is not ApprovalLedgerEntry:
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
                )
        if type(ledger_epoch_manifest) is not LedgerEpochManifest:
            raise ValueError(
                ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
            )
        normalized_source = _normalize_required_text(state_source_id, "state_source_id")
        validation = validate_approval_ledger_state_snapshot(
            state_snapshot=initial_snapshot,
            ledger_head=initial_head,
            ledger_epoch_manifest=ledger_epoch_manifest,
            expected_state_source_id=normalized_source,
        )
        if validation.status != "VALID":
            raise ValueError(validation.reason)
        self._current_snapshot = initial_snapshot
        self._current_head = initial_head
        self._current_prior_entries = cast(tuple[ApprovalLedgerEntry, ...], initial_prior_entries)
        self._ledger_epoch_manifest = ledger_epoch_manifest
        self._state_source_id = normalized_source
        self._repository_available = repository_available
        self._pending_proposals: dict[str, _StoredProposal] = {}
        self._lock = Lock()

    def read_current_state(self, epoch_manifest: object) -> ApprovalLedgerStateSnapshot:
        """Return the current canonical snapshot for one epoch manifest."""
        with self._lock:
            self._assert_available()
            if type(epoch_manifest) is not LedgerEpochManifest:
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
                )
            if epoch_manifest.manifest_checksum != recompute_ledger_epoch_manifest_checksum(
                epoch_manifest
            ):
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT
                )
            if epoch_manifest.manifest_checksum != self._ledger_epoch_manifest.manifest_checksum:
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED
                )
            return self._detached_current_snapshot()

    def propose_append(
        self,
        previous_snapshot: object,
        release_decision: object,
        authority_evidence: object,
    ) -> ApprovalLedgerStateTransition:
        """Propose one append transition from a supplied previous snapshot."""
        with self._lock:
            self._assert_available()
            if type(previous_snapshot) is not ApprovalLedgerStateSnapshot:
                raise ValueError(
                    ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
                )
            evidence = _normalize_authority_evidence(authority_evidence)
            snapshot_validation = validate_approval_ledger_state_snapshot(
                state_snapshot=previous_snapshot,
                ledger_head=evidence.ledger_head,
                ledger_epoch_manifest=evidence.ledger_epoch_manifest,
                expected_state_source_id=evidence.state_source_id,
            )
            if snapshot_validation.status != "VALID":
                raise ValueError(snapshot_validation.reason)
            release_status = getattr(release_decision, "status", None)
            release_checksum = getattr(release_decision, "decision_checksum", None)
            append_result = append_to_approval_ledger_head(
                prior_entries=evidence.prior_entries,
                head=evidence.ledger_head,
                release_status=release_status,
                release_decision_checksum=release_checksum,
            )
            new_snapshot = build_approval_ledger_state_snapshot(
                ledger_head=append_result.new_head,
                ledger_epoch_manifest=evidence.ledger_epoch_manifest,
                state_source_id=evidence.state_source_id,
            )
            transition = build_approval_ledger_state_transition(
                previous_snapshot=previous_snapshot,
                append_result=append_result,
                new_snapshot=new_snapshot,
            )
            transition_validation = validate_approval_ledger_state_transition(
                transition=transition,
                previous_snapshot=previous_snapshot,
                append_result=append_result,
                new_snapshot=new_snapshot,
            )
            if transition_validation.status != "VALID":
                raise ValueError(transition_validation.reason)
            self._pending_proposals[transition.state_transition_checksum] = _StoredProposal(
                transition=transition,
                previous_snapshot=previous_snapshot,
                new_snapshot=new_snapshot,
                new_head=append_result.new_head,
                new_entry=append_result.new_entry,
                prior_entries=evidence.prior_entries,
            )
            return transition

    def commit_transition(
        self,
        transition: object,
        expected_previous_snapshot_checksum: object,
    ) -> RepositoryCommitResult:
        """Attempt CAS commit for one proposed transition."""
        with self._lock:
            current_snapshot_checksum = self._current_snapshot.state_snapshot_checksum
            expected_checksum = _normalize_required_checksum(
                expected_previous_snapshot_checksum, "expected_previous_snapshot_checksum"
            )
            current_manifest_checksum = self._ledger_epoch_manifest.manifest_checksum
            if not self._repository_available:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=checksum_or_fallback(
                        getattr(transition, "state_transition_checksum", None)
                    ),
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=True,
                )
            if type(transition) is not ApprovalLedgerStateTransition:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=checksum_or_fallback(
                        getattr(transition, "state_transition_checksum", None)
                    ),
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                )
            if (
                transition.state_transition_checksum
                != recompute_approval_ledger_state_transition_checksum(transition)
            ):
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_FORGED_APPEND_RESULT,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                )
            if expected_checksum != transition.previous_snapshot_checksum:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMIT_WITHOUT_CAS_PROOF,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=True,
                )
            if transition.ledger_epoch_manifest_checksum != current_manifest_checksum:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=False,
                )
            if expected_checksum != current_snapshot_checksum:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_LOST_UPDATE,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    expected_previous_snapshot_matched=False,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=True,
                )
            proposal = self._pending_proposals.get(transition.state_transition_checksum)
            if proposal is None:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_FORGED_APPEND_RESULT,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=True,
                )
            if proposal.previous_snapshot.state_snapshot_checksum != expected_checksum:
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_STALE_READ_ACCEPTED,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    expected_previous_snapshot_matched=False,
                    stale_write_rejected=False,
                )
            if (
                proposal.new_snapshot.latest_sequence_index
                != self._current_snapshot.latest_sequence_index + 1
            ):
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_FORK_ACCEPTED,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=False,
                    rollback_rejected=True,
                    cross_epoch_rejected=True,
                )
            if (
                proposal.new_snapshot.latest_sequence_index
                <= self._current_snapshot.latest_sequence_index
            ):
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_ROLLBACK_ACCEPTED,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=False,
                    cross_epoch_rejected=True,
                )
            if (
                proposal.new_snapshot.ledger_epoch_manifest_checksum
                != self._ledger_epoch_manifest.manifest_checksum
            ):
                return _blocked_commit_result(
                    reason=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_CROSS_EPOCH_COMMIT_ACCEPTED,
                    expected_previous_snapshot_checksum=expected_checksum,
                    previous_snapshot_checksum=current_snapshot_checksum,
                    committed_snapshot_checksum=current_snapshot_checksum,
                    committed_transition_checksum=transition.state_transition_checksum,
                    repository_epoch_manifest_checksum=current_manifest_checksum,
                    stale_write_rejected=True,
                    fork_rejected=True,
                    rollback_rejected=True,
                    cross_epoch_rejected=False,
                )
            self._current_snapshot = proposal.new_snapshot
            self._current_head = proposal.new_head
            self._current_prior_entries = proposal.prior_entries + (proposal.new_entry,)
            del self._pending_proposals[transition.state_transition_checksum]
            return RepositoryCommitResult(
                status="COMMITTED",
                reason_code=ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_COMMITTED,
                expected_previous_snapshot_checksum=expected_checksum,
                previous_snapshot_checksum=proposal.previous_snapshot.state_snapshot_checksum,
                committed_snapshot_checksum=proposal.new_snapshot.state_snapshot_checksum,
                committed_transition_checksum=proposal.transition.state_transition_checksum,
                repository_epoch_manifest_checksum=self._ledger_epoch_manifest.manifest_checksum,
                expected_previous_snapshot_matched=True,
                transition_valid=True,
                new_snapshot_became_current=True,
                stale_write_rejected=True,
                fork_rejected=True,
                rollback_rejected=True,
                cross_epoch_rejected=True,
                _commit_token=_COMMIT_RESULT_TOKEN,
            )

    @property
    def current_snapshot(self) -> ApprovalLedgerStateSnapshot:
        """Return repository current snapshot without mutating state."""
        with self._lock:
            return self._detached_current_snapshot()

    @property
    def current_head(self) -> ApprovalLedgerHead:
        """Return repository current head without mutating state."""
        with self._lock:
            return self._detached_current_head()

    def set_repository_availability(self, value: object) -> None:
        """Set deterministic availability flag for failure-path testing."""
        self._repository_available = _normalize_bool(value, "repository_available")

    def _assert_available(self) -> None:
        if not self._repository_available:
            raise ValueError(ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_UNAVAILABLE)

    def _detached_current_snapshot(self) -> ApprovalLedgerStateSnapshot:
        detached_head = self._detached_current_head()
        detached_manifest = self._detached_manifest()
        return build_approval_ledger_state_snapshot(
            ledger_head=detached_head,
            ledger_epoch_manifest=detached_manifest,
            state_source_id=self._current_snapshot.state_source_id,
        )

    def _detached_current_head(self) -> ApprovalLedgerHead:
        return build_approval_ledger_head(
            session_epoch=self._current_head.session_epoch,
            context_authority_checksum=self._current_head.context_authority_checksum,
            prior_entries=self._current_prior_entries,
        )

    def _detached_manifest(self) -> LedgerEpochManifest:
        return build_ledger_epoch_manifest(
            session_epoch=self._ledger_epoch_manifest.session_epoch,
            context_authority_checksum=self._ledger_epoch_manifest.context_authority_checksum,
            backend_admission_checksum=self._ledger_epoch_manifest.backend_admission_checksum,
        )


def approval_ledger_repository_authority_evidence_checksum(
    *,
    ledger_head_checksum: str,
    ledger_epoch_manifest_checksum: str,
    state_source_id: str,
    prior_entries_checksum: str,
) -> str:
    """Return checksum for one repository authority evidence packet."""
    return _sha256(
        {
            "approval_ledger_repository_contract_version": (
                APPROVAL_LEDGER_REPOSITORY_CONTRACT_VERSION
            ),
            "ledger_head_checksum": ledger_head_checksum,
            "ledger_epoch_manifest_checksum": ledger_epoch_manifest_checksum,
            "state_source_id": state_source_id,
            "prior_entries_checksum": prior_entries_checksum,
        }
    )


def repository_commit_result_checksum(
    *,
    status: RepositoryCommitStatusValue,
    reason_code: str,
    expected_previous_snapshot_checksum: str,
    previous_snapshot_checksum: str,
    committed_snapshot_checksum: str,
    committed_transition_checksum: str,
    repository_epoch_manifest_checksum: str,
    expected_previous_snapshot_matched: bool,
    transition_valid: bool,
    new_snapshot_became_current: bool,
    stale_write_rejected: bool,
    fork_rejected: bool,
    rollback_rejected: bool,
    cross_epoch_rejected: bool,
) -> str:
    """Return checksum for one repository commit result."""
    return _sha256(
        {
            "approval_ledger_repository_contract_version": (
                APPROVAL_LEDGER_REPOSITORY_CONTRACT_VERSION
            ),
            "status": status,
            "reason_code": reason_code,
            "expected_previous_snapshot_checksum": expected_previous_snapshot_checksum,
            "previous_snapshot_checksum": previous_snapshot_checksum,
            "committed_snapshot_checksum": committed_snapshot_checksum,
            "committed_transition_checksum": committed_transition_checksum,
            "repository_epoch_manifest_checksum": repository_epoch_manifest_checksum,
            "expected_previous_snapshot_matched": expected_previous_snapshot_matched,
            "transition_valid": transition_valid,
            "new_snapshot_became_current": new_snapshot_became_current,
            "stale_write_rejected": stale_write_rejected,
            "fork_rejected": fork_rejected,
            "rollback_rejected": rollback_rejected,
            "cross_epoch_rejected": cross_epoch_rejected,
        }
    )


def recompute_repository_commit_result_checksum(result: RepositoryCommitResult) -> str:
    """Recompute commit result checksum from authoritative fields."""
    return repository_commit_result_checksum(
        status=result.status,
        reason_code=result.reason_code,
        expected_previous_snapshot_checksum=result.expected_previous_snapshot_checksum,
        previous_snapshot_checksum=result.previous_snapshot_checksum,
        committed_snapshot_checksum=result.committed_snapshot_checksum,
        committed_transition_checksum=result.committed_transition_checksum,
        repository_epoch_manifest_checksum=result.repository_epoch_manifest_checksum,
        expected_previous_snapshot_matched=result.expected_previous_snapshot_matched,
        transition_valid=result.transition_valid,
        new_snapshot_became_current=result.new_snapshot_became_current,
        stale_write_rejected=result.stale_write_rejected,
        fork_rejected=result.fork_rejected,
        rollback_rejected=result.rollback_rejected,
        cross_epoch_rejected=result.cross_epoch_rejected,
    )


def _blocked_commit_result(
    *,
    reason: ApprovalLedgerRepositoryReason,
    expected_previous_snapshot_checksum: str,
    previous_snapshot_checksum: str,
    committed_snapshot_checksum: str,
    committed_transition_checksum: str,
    repository_epoch_manifest_checksum: str,
    expected_previous_snapshot_matched: bool = True,
    stale_write_rejected: bool = True,
    fork_rejected: bool = True,
    rollback_rejected: bool = True,
    cross_epoch_rejected: bool = True,
) -> RepositoryCommitResult:
    return RepositoryCommitResult(
        status="BLOCKED",
        reason_code=reason,
        expected_previous_snapshot_checksum=expected_previous_snapshot_checksum,
        previous_snapshot_checksum=previous_snapshot_checksum,
        committed_snapshot_checksum=committed_snapshot_checksum,
        committed_transition_checksum=committed_transition_checksum,
        repository_epoch_manifest_checksum=repository_epoch_manifest_checksum,
        expected_previous_snapshot_matched=expected_previous_snapshot_matched,
        transition_valid=False,
        new_snapshot_became_current=False,
        stale_write_rejected=stale_write_rejected,
        fork_rejected=fork_rejected,
        rollback_rejected=rollback_rejected,
        cross_epoch_rejected=cross_epoch_rejected,
    )


def _normalize_authority_evidence(value: object) -> ApprovalLedgerRepositoryAuthorityEvidence:
    if type(value) is not ApprovalLedgerRepositoryAuthorityEvidence:
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
        )
    expected_checksum = approval_ledger_repository_authority_evidence_checksum(
        ledger_head_checksum=value.ledger_head.head_checksum,
        ledger_epoch_manifest_checksum=value.ledger_epoch_manifest.manifest_checksum,
        state_source_id=value.state_source_id,
        prior_entries_checksum=_prior_entries_checksum(value.prior_entries),
    )
    if value.authority_evidence_checksum != expected_checksum:
        raise ValueError(ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_MUTATED_SNAPSHOT)
    return value


def _prior_entries_checksum(entries: tuple[ApprovalLedgerEntry, ...]) -> str:
    return _sha256(
        {
            "approval_ledger_repository_contract_version": (
                APPROVAL_LEDGER_REPOSITORY_CONTRACT_VERSION
            ),
            "prior_entries": [entry.entry_checksum for entry in entries],
        }
    )


def _normalize_status(value: object) -> RepositoryCommitStatusValue:
    if value in {"COMMITTED", "BLOCKED"}:
        return cast(RepositoryCommitStatusValue, value)
    raise ValueError("status must be COMMITTED or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(char.isalnum() or char == "_" for char in normalized):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(
            ApprovalLedgerRepositoryReason.APPROVAL_LEDGER_REPOSITORY_RUNTIME_OBJECT_INJECTION
        )
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if checksum_or_fallback(normalized) != normalized:
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied_checksum, field_name)
    if normalized is None:
        return computed_checksum
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _normalize_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be bool")
    return value


def _sha256(payload: Mapping[str, CanonicalApprovalLedgerRepositoryValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalApprovalLedgerRepositoryValue],
) -> dict[str, CanonicalApprovalLedgerRepositoryValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalApprovalLedgerRepositoryValue,
) -> CanonicalApprovalLedgerRepositoryValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalApprovalLedgerRepositoryValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "ApprovalLedgerRepositoryAuthorityEvidence",
    "ApprovalLedgerRepositoryReason",
    "InMemoryApprovalLedgerRepository",
    "RepositoryCommitResult",
    "RepositoryCommitStatusValue",
    "approval_ledger_repository_authority_evidence_checksum",
    "build_approval_ledger_repository_authority_evidence",
    "recompute_repository_commit_result_checksum",
    "repository_commit_result_checksum",
]
