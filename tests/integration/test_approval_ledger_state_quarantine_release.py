"""Integration tests for ADR-0026 state boundary with quarantine release."""

from __future__ import annotations

from tests.operator_authority_fixtures import OperatorAuthorityParts, operator_authority_parts

from aegis.execution.aegis_approval_ledger import append_approval_ledger_entry
from aegis.execution.aegis_approval_ledger_head import (
    append_to_approval_ledger_head,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
)
from aegis.execution.aegis_approval_ledger_state import build_approval_ledger_state_snapshot
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)

_SOURCE = "canonical-memory-authority"


def _evaluate(
    parts: OperatorAuthorityParts,
    *,
    ledger_prior: object | None = None,
    ledger_head: object | None = None,
    ledger_epoch: object | None = None,
    state_snapshot: object | None = None,
    state_source_id: object | None = None,
    state_enforced: bool = False,
) -> QuarantineReleaseDecision:
    p = parts
    ctx = p.context_authority.context_checksum
    return evaluate_quarantine_release(
        quarantine=p.quarantine,
        approval=p.approval,
        approval_replay_validation=p.replay_validation,
        capability_lease=p.capability_lease,
        dispatch_plan=p.dispatch_plan,
        backend_admission_decision=p.backend_admission_decision,
        backend_descriptor=p.backend_descriptor,
        authority_manifest=p.backend_authority_manifest,
        registry_checksum=p.backend_registry.registry_checksum,
        backend_certification=p.backend_certification,
        backend_replay_proof=p.backend_replay_proof,
        firewall_decision=p.firewall_decision,
        context_authority_checksum=ctx,
        current_lease_epoch=1,
        approval_ledger_prior_entries=ledger_prior,
        approval_ledger_head=ledger_head,
        approval_ledger_session_epoch=ledger_epoch,
        approval_ledger_state_snapshot=state_snapshot,
        approval_ledger_state_source_id=state_source_id,
        approval_ledger_state_enforced=state_enforced,
    )


def _baseline(parts: OperatorAuthorityParts):
    ctx = parts.context_authority.context_checksum
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=ctx,
        prior_entries=(),
    )
    manifest = build_ledger_epoch_manifest(
        session_epoch=1,
        context_authority_checksum=ctx,
        backend_admission_checksum=parts.backend_admission_decision.decision_checksum,
    )
    snapshot = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    return head, manifest, snapshot


def test_matching_state_snapshot_allows_release() -> None:
    parts = operator_authority_parts(request_id="state-integration-positive")
    head, _, snapshot = _baseline(parts)
    release = _evaluate(
        parts,
        ledger_prior=(),
        ledger_head=head,
        ledger_epoch=1,
        state_snapshot=snapshot,
        state_source_id=_SOURCE,
    )
    assert release.status == "RELEASED_DRY_RUN"


def test_mismatched_state_snapshot_blocks_release() -> None:
    parts = operator_authority_parts(request_id="state-integration-mismatch")
    head, _, _ = _baseline(parts)
    release_prev = _evaluate(parts, ledger_prior=(), ledger_head=head, ledger_epoch=1)
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release_prev.status,
        release_decision_checksum=release_prev.decision_checksum,
    )
    advanced_head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=parts.context_authority.context_checksum,
        prior_entries=(entry,),
    )
    stale_snapshot = build_approval_ledger_state_snapshot(
        ledger_head=head,
        ledger_epoch_manifest=build_ledger_epoch_manifest(
            session_epoch=1,
            context_authority_checksum=parts.context_authority.context_checksum,
            backend_admission_checksum=parts.backend_admission_decision.decision_checksum,
        ),
        state_source_id=_SOURCE,
    )
    blocked = _evaluate(
        parts,
        ledger_prior=(entry,),
        ledger_head=advanced_head,
        ledger_epoch=1,
        state_snapshot=stale_snapshot,
        state_source_id=_SOURCE,
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code
        == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID.value
    )


def test_state_source_drift_blocks_release() -> None:
    parts = operator_authority_parts(request_id="state-integration-source-drift")
    head, _, snapshot = _baseline(parts)
    blocked = _evaluate(
        parts,
        ledger_prior=(),
        ledger_head=head,
        ledger_epoch=1,
        state_snapshot=snapshot,
        state_source_id="drifted-authority",
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code
        == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID.value
    )


def test_state_enforced_mode_requires_snapshot() -> None:
    parts = operator_authority_parts(request_id="state-integration-required")
    head, _, _ = _baseline(parts)
    blocked = _evaluate(
        parts,
        ledger_prior=(),
        ledger_head=head,
        ledger_epoch=1,
        state_snapshot=None,
        state_enforced=True,
    )
    assert blocked.status == "BLOCKED"
    assert (
        blocked.reason_code
        == CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED.value
    )


def test_append_advances_head_snapshot_and_stays_releasable() -> None:
    parts = operator_authority_parts(request_id="state-integration-append")
    head0, manifest, snapshot0 = _baseline(parts)
    release1 = _evaluate(
        parts,
        ledger_prior=(),
        ledger_head=head0,
        ledger_epoch=1,
        state_snapshot=snapshot0,
        state_source_id=_SOURCE,
    )
    append = append_to_approval_ledger_head(
        prior_entries=(),
        head=head0,
        release_status=release1.status,
        release_decision_checksum=release1.decision_checksum,
    )
    snapshot1 = build_approval_ledger_state_snapshot(
        ledger_head=append.new_head,
        ledger_epoch_manifest=manifest,
        state_source_id=_SOURCE,
    )
    release2 = _evaluate(
        parts,
        ledger_prior=(append.new_entry,),
        ledger_head=append.new_head,
        ledger_epoch=1,
        state_snapshot=snapshot1,
        state_source_id=_SOURCE,
    )
    assert append.new_head.latest_sequence_index == 0
    assert snapshot1.latest_sequence_index == 0
    assert release2.status == "RELEASED_DRY_RUN"
