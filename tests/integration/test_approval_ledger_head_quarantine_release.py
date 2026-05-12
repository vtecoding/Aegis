"""Integration tests for ADR-0025 approval ledger head with quarantine release."""

from __future__ import annotations

from tests.operator_authority_fixtures import OperatorAuthorityParts, operator_authority_parts

from aegis.execution.aegis_approval_ledger import append_approval_ledger_entry
from aegis.execution.aegis_approval_ledger_head import (
    build_approval_ledger_head,
)
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)

_CTX_FALLBACK = None


def _evaluate(
    parts: OperatorAuthorityParts,
    *,
    ledger_prior: object | None = None,
    ledger_head: object | None = None,
    ledger_epoch: object | None = None,
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
    )


def test_head_gated_release_passes() -> None:
    parts = operator_authority_parts(request_id="head-integration-positive")
    ctx = parts.context_authority.context_checksum
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=ctx,
        prior_entries=(),
    )
    release = _evaluate(parts, ledger_prior=(), ledger_head=head, ledger_epoch=1)
    assert release.status == "RELEASED_DRY_RUN"


def test_head_tip_mismatch_blocks() -> None:
    parts = operator_authority_parts(request_id="head-integration-tip-mismatch")
    ctx = parts.context_authority.context_checksum

    from tests.command_quarantine_fixtures import quarantine_release_decision

    release_prev = quarantine_release_decision(request_id="head-integration-tip-mismatch-prev")
    entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=release_prev.status,
        release_decision_checksum=release_prev.decision_checksum,
    )
    head_with_entry = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=ctx,
        prior_entries=(entry,),
    )
    blocked = _evaluate(
        parts,
        ledger_prior=(),
        ledger_head=head_with_entry,
        ledger_epoch=1,
    )
    assert blocked.status == "BLOCKED"
    assert blocked.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID.value
    )


def test_stale_epoch_blocks() -> None:
    parts = operator_authority_parts(request_id="head-integration-stale-epoch")
    ctx = parts.context_authority.context_checksum
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=ctx,
        prior_entries=(),
    )
    blocked = _evaluate(parts, ledger_prior=(), ledger_head=head, ledger_epoch=2)
    assert blocked.status == "BLOCKED"
    assert blocked.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID.value
    )


def test_context_drift_blocks() -> None:
    parts = operator_authority_parts(request_id="head-integration-context-drift")
    different_ctx = "e" * 64
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=different_ctx,
        prior_entries=(),
    )
    blocked = _evaluate(parts, ledger_prior=(), ledger_head=head, ledger_epoch=1)
    assert blocked.status == "BLOCKED"
    assert blocked.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID.value
    )


def test_enforced_mode_bypass_blocks_when_head_supplied_but_prior_none() -> None:
    parts = operator_authority_parts(request_id="head-integration-bypass")
    ctx = parts.context_authority.context_checksum
    head = build_approval_ledger_head(
        session_epoch=1,
        context_authority_checksum=ctx,
        prior_entries=(),
    )
    blocked = _evaluate(
        parts,
        ledger_prior=None,
        ledger_head=head,
        ledger_epoch=1,
    )
    assert blocked.status == "BLOCKED"
    assert blocked.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_ENFORCED_MODE_BYPASS.value
    )


def test_head_none_does_not_require_prior_entries() -> None:
    parts = operator_authority_parts(request_id="head-integration-none-head")
    release = _evaluate(parts, ledger_prior=None, ledger_head=None, ledger_epoch=None)
    assert release.status == "RELEASED_DRY_RUN"
