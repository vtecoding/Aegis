"""Adversarial tests for ADR-0025 approval ledger head tamper resistance."""

from __future__ import annotations

import pytest
from tests.command_quarantine_fixtures import quarantine_release_decision

from aegis.execution.aegis_approval_ledger import (
    append_approval_ledger_entry,
    approval_ledger_genesis_head_checksum,
)
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerHead,
    ApprovalLedgerHeadReason,
    build_approval_ledger_head,
    validate_approval_ledger_head,
)

_CTX = "a" * 64
_OTHER_CTX = "f" * 64


def _head(
    *,
    epoch: int = 1,
    ctx: str = _CTX,
    prior_entries: tuple = (),
) -> ApprovalLedgerHead:
    return build_approval_ledger_head(
        session_epoch=epoch,
        context_authority_checksum=ctx,
        prior_entries=prior_entries,
    )


def _entry(request_id: str, prior: tuple = ()):  # type: ignore[return]
    release = quarantine_release_decision(request_id=request_id)
    return append_approval_ledger_entry(
        prior_entries=prior,
        release_status=release.status,
        release_decision_checksum=release.decision_checksum,
    )


def test_stale_head_accepted_for_old_chain_but_blocked_for_current() -> None:
    e0 = _entry("head-tamper-stale-head-e0")
    old_head = _head(prior_entries=(e0,))
    result = validate_approval_ledger_head(
        head=old_head,
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code in {
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_TIP_MISMATCH,
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_SEQUENCE_MISMATCH,
    }


def test_forked_head_blocked() -> None:
    e0 = _entry("head-tamper-fork-e0")
    e1 = _entry("head-tamper-fork-e1", prior=(e0,))
    e0_forked = _entry("head-tamper-fork-e0-forked")
    head_a = _head(prior_entries=(e0, e1))
    result = validate_approval_ledger_head(
        head=head_a,
        prior_entries=(e0_forked,),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"


def test_valid_chain_from_different_epoch_is_blocked() -> None:
    e0 = _entry("head-tamper-epoch-drift")
    head = _head(epoch=2, prior_entries=(e0,))
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(e0,),
        context_authority_checksum=_CTX,
        session_epoch=3,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_STALE_EPOCH


def test_genesis_replay_after_prior_approvals_blocked() -> None:
    e0 = _entry("head-tamper-genesis-replay-e0")
    e1 = _entry("head-tamper-genesis-replay-e1", prior=(e0,))
    head_with_two = _head(prior_entries=(e0, e1))
    empty_head = _head(prior_entries=())
    result = validate_approval_ledger_head(
        head=empty_head,
        prior_entries=(e0, e1),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    _ = head_with_two


def test_sequence_gap_blocked() -> None:
    e0 = _entry("head-tamper-sequence-gap-e0")
    e1 = _entry("head-tamper-sequence-gap-e1", prior=(e0,))
    result = validate_approval_ledger_head(
        head=_head(prior_entries=(e0, e1)),
        prior_entries=(e1,),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"


def test_sequence_rollback_blocked() -> None:
    e0 = _entry("head-tamper-rollback-e0")
    e1 = _entry("head-tamper-rollback-e1", prior=(e0,))
    head_with_one = _head(prior_entries=(e0,))
    result = validate_approval_ledger_head(
        head=_head(prior_entries=(e0, e1)),
        prior_entries=(e0,),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    _ = head_with_one


def test_prefix_truncation_blocked() -> None:
    e0 = _entry("head-tamper-truncation-e0")
    e1 = _entry("head-tamper-truncation-e1", prior=(e0,))
    head_with_two = _head(prior_entries=(e0, e1))
    result = validate_approval_ledger_head(
        head=head_with_two,
        prior_entries=(e0,),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"


def test_tail_duplication_blocked() -> None:
    e0 = _entry("head-tamper-dup-tail")
    with pytest.raises(ValueError):
        build_approval_ledger_head(
            session_epoch=1,
            context_authority_checksum=_CTX,
            prior_entries=(e0, e0),
        )


def test_cross_context_chain_grafting_blocked() -> None:
    e0 = _entry("head-tamper-cross-ctx-e0")
    head_ctx_a = _head(ctx=_CTX, prior_entries=(e0,))
    result = validate_approval_ledger_head(
        head=head_ctx_a,
        prior_entries=(e0,),
        context_authority_checksum=_OTHER_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == (
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_CONTEXT_AUTHORITY_DRIFT
    )


def test_head_checksum_drift_blocked() -> None:
    head = _head(prior_entries=())
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "VALID"

    result2 = validate_approval_ledger_head(
        head=head,
        prior_entries=(),
        context_authority_checksum=_OTHER_CTX,
        session_epoch=1,
    )
    assert result2.status == "BLOCKED"


def test_direct_construction_blocked() -> None:
    genesis = approval_ledger_genesis_head_checksum()
    from aegis.aegis_constants import APPROVAL_LEDGER_CONTRACT_VERSION

    reason = ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_DIRECT_CONSTRUCTION
    with pytest.raises(ValueError, match=reason):
        ApprovalLedgerHead(
            ledger_contract_version=APPROVAL_LEDGER_CONTRACT_VERSION,
            session_epoch=1,
            latest_sequence_index=-1,
            latest_entry_checksum=genesis,
            genesis_checksum=genesis,
            context_authority_checksum=_CTX,
        )


def test_non_head_object_injection_blocked() -> None:
    result = validate_approval_ledger_head(
        head=object(),
        prior_entries=(),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == (
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION
    )


def test_non_tuple_prior_injection_blocked() -> None:
    head = _head(prior_entries=())
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=[],
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == (
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION
    )


def test_non_entry_in_tuple_injection_blocked() -> None:
    head = _head(prior_entries=())
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(object(),),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "BLOCKED"
    assert result.reason_code == (
        ApprovalLedgerHeadReason.APPROVAL_LEDGER_HEAD_RUNTIME_OBJECT_INJECTION
    )


def test_head_shape_invalid_when_genesis_mismatch() -> None:
    e0 = _entry("head-tamper-genesis-mismatch")
    head = _head(prior_entries=(e0,))
    result = validate_approval_ledger_head(
        head=head,
        prior_entries=(e0,),
        context_authority_checksum=_CTX,
        session_epoch=1,
    )
    assert result.status == "VALID"


def test_build_head_rejects_callable_context_authority_checksum() -> None:
    with pytest.raises(ValueError):
        build_approval_ledger_head(
            session_epoch=1,
            context_authority_checksum=lambda: _CTX,
            prior_entries=(),
        )
