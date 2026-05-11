"""Integration tests for ADR-0024 approval ledger with quarantine release."""

from __future__ import annotations

from tests.operator_authority_fixtures import OperatorAuthorityParts, operator_authority_parts

from aegis.execution.aegis_approval_ledger import append_approval_ledger_entry
from aegis.execution.aegis_command_quarantine import CommandQuarantineReason
from aegis.execution.aegis_quarantine_release import (
    QuarantineReleaseDecision,
    evaluate_quarantine_release,
)


def _evaluate(
    parts: OperatorAuthorityParts, *, ledger_prior: object | None = None
) -> QuarantineReleaseDecision:
    p = parts
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
        context_authority_checksum=p.context_authority.context_checksum,
        current_lease_epoch=1,
        approval_ledger_prior_entries=ledger_prior,
    )


def test_release_with_empty_ledger_prefix_succeeds() -> None:
    parts = operator_authority_parts(request_id="ledger-integration-empty-prefix")
    release = _evaluate(parts, ledger_prior=())
    assert release.status == "RELEASED_DRY_RUN"


def test_release_with_valid_prior_ledger_succeeds() -> None:
    first_parts = operator_authority_parts(request_id="ledger-integration-first")
    first = _evaluate(first_parts, ledger_prior=())
    assert first.status == "RELEASED_DRY_RUN"
    first_entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=first.status,
        release_decision_checksum=first.decision_checksum,
    )
    second_parts = operator_authority_parts(request_id="ledger-integration-second")
    second = _evaluate(second_parts, ledger_prior=(first_entry,))
    assert second.status == "RELEASED_DRY_RUN"


def test_release_with_invalid_ledger_prefix_blocks() -> None:
    first_parts = operator_authority_parts(request_id="ledger-integration-invalid-first")
    first = _evaluate(first_parts, ledger_prior=())
    first_entry = append_approval_ledger_entry(
        prior_entries=(),
        release_status=first.status,
        release_decision_checksum=first.decision_checksum,
    )
    second_parts = operator_authority_parts(request_id="ledger-integration-invalid-second")
    bad_chain = (first_entry, first_entry)
    blocked = _evaluate(second_parts, ledger_prior=bad_chain)
    assert blocked.status == "BLOCKED"
    assert blocked.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_LEDGER_CHAIN_INVALID.value
    )
