"""Runtime object injection tests for ADR-0022 command quarantine."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from tests.command_quarantine_fixtures import command_quarantine_parts
from tests.operator_authority_fixtures import operator_authority_parts

from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineReason,
    quarantine_runtime_command,
)
from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release


def test_runtime_object_injection_blocks_quarantine_creation() -> None:
    (
        dispatch_plan,
        firewall_decision,
        _,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id="quarantine-object-create")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        quarantine_runtime_command(
            dispatch_plan=dispatch_plan,
            backend_admission_decision=backend_admission_decision,
            capability_lease=capability_lease,
            backend_descriptor={"mutable": "descriptor"},
            authority_manifest=authority_manifest,
            registry_checksum=backend_registry.registry_checksum,
            backend_certification=backend_certification,
            backend_replay_proof=backend_replay_proof,
            firewall_decision=firewall_decision,
            context_authority_checksum=context_authority.context_checksum,
            quarantine_epoch=1,
            current_lease_epoch=1,
        )


def test_callable_scope_injection_blocks_release() -> None:
    parts = operator_authority_parts(request_id="quarantine-object-release")
    object.__setattr__(parts.approval, "approved_scope", frozenset({lambda: "scope"}))

    release = evaluate_quarantine_release(
        quarantine=parts.quarantine,
        approval=parts.approval,
        approval_replay_validation=parts.replay_validation,
        capability_lease=parts.capability_lease,
        dispatch_plan=parts.dispatch_plan,
        backend_admission_decision=parts.backend_admission_decision,
        backend_descriptor=parts.backend_descriptor,
        authority_manifest=parts.backend_authority_manifest,
        registry_checksum=parts.backend_registry.registry_checksum,
        backend_certification=parts.backend_certification,
        backend_replay_proof=parts.backend_replay_proof,
        firewall_decision=parts.firewall_decision,
        context_authority_checksum=parts.context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert release.status == "BLOCKED"
    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    )


def test_runtime_object_injection_blocks_release_boundary() -> None:
    (
        dispatch_plan,
        firewall_decision,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id="quarantine-object-boundary")
    injected_quarantine = SimpleNamespace(quarantine_checksum="0" * 64, backend_client=object())

    release = evaluate_quarantine_release(
        quarantine=injected_quarantine,
        approval=None,
        capability_lease=capability_lease,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert release.status == "BLOCKED"
    assert release.reason_code == (
        CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    )
