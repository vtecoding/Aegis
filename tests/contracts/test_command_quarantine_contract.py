"""Contract tests for ADR-0022 command quarantine envelopes."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.command_quarantine_fixtures import (
    command_quarantine_envelope,
    command_quarantine_parts,
)

from aegis.execution.aegis_backend_admission import (
    BackendAdmissionDecision,
    recompute_backend_admission_decision_checksum,
)
from aegis.execution.aegis_capability_lease import recompute_runtime_capability_lease_checksum
from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineEnvelope,
    CommandQuarantineReason,
    CommandQuarantineStatus,
    QuarantinedCommandItem,
    command_quarantine_evidence_drift_reason,
    command_quarantine_issue_block_reason,
    normalize_quarantined_items,
    quarantine_items_from_dispatch_plan,
    quarantine_runtime_command,
    recompute_command_quarantine_checksum,
)


def test_command_quarantine_envelope_binds_full_evidence_chain() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-contract-bindings")
    (
        dispatch_plan,
        _,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id="quarantine-contract-bindings")

    assert quarantine.dispatch_plan_checksum == dispatch_plan.plan_checksum
    assert quarantine.backend_admission_checksum == backend_admission_decision.decision_checksum
    assert quarantine.capability_lease_checksum == capability_lease.lease_checksum
    assert quarantine.backend_descriptor_checksum == backend_descriptor.descriptor_checksum
    assert quarantine.authority_manifest_checksum == authority_manifest.manifest_checksum
    assert quarantine.registry_checksum == backend_registry.registry_checksum
    assert quarantine.certification_checksum == backend_certification.certification_checksum
    assert quarantine.backend_replay_proof_checksum == backend_replay_proof.proof_checksum
    assert quarantine.context_authority_checksum == context_authority.context_checksum
    assert quarantine.quarantined_items == quarantine_items_from_dispatch_plan(dispatch_plan)
    assert quarantine.quarantine_status is CommandQuarantineStatus.QUARANTINED
    assert quarantine.quarantine_checksum == recompute_command_quarantine_checksum(quarantine)


def test_command_quarantine_envelope_is_immutable() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-contract-immutable")

    with pytest.raises(FrozenInstanceError):
        quarantine.quarantine_epoch = 2


def test_command_quarantine_checksum_changes_on_epoch_change() -> None:
    first = command_quarantine_envelope(request_id="quarantine-contract-epoch", quarantine_epoch=1)
    second = command_quarantine_envelope(request_id="quarantine-contract-epoch", quarantine_epoch=2)

    assert first.quarantine_id != second.quarantine_id
    assert first.quarantine_checksum != second.quarantine_checksum


def test_command_quarantine_rejects_partial_or_runtime_item_escape_hatches() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-contract-items")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value
    ):
        CommandQuarantineEnvelope(
            quarantine_id=quarantine.quarantine_id,
            dispatch_plan_checksum=quarantine.dispatch_plan_checksum,
            backend_admission_checksum=quarantine.backend_admission_checksum,
            capability_lease_checksum=quarantine.capability_lease_checksum,
            backend_descriptor_checksum=quarantine.backend_descriptor_checksum,
            authority_manifest_checksum=quarantine.authority_manifest_checksum,
            registry_checksum=quarantine.registry_checksum,
            certification_checksum=quarantine.certification_checksum,
            backend_replay_proof_checksum=quarantine.backend_replay_proof_checksum,
            context_authority_checksum=quarantine.context_authority_checksum,
            quarantined_items=(),
            quarantine_status=quarantine.quarantine_status,
            quarantine_epoch=quarantine.quarantine_epoch,
        )
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        CommandQuarantineEnvelope(
            quarantine_id=quarantine.quarantine_id,
            dispatch_plan_checksum=quarantine.dispatch_plan_checksum,
            backend_admission_checksum=quarantine.backend_admission_checksum,
            capability_lease_checksum=quarantine.capability_lease_checksum,
            backend_descriptor_checksum=quarantine.backend_descriptor_checksum,
            authority_manifest_checksum=quarantine.authority_manifest_checksum,
            registry_checksum=quarantine.registry_checksum,
            certification_checksum=quarantine.certification_checksum,
            backend_replay_proof_checksum=quarantine.backend_replay_proof_checksum,
            context_authority_checksum=quarantine.context_authority_checksum,
            quarantined_items=(lambda: quarantine.quarantine_checksum,),
            quarantine_status=quarantine.quarantine_status,
            quarantine_epoch=quarantine.quarantine_epoch,
        )


def test_command_quarantine_requires_admitted_backend_and_valid_lease() -> None:
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
    ) = command_quarantine_parts(request_id="quarantine-contract-valid-lease")
    blocked_admission = BackendAdmissionDecision(
        status="BLOCKED",
        reason_code="BACKEND_ADMISSION_REGISTRY_CHECKSUM_DRIFT",
        backend_kind=backend_admission_decision.backend_kind,
        backend_descriptor_checksum=backend_admission_decision.backend_descriptor_checksum,
        certification_checksum=backend_admission_decision.certification_checksum,
        replay_proof_checksum=backend_admission_decision.replay_proof_checksum,
        authority_manifest_checksum=backend_admission_decision.authority_manifest_checksum,
        registry_checksum=backend_admission_decision.registry_checksum,
    )

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT.value
    ):
        quarantine_runtime_command(
            dispatch_plan=dispatch_plan,
            backend_admission_decision=blocked_admission,
            capability_lease=capability_lease,
            backend_descriptor=backend_descriptor,
            authority_manifest=authority_manifest,
            registry_checksum=backend_registry.registry_checksum,
            backend_certification=backend_certification,
            backend_replay_proof=backend_replay_proof,
            firewall_decision=firewall_decision,
            context_authority_checksum=context_authority.context_checksum,
            quarantine_epoch=1,
            current_lease_epoch=1,
        )


def test_command_quarantine_item_normalizers_reject_drift_and_malformed_values() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-contract-normalizers")
    item = quarantine.quarantined_items[0]

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION.value
    ):
        normalize_quarantined_items((item, item))
    object.__setattr__(item, "item_checksum", "1" * 64)
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_CHECKSUM_DRIFT.value
    ):
        normalize_quarantined_items((item,))
    with pytest.raises(ValueError, match="runtime_kind"):
        QuarantinedCommandItem(
            sequence=0,
            capability="locomotion.translation",
            runtime_kind="not-a-kind",
            runtime_name="cmd",
            namespace="/aegis",
            message_type="pkg/Msg",
            qos_profile_checksum="0" * 64,
            payload_checksum="0" * 64,
            payload_size_bytes=1,
            field_map_checksum="0" * 64,
        )
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        QuarantinedCommandItem(
            sequence=0,
            capability="*",
            runtime_kind="topic",
            runtime_name="cmd",
            namespace="/aegis",
            message_type="pkg/Msg",
            qos_profile_checksum="0" * 64,
            payload_checksum="0" * 64,
            payload_size_bytes=1,
            field_map_checksum="0" * 64,
        )


def test_command_quarantine_rejects_invalid_status_and_epoch() -> None:
    quarantine = command_quarantine_envelope(request_id="quarantine-contract-status")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_STATUS_INVALID.value
    ):
        CommandQuarantineEnvelope(
            quarantine_id=quarantine.quarantine_id,
            dispatch_plan_checksum=quarantine.dispatch_plan_checksum,
            backend_admission_checksum=quarantine.backend_admission_checksum,
            capability_lease_checksum=quarantine.capability_lease_checksum,
            backend_descriptor_checksum=quarantine.backend_descriptor_checksum,
            authority_manifest_checksum=quarantine.authority_manifest_checksum,
            registry_checksum=quarantine.registry_checksum,
            certification_checksum=quarantine.certification_checksum,
            backend_replay_proof_checksum=quarantine.backend_replay_proof_checksum,
            context_authority_checksum=quarantine.context_authority_checksum,
            quarantined_items=quarantine.quarantined_items,
            quarantine_status="READY",
            quarantine_epoch=quarantine.quarantine_epoch,
        )
    with pytest.raises(ValueError, match="lease_epoch"):
        CommandQuarantineEnvelope(
            quarantine_id=quarantine.quarantine_id,
            dispatch_plan_checksum=quarantine.dispatch_plan_checksum,
            backend_admission_checksum=quarantine.backend_admission_checksum,
            capability_lease_checksum=quarantine.capability_lease_checksum,
            backend_descriptor_checksum=quarantine.backend_descriptor_checksum,
            authority_manifest_checksum=quarantine.authority_manifest_checksum,
            registry_checksum=quarantine.registry_checksum,
            certification_checksum=quarantine.certification_checksum,
            backend_replay_proof_checksum=quarantine.backend_replay_proof_checksum,
            context_authority_checksum=quarantine.context_authority_checksum,
            quarantined_items=quarantine.quarantined_items,
            quarantine_status=quarantine.quarantine_status,
            quarantine_epoch=True,
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "dispatch_plan",
        "backend_admission_decision",
        "capability_lease",
        "backend_descriptor",
        "authority_manifest",
        "backend_certification",
        "backend_replay_proof",
        "firewall_decision",
    ),
)
def test_command_quarantine_issue_block_reason_rejects_runtime_object_injection(
    field_name: str,
) -> None:
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
    ) = command_quarantine_parts(request_id=f"quarantine-contract-shape-{field_name}")
    values: dict[str, object] = {
        "dispatch_plan": dispatch_plan,
        "backend_admission_decision": backend_admission_decision,
        "capability_lease": capability_lease,
        "backend_descriptor": backend_descriptor,
        "authority_manifest": authority_manifest,
        "backend_certification": backend_certification,
        "backend_replay_proof": backend_replay_proof,
        "firewall_decision": firewall_decision,
    }
    values[field_name] = object()

    reason = command_quarantine_issue_block_reason(
        dispatch_plan=values["dispatch_plan"],
        backend_admission_decision=values["backend_admission_decision"],
        capability_lease=values["capability_lease"],
        backend_descriptor=values["backend_descriptor"],
        authority_manifest=values["authority_manifest"],
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=values["backend_certification"],
        backend_replay_proof=values["backend_replay_proof"],
        firewall_decision=values["firewall_decision"],
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=1,
    )

    assert reason is CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION


def test_command_quarantine_issue_block_reason_reports_revoked_lease_epoch() -> None:
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
    ) = command_quarantine_parts(request_id="quarantine-contract-revoked")

    reason = command_quarantine_issue_block_reason(
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        firewall_decision=firewall_decision,
        context_authority_checksum=context_authority.context_checksum,
        current_lease_epoch=2,
    )

    assert reason is CommandQuarantineReason.COMMAND_QUARANTINE_LEASE_REVOKED


@pytest.mark.parametrize(
    ("field_name", "reason"),
    (
        ("dispatch_plan_checksum", CommandQuarantineReason.COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT),
        (
            "admission_decision_checksum",
            CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT,
        ),
        (
            "backend_descriptor_checksum",
            CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT,
        ),
        ("authority_manifest_checksum", CommandQuarantineReason.COMMAND_QUARANTINE_MANIFEST_DRIFT),
        ("registry_checksum", CommandQuarantineReason.COMMAND_QUARANTINE_REGISTRY_DRIFT),
        ("certification_checksum", CommandQuarantineReason.COMMAND_QUARANTINE_CERTIFICATION_DRIFT),
        ("replay_proof_checksum", CommandQuarantineReason.COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT),
        (
            "context_authority_checksum",
            CommandQuarantineReason.COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT,
        ),
    ),
)
def test_command_quarantine_evidence_reports_capability_lease_binding_drift(
    field_name: str,
    reason: CommandQuarantineReason,
) -> None:
    (
        dispatch_plan,
        _,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id=f"quarantine-contract-lease-drift-{field_name}")
    object.__setattr__(capability_lease, field_name, "1" * 64)
    object.__setattr__(
        capability_lease,
        "lease_checksum",
        recompute_runtime_capability_lease_checksum(capability_lease),
    )

    drift_reason = command_quarantine_evidence_drift_reason(
        quarantine=None,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        context_authority_checksum=context_authority.context_checksum,
    )

    assert drift_reason is reason


@pytest.mark.parametrize(
    "field_name",
    (
        "backend_descriptor_checksum",
        "authority_manifest_checksum",
        "registry_checksum",
        "certification_checksum",
        "replay_proof_checksum",
    ),
)
def test_command_quarantine_evidence_reports_backend_admission_binding_drift(
    field_name: str,
) -> None:
    (
        dispatch_plan,
        _,
        backend_descriptor,
        backend_certification,
        backend_replay_proof,
        authority_manifest,
        backend_registry,
        backend_admission_decision,
        context_authority,
        capability_lease,
    ) = command_quarantine_parts(request_id=f"quarantine-contract-admission-drift-{field_name}")
    object.__setattr__(backend_admission_decision, field_name, "1" * 64)
    object.__setattr__(
        backend_admission_decision,
        "decision_checksum",
        recompute_backend_admission_decision_checksum(backend_admission_decision),
    )

    drift_reason = command_quarantine_evidence_drift_reason(
        quarantine=None,
        dispatch_plan=dispatch_plan,
        backend_admission_decision=backend_admission_decision,
        capability_lease=capability_lease,
        backend_descriptor=backend_descriptor,
        authority_manifest=authority_manifest,
        registry_checksum=backend_registry.registry_checksum,
        backend_certification=backend_certification,
        backend_replay_proof=backend_replay_proof,
        context_authority_checksum=context_authority.context_checksum,
    )

    assert drift_reason is CommandQuarantineReason.COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT
