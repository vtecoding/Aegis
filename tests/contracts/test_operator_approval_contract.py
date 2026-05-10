"""Contract tests for ADR-0022 operator approval receipts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.command_quarantine_fixtures import command_quarantine_envelope

from aegis.execution.aegis_command_quarantine import (
    CommandQuarantineReason,
    quarantine_item_checksums,
)
from aegis.execution.aegis_operator_approval import (
    OperatorApprovalReceipt,
    OperatorApprovalStatus,
    approval_checksum_or_fallback,
    build_operator_approval_receipt,
    normalize_approval_scope,
    normalize_operator_id,
    operator_approval_id,
    recompute_operator_approval_checksum,
)


def test_operator_approval_receipt_binds_quarantine_scope_and_operator() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-contract")
    approval = build_operator_approval_receipt(
        quarantine=quarantine,
        operator_id="operator-001",
        approval_status=OperatorApprovalStatus.APPROVED,
        approved_scope=quarantine_item_checksums(quarantine),
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )

    assert approval.operator_id == "operator-001"
    assert approval.approval_status is OperatorApprovalStatus.APPROVED
    assert approval.quarantine_checksum == quarantine.quarantine_checksum
    assert approval.approved_scope == quarantine_item_checksums(quarantine)
    assert approval.approval_checksum == recompute_operator_approval_checksum(approval)


def test_operator_approval_receipt_is_immutable_and_can_reject() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-immutable")
    approval = build_operator_approval_receipt(
        quarantine=quarantine,
        operator_id="operator-001",
        approval_status="REJECTED",
        approved_scope=quarantine_item_checksums(quarantine),
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="operator rejected",
    )

    assert approval.approval_status is OperatorApprovalStatus.REJECTED
    with pytest.raises(FrozenInstanceError):
        approval.operator_id = "operator-002"


def test_operator_approval_rejects_wildcard_empty_and_overbroad_scope() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-scope")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE.value
    ):
        normalize_approval_scope(("*",))
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY.value
    ):
        normalize_approval_scope(())
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE.value
    ):
        build_operator_approval_receipt(
            quarantine=quarantine,
            operator_id="operator-001",
            approval_status="APPROVED",
            approved_scope=quarantine_item_checksums(quarantine).union({"f" * 64}),
            approval_epoch=quarantine.quarantine_epoch,
            approval_reason="overbroad",
        )


def test_operator_approval_rejects_malformed_operator_id() -> None:
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED.value
    ):
        normalize_operator_id("")
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED.value
    ):
        normalize_operator_id("*")


def test_operator_approval_rejects_bad_quarantine_and_malformed_fields() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-malformed")

    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        build_operator_approval_receipt(
            quarantine=object(),
            operator_id="operator-001",
            approval_status="APPROVED",
            approved_scope=quarantine_item_checksums(quarantine),
            approval_epoch=quarantine.quarantine_epoch,
            approval_reason="bad quarantine",
        )
    object.__setattr__(quarantine, "quarantine_checksum", "1" * 64)
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_CHECKSUM_DRIFT.value
    ):
        build_operator_approval_receipt(
            quarantine=quarantine,
            operator_id="operator-001",
            approval_status="APPROVED",
            approved_scope=quarantine_item_checksums(quarantine),
            approval_epoch=quarantine.quarantine_epoch,
            approval_reason="drifted quarantine",
        )
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        normalize_approval_scope({"mutable": "scope"})
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION.value
    ):
        normalize_approval_scope((lambda: "scope",))
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value
    ):
        OperatorApprovalReceipt(
            approval_id="0" * 64,
            operator_id="operator-001",
            approval_status="MAYBE",
            quarantine_checksum="0" * 64,
            approved_scope=("0" * 64,),
            approval_epoch=1,
            approval_reason="bad status",
        )
    with pytest.raises(
        ValueError, match=CommandQuarantineReason.COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID.value
    ):
        OperatorApprovalReceipt(
            approval_id="0" * 64,
            operator_id="operator-001",
            approval_status=object(),
            quarantine_checksum="0" * 64,
            approved_scope=("0" * 64,),
            approval_epoch=1,
            approval_reason="bad status",
        )
    with pytest.raises(ValueError, match="approval_epoch"):
        OperatorApprovalReceipt(
            approval_id="0" * 64,
            operator_id="operator-001",
            approval_status="APPROVED",
            quarantine_checksum="0" * 64,
            approved_scope=("0" * 64,),
            approval_epoch=True,
            approval_reason="bad epoch",
        )


def test_operator_approval_fallbacks_and_checksum_validation() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-fallback")
    approval = build_operator_approval_receipt(
        quarantine=quarantine,
        operator_id="operator-001",
        approval_status="APPROVED",
        approved_scope=quarantine_item_checksums(quarantine),
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )

    assert approval_checksum_or_fallback(approval) == approval.approval_checksum
    assert approval_checksum_or_fallback(object()) == "0" * 64
    with pytest.raises(ValueError, match="approval_checksum"):
        OperatorApprovalReceipt(
            approval_id=approval.approval_id,
            operator_id=approval.operator_id,
            approval_status=approval.approval_status,
            quarantine_checksum=approval.quarantine_checksum,
            approved_scope=approval.approved_scope,
            approval_epoch=approval.approval_epoch,
            approval_reason=approval.approval_reason,
            approval_checksum="0" * 64,
        )


def test_operator_approval_checksum_changes_on_scope_change() -> None:
    quarantine = command_quarantine_envelope(request_id="operator-approval-checksum")
    scope = quarantine_item_checksums(quarantine)
    approval_id = operator_approval_id(
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=scope,
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )
    overbroad_id = operator_approval_id(
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=scope.union({"f" * 64}),
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )

    approval = OperatorApprovalReceipt(
        approval_id=approval_id,
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=scope,
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )
    overbroad = OperatorApprovalReceipt(
        approval_id=overbroad_id,
        operator_id="operator-001",
        approval_status="APPROVED",
        quarantine_checksum=quarantine.quarantine_checksum,
        approved_scope=scope.union({"f" * 64}),
        approval_epoch=quarantine.quarantine_epoch,
        approval_reason="approved dry run",
    )

    assert approval.approval_checksum != overbroad.approval_checksum
