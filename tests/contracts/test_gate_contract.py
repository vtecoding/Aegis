"""Contract conformance tests for gate-v1 decisions."""

from __future__ import annotations

import dataclasses

import pytest

from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus


class TestGateEnums:
    def test_gate_decision_status_values_are_stable(self) -> None:
        assert GateDecisionStatus.ALLOWED == "allowed"
        assert GateDecisionStatus.BLOCKED == "blocked"

    def test_gate_block_reason_values_are_stable(self) -> None:
        assert GateBlockReason.CHECKSUM_MISMATCH == "checksum_mismatch"
        assert GateBlockReason.AUDIT_ID_MISMATCH == "audit_id_mismatch"
        assert GateBlockReason.MALFORMED_AUDITED_PLAN == "malformed_audited_plan"


class TestGateDecisionConstruction:
    def test_rejects_invalid_status_value(self) -> None:
        with pytest.raises(ValueError, match="GateDecisionStatus"):
            GateDecision(
                status="allowed",
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=(),
                checksum_verified=True,
                audit_id_verified=True,
            )

    @pytest.mark.parametrize(
        ("checksum_verified", "audit_id_verified"),
        [("true", True), (True, "true")],
    )
    def test_rejects_non_bool_verification_flags(
        self, checksum_verified: object, audit_id_verified: object
    ) -> None:
        with pytest.raises(ValueError, match="verified must be a bool"):
            GateDecision(
                status=GateDecisionStatus.BLOCKED,
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=(GateBlockReason.MALFORMED_AUDITED_PLAN,),
                checksum_verified=checksum_verified,
                audit_id_verified=audit_id_verified,
            )

    def test_allowed_decision_accepts_verified_receipt(self) -> None:
        decision = GateDecision(
            status=GateDecisionStatus.ALLOWED,
            audit_id="audit-1",
            plan_id="plan-1",
            reasons=(),
            checksum_verified=True,
            audit_id_verified=True,
        )

        assert decision.status is GateDecisionStatus.ALLOWED
        assert decision.reasons == ()
        assert decision.checksum_verified is True
        assert decision.audit_id_verified is True
        assert decision.audit_id == "audit-1"
        assert decision.plan_id == "plan-1"

    def test_blocked_decision_accepts_non_empty_reasons(self) -> None:
        decision = GateDecision(
            status=GateDecisionStatus.BLOCKED,
            audit_id="audit-1",
            plan_id="plan-1",
            reasons=[GateBlockReason.CHECKSUM_MISMATCH],
            checksum_verified=False,
            audit_id_verified=True,
        )

        assert decision.status is GateDecisionStatus.BLOCKED
        assert decision.reasons == (GateBlockReason.CHECKSUM_MISMATCH,)

    def test_allowed_decision_rejects_reasons(self) -> None:
        with pytest.raises(ValueError, match="block reasons"):
            GateDecision(
                status=GateDecisionStatus.ALLOWED,
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=(GateBlockReason.CHECKSUM_MISMATCH,),
                checksum_verified=True,
                audit_id_verified=True,
            )

    @pytest.mark.parametrize(
        ("audit_id", "plan_id"),
        [(None, "plan-1"), ("audit-1", None)],
    )
    def test_allowed_decision_requires_identifiers(
        self, audit_id: str | None, plan_id: str | None
    ) -> None:
        with pytest.raises(ValueError, match="allowed decisions"):
            GateDecision(
                status=GateDecisionStatus.ALLOWED,
                audit_id=audit_id,
                plan_id=plan_id,
                reasons=(),
                checksum_verified=True,
                audit_id_verified=True,
            )

    @pytest.mark.parametrize(
        ("checksum_verified", "audit_id_verified"),
        [(False, True), (True, False), (False, False)],
    )
    def test_allowed_decision_requires_all_verification_flags(
        self, checksum_verified: bool, audit_id_verified: bool
    ) -> None:
        with pytest.raises(ValueError, match="allowed decisions"):
            GateDecision(
                status=GateDecisionStatus.ALLOWED,
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=(),
                checksum_verified=checksum_verified,
                audit_id_verified=audit_id_verified,
            )

    def test_blocked_decision_requires_non_empty_reasons(self) -> None:
        with pytest.raises(ValueError, match="blocked decisions"):
            GateDecision(
                status=GateDecisionStatus.BLOCKED,
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=(),
                checksum_verified=False,
                audit_id_verified=False,
            )

    @pytest.mark.parametrize(
        ("audit_id", "plan_id"),
        [(" ", "plan-1"), ("audit-1", "\t")],
    )
    def test_rejects_blank_identifiers_when_provided(
        self, audit_id: str | None, plan_id: str | None
    ) -> None:
        with pytest.raises(ValueError, match="must be non-empty"):
            GateDecision(
                status=GateDecisionStatus.BLOCKED,
                audit_id=audit_id,
                plan_id=plan_id,
                reasons=(GateBlockReason.MALFORMED_AUDITED_PLAN,),
                checksum_verified=False,
                audit_id_verified=False,
            )

    def test_reason_order_is_preserved(self) -> None:
        decision = GateDecision(
            status=GateDecisionStatus.BLOCKED,
            audit_id="audit-1",
            plan_id="plan-1",
            reasons=(GateBlockReason.CHECKSUM_MISMATCH, GateBlockReason.AUDIT_ID_MISMATCH),
            checksum_verified=False,
            audit_id_verified=False,
        )

        assert decision.reasons == (
            GateBlockReason.CHECKSUM_MISMATCH,
            GateBlockReason.AUDIT_ID_MISMATCH,
        )

    def test_rejects_invalid_reason_values(self) -> None:
        with pytest.raises(ValueError, match="GateBlockReason"):
            GateDecision(
                status=GateDecisionStatus.BLOCKED,
                audit_id="audit-1",
                plan_id="plan-1",
                reasons=("checksum_mismatch",),  # type: ignore[arg-type]
                checksum_verified=False,
                audit_id_verified=True,
            )

    def test_gate_decision_is_immutable(self) -> None:
        decision = GateDecision(
            status=GateDecisionStatus.BLOCKED,
            audit_id=None,
            plan_id=None,
            reasons=(GateBlockReason.MALFORMED_AUDITED_PLAN,),
            checksum_verified=False,
            audit_id_verified=False,
        )

        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            decision.status = GateDecisionStatus.ALLOWED  # type: ignore[misc]

    def test_gate_decision_is_a_slots_dataclass(self) -> None:
        assert dataclasses.is_dataclass(GateDecision)
        assert hasattr(GateDecision, "__slots__")
