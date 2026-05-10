"""Adversarial tests for world snapshot freshness bypass attempts."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    FRESH_OBSERVED_AT_MS,
    bind_policy_result_to_freshness,
    fresh_policy_context,
    fresh_world_snapshot,
    fresh_world_snapshot_result,
)
from tests.policy_trust_fixtures import bind_policy_result_to_trust, trusted_world_snapshot_result

from aegis.aegis_errors import PolicyAdmissionIntegrityError
from aegis.audit import build_audited_plan
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
    WorldSnapshotStub,
)
from aegis.contracts.aegis_policy_admission import (
    PolicyAdmissionInput,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    is_policy_backed_approval,
)
from aegis.contracts.aegis_world_snapshot_freshness import (
    DEFAULT_FRESHNESS_POLICY,
    WorldSnapshotFreshnessError,
    assert_world_snapshot_freshness_integrity,
)
from aegis.contracts.aegis_world_snapshot_trust import WorldSnapshotTrustResult
from aegis.gate import gate_audited_plan
from aegis.governance.aegis_context_authority import ContextAuthority
from aegis.pipeline import run_pipeline
from aegis.planning import plan_validated_intent
from aegis.policy import build_safety_case
from aegis.validation import validate_intent


def _context(request_id: str = "freshness-adversarial") -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "adversary", 5, context)


def _audited_plan(request_id: str = "freshness-adversarial"):
    context = _context(request_id)
    validation_result = validate_intent(_intent(context))
    plan = plan_validated_intent(validation_result)
    return build_audited_plan(plan)


def _policy() -> Policy:
    return Policy(
        "freshness-adversarial-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                "locomotion.translation",
                [Constraint("max_velocity", {"max_mps": 1.0})],
            )
        ],
    )


def _capability() -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": 0.2})


def _context_authority() -> ContextAuthority:
    return ContextAuthority(
        context_id="freshness-adversarial-context",
        request_id="freshness-adversarial-request",
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        caller_authority="pytest",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )


def _context_authority_kwargs() -> dict[str, object]:
    authority = _context_authority()
    return {
        "context_authority_checksum": authority.context_checksum,
        "context_id": authority.context_id,
        "caller_authority": authority.caller_authority,
        "deployment_domain": authority.deployment_domain,
        "context_schema_version": authority.context_schema_version,
        "context_evaluation_time_ms": authority.evaluation_time_ms,
    }


def _allow_result(snapshot: WorldSnapshotStub | None = None) -> PolicyEvaluationResult:
    policy = _policy()
    authority = _context_authority()
    freshness_result = fresh_world_snapshot_result(snapshot or fresh_world_snapshot())
    trust_snapshot = snapshot or fresh_world_snapshot()
    trust_result = trusted_world_snapshot_result(trust_snapshot)
    return bind_policy_result_to_trust(
        bind_policy_result_to_freshness(
            PolicyEvaluationResult(
                PolicyDecision.ALLOW,
                "freshness-adversarial-policy",
                ["rule-1"],
                ["rule-1:0:max_velocity"],
                [],
                ["POLICY_ALLOWED"],
                policy_version=policy.policy_version,
                policy_schema_version=policy.policy_schema_version,
                policy_checksum=policy.policy_checksum,
                policy_authority=policy.policy_authority,
                context_authority_checksum=authority.context_checksum,
            ),
            freshness_result,
        ),
        trust_result,
    )


def _safety_case(audited_plan, policy_result: PolicyEvaluationResult, snapshot: WorldSnapshotStub):
    freshness_result = fresh_world_snapshot_result(snapshot)
    trust_result = trusted_world_snapshot_result(snapshot)
    return build_safety_case(
        policy_result=policy_result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
        trust_result=trust_result,
    )


def _trusted_record_kwargs(trust_result: WorldSnapshotTrustResult) -> dict[str, object]:
    return {
        "world_snapshot_admissibility_status": trust_result.world_snapshot_admissibility_status,
        "world_snapshot_admissibility_reason_code": (
            trust_result.world_snapshot_admissibility_reason_code
        ),
        "world_snapshot_admissibility_result_checksum": (
            trust_result.world_snapshot_admissibility_result_checksum
        ),
        "world_snapshot_trust_status": trust_result.status.value,
        "world_snapshot_trust_reason_code": trust_result.reason_code,
        "world_snapshot_trust_result_checksum": trust_result.checksum,
        "evidence_envelope_checksum": trust_result.evidence_envelope_checksum,
        "attestation_checksum": trust_result.attestation_checksum,
        "trust_policy_checksum": trust_result.trust_policy_checksum,
        "verifier_certification_status": "CERTIFIED",
        "verifier_certification_reason_code": "ATTESTATION_VERIFIER_CERTIFIED",
        "verifier_certification_checksum": trust_result.verifier_certification_checksum,
        "verifier_id": trust_result.verifier_id,
        "verifier_metadata_checksum": trust_result.verifier_metadata_checksum,
        "trust_policy_config_status": "VALID",
        "trust_policy_config_reason_code": "TRUST_POLICY_CONFIG_VALID",
        "trust_policy_config_validation_checksum": (
            trust_result.trust_policy_config_validation_checksum
        ),
        "source_id": trust_result.source_id,
        "source_type": trust_result.source_type.value
        if trust_result.source_type is not None
        else None,
        "trust_domain": trust_result.trust_domain.value
        if trust_result.trust_domain is not None
        else None,
    }


def test_stale_snapshot_with_monkeypatched_allow_evaluator_still_blocks() -> None:
    context = _context("freshness-adversarial-stale")
    stale_snapshot = fresh_world_snapshot(observed_at_ms=FRESH_OBSERVED_AT_MS - 2_000)
    allow_result = _allow_result()

    with patch(
        "aegis.pipeline.aegis_orchestrator.evaluate_policy", return_value=allow_result
    ) as evaluator:
        result = run_pipeline(
            _intent(context),
            context,
            policy_admission=PolicyAdmissionInput(
                PolicyAdmissionMode.ENFORCE,
                policy=_policy(),
                capability=_capability(),
                world_snapshot=stale_snapshot,
                context=fresh_policy_context(),
            ),
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        )

    evaluator.assert_not_called()
    assert result.outcome is PipelineOutcome.BLOCKED
    assert result.policy_admission.freshness_status == "STALE"


def test_reused_freshness_result_from_another_snapshot_is_rejected() -> None:
    snapshot_a = fresh_world_snapshot("snapshot-a")
    snapshot_b = fresh_world_snapshot("snapshot-b")
    freshness_result = fresh_world_snapshot_result(snapshot_a)

    with pytest.raises(WorldSnapshotFreshnessError):
        assert_world_snapshot_freshness_integrity(
            snapshot=snapshot_b,
            freshness_result=freshness_result,
            evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
            freshness_policy=DEFAULT_FRESHNESS_POLICY,
        )


def test_safety_case_freshness_mismatch_is_rejected() -> None:
    audited_plan = _audited_plan("freshness-adversarial-safety-case")
    snapshot_a = fresh_world_snapshot("snapshot-a")
    snapshot_b = fresh_world_snapshot("snapshot-b")
    policy_result = _allow_result(snapshot_a)
    safety_case = _safety_case(audited_plan, policy_result, snapshot_b)
    freshness_a = fresh_world_snapshot_result(snapshot_a)

    with pytest.raises(ValueError, match="safety_case"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=policy_result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id=audited_plan.audit_id,
            plan_id=audited_plan.plan.plan_id,
            plan_checksum=audited_plan.checksum,
            world_snapshot_id=snapshot_a.snapshot_id,
            world_snapshot_checksum=snapshot_a.checksum,
            capability_name=safety_case.capability_name,
            capability_version=safety_case.capability_version,
            world_snapshot_observed_at_ms=freshness_a.observed_at_ms,
            freshness_result_checksum=freshness_a.checksum,
            freshness_status=freshness_a.status.value,
            **_context_authority_kwargs(),
            **_trusted_record_kwargs(trusted_world_snapshot_result(snapshot_a)),
        )


def test_policy_evaluation_freshness_mismatch_is_rejected() -> None:
    audited_plan = _audited_plan("freshness-adversarial-policy-result")
    snapshot_a = fresh_world_snapshot("snapshot-a")
    snapshot_b = fresh_world_snapshot("snapshot-b")
    policy_result = _allow_result(snapshot_a)
    safety_case = _safety_case(audited_plan, policy_result, snapshot_b)
    freshness_b = fresh_world_snapshot_result(snapshot_b)

    with pytest.raises(ValueError, match="policy_result"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=policy_result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id=audited_plan.audit_id,
            plan_id=audited_plan.plan.plan_id,
            plan_checksum=audited_plan.checksum,
            world_snapshot_id=snapshot_b.snapshot_id,
            world_snapshot_checksum=snapshot_b.checksum,
            capability_name=safety_case.capability_name,
            capability_version=safety_case.capability_version,
            world_snapshot_observed_at_ms=freshness_b.observed_at_ms,
            freshness_result_checksum=freshness_b.checksum,
            freshness_status=freshness_b.status.value,
            **_context_authority_kwargs(),
            **_trusted_record_kwargs(trusted_world_snapshot_result(snapshot_b)),
        )


def test_policy_admission_freshness_mismatch_is_rejected_by_integrity() -> None:
    audited_plan = _audited_plan("freshness-adversarial-admission")
    snapshot = fresh_world_snapshot()
    policy_result = _allow_result(snapshot)
    safety_case = _safety_case(audited_plan, policy_result, snapshot)
    freshness_result = fresh_world_snapshot_result(snapshot)
    record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=policy_result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=snapshot.snapshot_id,
        world_snapshot_checksum=snapshot.checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
        **_context_authority_kwargs(),
        **_trusted_record_kwargs(trusted_world_snapshot_result(snapshot)),
    )
    object.__setattr__(record, "freshness_result_checksum", "0" * 64)

    with pytest.raises(PolicyAdmissionIntegrityError):
        assert_policy_admission_integrity(audited_plan, record)


@pytest.mark.parametrize("status", ["FRESH ", "fresh", "ＦＲＥＳＨ", "FRESH\u200b"])
def test_confusable_freshness_status_strings_are_rejected(status: str) -> None:
    with pytest.raises(ValueError):
        PolicyEvaluationResult(
            PolicyDecision.ALLOW,
            "policy-1",
            ["rule-1"],
            ["rule-1:0:max_velocity"],
            [],
            ["POLICY_ALLOWED"],
            freshness_status=status,
        )


def test_direct_gate_approval_cannot_produce_full_pipeline_allowed() -> None:
    audited_plan = _audited_plan("freshness-adversarial-direct-gate")
    gate_decision = gate_audited_plan(audited_plan)

    assert gate_decision.status == "allowed"
    assert not is_policy_backed_approval(audited_plan, None, gate_decision)
