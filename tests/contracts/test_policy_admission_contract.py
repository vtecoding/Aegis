"""Contract tests for pipeline policy admission input and record objects."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from tests.policy_freshness_fixtures import (
    bind_policy_result_to_freshness,
    fresh_world_snapshot,
    fresh_world_snapshot_result,
)

from aegis.audit import build_audited_plan
from aegis.contracts.context import ExecutionContext
from aegis.contracts.gate import GateBlockReason, GateDecision, GateDecisionStatus
from aegis.contracts.intent import RawIntent
from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
    WorldSnapshotStub,
    policy_evaluation_result_checksum,
)
from aegis.contracts.policy_admission import (
    PolicyAdmissionDecision,
    PolicyAdmissionInput,
    PolicyAdmissionIntegrityStatus,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    assert_policy_admission_integrity,
    disabled_policy_admission_record,
    is_policy_backed_approval,
)
from aegis.errors import PolicyAdmissionIntegrityError
from aegis.gate import gate_audited_plan
from aegis.planning import plan_validated_intent
from aegis.policy import build_safety_case
from aegis.validation import validate_intent


def _policy() -> Policy:
    return Policy(
        "policy-1",
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", [Constraint("max_velocity")])],
    )


def _capability() -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": 0.2})


def _allow_result() -> PolicyEvaluationResult:
    return bind_policy_result_to_freshness(
        PolicyEvaluationResult(
            PolicyDecision.ALLOW,
            "policy-1",
            ["rule-1"],
            ["rule-1:0:max_velocity"],
            [],
            ["POLICY_ALLOWED"],
        )
    )


def _block_result() -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        PolicyDecision.BLOCK,
        "policy-1",
        ["rule-1"],
        [],
        ["rule-1:0:max_velocity"],
        ["VELOCITY_LIMIT_EXCEEDED"],
    )


def _safety_case(result: PolicyEvaluationResult) -> object:
    snapshot = fresh_world_snapshot()
    freshness_result = fresh_world_snapshot_result(snapshot)
    return build_safety_case(
        policy_result=result,
        audited_plan_id="audit-1",
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id="plan-1",
        plan_checksum="checksum-1",
        capability=_capability(),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )


def _allowed_record(result: PolicyEvaluationResult) -> PolicyAdmissionRecord:
    safety_case = _safety_case(result)
    freshness_result = fresh_world_snapshot_result()
    return PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id="audit-1",
        plan_id="plan-1",
        plan_checksum="checksum-1",
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name="locomotion.translation",
        capability_version="v1",
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )


def _audited_plan():
    context = ExecutionContext("policy-admission-contract", datetime(2026, 1, 1, tzinfo=UTC), "v1")
    intent = RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)
    validation_result = validate_intent(intent)
    plan = plan_validated_intent(validation_result)
    return build_audited_plan(plan)


def _bound_allowed_record(
    *, world_snapshot: WorldSnapshotStub | None = None
) -> PolicyAdmissionRecord:
    audited_plan = _audited_plan()
    snapshot = world_snapshot or fresh_world_snapshot()
    freshness_result = fresh_world_snapshot_result(snapshot)
    result = bind_policy_result_to_freshness(_allow_result(), freshness_result)
    safety_case = build_safety_case(
        policy_result=result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )
    return PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )


def test_policy_admission_mode_values_are_stable() -> None:
    assert PolicyAdmissionMode.DISABLED == "DISABLED"
    assert PolicyAdmissionMode.ENFORCE == "ENFORCE"
    assert isinstance(PolicyAdmissionMode.ENFORCE, str)


@pytest.mark.parametrize("mode", ["ENFORCE ", "DISABLED\u200b", "UNKNOWN"])
def test_policy_admission_mode_strings_are_strict(mode: str) -> None:
    with pytest.raises(ValueError):
        PolicyAdmissionInput(mode)


def test_disabled_input_rejects_policy_inputs() -> None:
    with pytest.raises(ValueError, match="DISABLED"):
        PolicyAdmissionInput(PolicyAdmissionMode.DISABLED, policy=_policy())


def test_disabled_input_rejects_context_and_evidence() -> None:
    with pytest.raises(ValueError, match="DISABLED"):
        PolicyAdmissionInput(PolicyAdmissionMode.DISABLED, context={"force_allow": True})
    with pytest.raises(ValueError, match="DISABLED"):
        PolicyAdmissionInput(PolicyAdmissionMode.DISABLED, evidence={"override": "ALLOW"})


def test_enforce_input_allows_missing_policy_for_fail_closed_pipeline_result() -> None:
    admission = PolicyAdmissionInput(PolicyAdmissionMode.ENFORCE, capability=_capability())

    assert admission.mode is PolicyAdmissionMode.ENFORCE
    assert admission.policy is None
    assert admission.capability == _capability()


def test_enforce_input_deep_freezes_context_and_evidence() -> None:
    context = {"authorisations": ["operator"], "nested": {"level": 1}}
    evidence = {"claim": ["inert"]}

    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(),
        capability=_capability(),
        context=context,
        evidence=evidence,
    )
    context["authorisations"].append("admin")
    evidence["claim"].append("override")

    assert admission.context["authorisations"] == ("operator",)
    assert admission.evidence["claim"] == ("inert",)
    assert isinstance(admission.context["nested"], Mapping)
    with pytest.raises(TypeError):
        admission.context["new"] = "value"  # type: ignore[index]


@pytest.mark.parametrize("bad_value", [float("nan"), object()])
def test_enforce_input_rejects_unsupported_context_values(bad_value: object) -> None:
    with pytest.raises(ValueError):
        PolicyAdmissionInput(PolicyAdmissionMode.ENFORCE, context={"bad": bad_value})


def test_enforce_input_freezes_all_supported_container_shapes() -> None:
    admission = PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        context={
            "none": None,
            "float": 1.5,
            "list": [1, 2],
            "tuple": ("a", "b"),
            "set": {"x"},
            "mapping": {"b": 2, "a": 1},
        },
    )

    assert admission.context["none"] is None
    assert admission.context["float"] == 1.5
    assert admission.context["list"] == (1, 2)
    assert admission.context["tuple"] == ("a", "b")
    assert admission.context["set"] == frozenset({"x"})
    nested = admission.context["mapping"]
    assert isinstance(nested, Mapping)
    assert tuple(nested.keys()) == ("a", "b")


def test_enforce_input_rejects_non_string_context_keys() -> None:
    with pytest.raises(ValueError, match="keys"):
        PolicyAdmissionInput(PolicyAdmissionMode.ENFORCE, context={1: "bad"})  # type: ignore[dict-item]


def test_disabled_record_is_canonical() -> None:
    record = disabled_policy_admission_record()

    assert record.mode is PolicyAdmissionMode.DISABLED
    assert record.policy_result is None
    assert record.safety_case is None
    assert record.enforced is False
    assert record.admission_allowed is False
    assert record.admission_decision is PolicyAdmissionDecision.DISABLED
    assert record.integrity_status is PolicyAdmissionIntegrityStatus.DISABLED
    assert record.reasons == ("POLICY_ADMISSION_DISABLED",)


def test_disabled_record_rejects_masquerading_allow() -> None:
    with pytest.raises(ValueError, match="DISABLED"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=None,
            enforced=False,
            admission_allowed=True,
            reasons=("POLICY_ADMISSION_DISABLED",),
            admission_decision=PolicyAdmissionDecision.ALLOW,
        )


def test_disabled_record_rejects_policy_result_safety_case_and_bindings() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="enforced"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
        )
    with pytest.raises(ValueError, match="policy_result"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=result,
            safety_case=None,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
        )
    with pytest.raises(ValueError, match="safety_case"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=safety_case,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
        )
    with pytest.raises(ValueError, match="integrity_status"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=None,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
            integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
        )
    with pytest.raises(ValueError, match="admission_decision"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=None,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
            admission_decision=PolicyAdmissionDecision.BLOCK,
        )
    with pytest.raises(ValueError, match="bindings"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.DISABLED,
            policy_result=None,
            safety_case=None,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_ADMISSION_DISABLED",),
            audit_id="audit-1",
        )


def test_allowed_enforce_record_requires_allow_result_and_safety_case() -> None:
    result = _allow_result()
    record = _allowed_record(result)

    assert record.admission_allowed is True
    assert record.admission_decision is PolicyAdmissionDecision.ALLOW
    assert record.integrity_status is PolicyAdmissionIntegrityStatus.PASSED

    with pytest.raises(ValueError, match="safety_case"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=None,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
        )


def test_allowed_enforce_record_requires_plan_bindings() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="missing bindings"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            capability_name="locomotion.translation",
            capability_version="v1",
        )


def test_policy_admission_record_rejects_non_bool_fields() -> None:
    with pytest.raises(ValueError, match="enforced"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced="yes",
            admission_allowed=False,
            reasons=("POLICY_REQUIRED",),
        )
    with pytest.raises(ValueError, match="admission_allowed"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed="no",
            reasons=("POLICY_REQUIRED",),
        )


def test_enforce_record_rejects_contradictory_allowed_state() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="policy_result"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
        )
    with pytest.raises(ValueError, match="admission_decision"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
            admission_decision=PolicyAdmissionDecision.BLOCK,
        )
    with pytest.raises(ValueError, match="integrity_status"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
            integrity_status=PolicyAdmissionIntegrityStatus.FAILED,
        )
    with pytest.raises(ValueError, match="exception_reason"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
            exception_reason="FORCED",
        )


def test_enforce_record_rejects_disabled_enforcement_and_orphan_safety_case() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="enforced"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=False,
            admission_allowed=False,
            reasons=("POLICY_REQUIRED",),
        )
    with pytest.raises(ValueError, match="policy_result"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=False,
            reasons=("POLICY_REQUIRED",),
        )


@pytest.mark.parametrize(
    "value",
    ["ALLOW ", "allow", "ALLOW\u200b", "\uff21\uff2c\uff2c\uff2f\uff37"],
)
def test_admission_decision_values_are_strict(value: str) -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
            admission_decision=value,
        )


def test_enforce_record_rejects_non_allow_admission_allowed() -> None:
    result = _block_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="ALLOW"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_BLOCKED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
        )


def test_denied_enforce_record_requires_reasons() -> None:
    with pytest.raises(ValueError, match="reasons"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons=(),
        )


def test_denied_enforce_record_rejects_allow_admission_decision() -> None:
    with pytest.raises(ValueError, match="ALLOW admission_decision"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons=("POLICY_REQUIRED",),
            admission_decision=PolicyAdmissionDecision.ALLOW,
        )


def test_denied_enforce_record_normalises_decision_statuses() -> None:
    error_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_EVALUATION_FAILED",),
    )
    not_run_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_ADMISSION_NOT_RUN",),
    )
    block_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_REQUIRED",),
    )
    allow_result_denied_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=_allow_result(),
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_ADMISSION_INTEGRITY_FAILED",),
    )
    policy_block_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=_block_result(),
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_BLOCKED",),
    )

    assert error_record.admission_decision is PolicyAdmissionDecision.ERROR
    assert not_run_record.admission_decision is PolicyAdmissionDecision.NOT_RUN
    assert block_record.admission_decision is PolicyAdmissionDecision.BLOCK
    assert allow_result_denied_record.admission_decision is PolicyAdmissionDecision.BLOCK
    assert policy_block_record.admission_decision is PolicyAdmissionDecision.BLOCK
    assert policy_block_record.integrity_status is PolicyAdmissionIntegrityStatus.NOT_CHECKED


@pytest.mark.parametrize("value", ["FAILED ", "MAYBE"])
def test_integrity_status_values_are_strict(value: str) -> None:
    with pytest.raises(ValueError):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons=("POLICY_REQUIRED",),
            integrity_status=value,
        )


def test_record_rejects_empty_reason_and_bare_string_reasons() -> None:
    with pytest.raises(ValueError, match="iterable"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons="POLICY_REQUIRED",
        )
    with pytest.raises(ValueError, match="reasons"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=None,
            safety_case=None,
            enforced=True,
            admission_allowed=False,
            reasons=(" ",),
        )


def test_record_rejects_mismatched_safety_case() -> None:
    allow_result = _allow_result()
    block_result = _block_result()
    safety_case = _safety_case(block_result)

    with pytest.raises(ValueError, match="explain"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=allow_result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            capability_name="locomotion.translation",
            capability_version="v1",
        )


def test_record_rejects_policy_and_safety_case_identity_mismatches() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    with pytest.raises(ValueError, match="policy_id"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            policy_id="other-policy",
            capability_name="locomotion.translation",
            capability_version="v1",
        )
    with pytest.raises(ValueError, match="policy_result_checksum"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            policy_result_checksum="wrong",
            capability_name="locomotion.translation",
            capability_version="v1",
        )
    with pytest.raises(ValueError, match="safety_case_id"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            audit_id="audit-1",
            plan_id="plan-1",
            plan_checksum="checksum-1",
            safety_case_id="other-case",
            capability_name="locomotion.translation",
            capability_version="v1",
        )


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("audit_id", "other-audit", "audit_id"),
        ("plan_id", "other-plan", "plan_id"),
        ("plan_checksum", "other-checksum", "plan_checksum"),
        ("world_snapshot_id", "other-snapshot", "world_snapshot_id"),
        ("world_snapshot_checksum", "other-snapshot-checksum", "world_snapshot_checksum"),
        ("capability_name", "other.capability", "capability_name"),
        ("capability_version", "v2", "capability_version"),
    ],
)
def test_allowed_record_rejects_safety_case_binding_mismatches(
    field_name: str,
    value: str,
    message: str,
) -> None:
    snapshot = fresh_world_snapshot("snapshot-1", checksum="snap-check")
    record = _bound_allowed_record(world_snapshot=snapshot)
    kwargs = {
        "audit_id": record.audit_id,
        "plan_id": record.plan_id,
        "plan_checksum": record.plan_checksum,
        "world_snapshot_id": record.world_snapshot_id,
        "world_snapshot_checksum": record.world_snapshot_checksum,
        "capability_name": record.capability_name,
        "capability_version": record.capability_version,
    }
    kwargs[field_name] = value

    with pytest.raises(ValueError, match=message):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=record.policy_result,
            safety_case=record.safety_case,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
            **kwargs,
        )


def test_assert_policy_admission_integrity_returns_bound_evidence() -> None:
    audited_plan = _audited_plan()
    snapshot = fresh_world_snapshot()
    freshness_result = fresh_world_snapshot_result(snapshot)
    result = bind_policy_result_to_freshness(_allow_result(), freshness_result)
    safety_case = build_safety_case(
        policy_result=result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )
    record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )

    integrity = assert_policy_admission_integrity(audited_plan, record)

    assert integrity.status is PolicyAdmissionIntegrityStatus.PASSED
    assert integrity.audit_id == audited_plan.audit_id
    assert integrity.plan_id == audited_plan.plan.plan_id
    assert integrity.policy_id == result.policy_id
    assert integrity.policy_result_checksum == policy_evaluation_result_checksum(result)


def test_policy_backed_approval_predicate_rejects_non_matching_gate_states() -> None:
    audited_plan = _audited_plan()
    snapshot = fresh_world_snapshot()
    freshness_result = fresh_world_snapshot_result(snapshot)
    result = bind_policy_result_to_freshness(_allow_result(), freshness_result)
    safety_case = build_safety_case(
        policy_result=result,
        audited_plan_id=audited_plan.audit_id,
        world_snapshot=snapshot,
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        capability=_capability(),
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )
    record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
        audit_id=audited_plan.audit_id,
        plan_id=audited_plan.plan.plan_id,
        plan_checksum=audited_plan.checksum,
        world_snapshot_id=safety_case.world_snapshot_id,
        world_snapshot_checksum=safety_case.world_snapshot_checksum,
        capability_name=safety_case.capability_name,
        capability_version=safety_case.capability_version,
        world_snapshot_observed_at_ms=freshness_result.observed_at_ms,
        freshness_result_checksum=freshness_result.checksum,
        freshness_status=freshness_result.status.value,
    )
    allowed_gate = gate_audited_plan(audited_plan)
    blocked_gate = GateDecision(
        GateDecisionStatus.BLOCKED,
        audited_plan.audit_id,
        audited_plan.plan.plan_id,
        (GateBlockReason.CHECKSUM_MISMATCH,),
        False,
        True,
    )

    assert is_policy_backed_approval(audited_plan, record, allowed_gate)
    assert not is_policy_backed_approval(audited_plan, None, allowed_gate)
    assert not is_policy_backed_approval(audited_plan, record, None)
    assert not is_policy_backed_approval(audited_plan, record, blocked_gate)
    assert not is_policy_backed_approval(
        audited_plan, disabled_policy_admission_record(), allowed_gate
    )

    object.__setattr__(allowed_gate, "audit_id", "other-audit")
    assert not is_policy_backed_approval(audited_plan, record, allowed_gate)
    object.__setattr__(allowed_gate, "audit_id", audited_plan.audit_id)
    object.__setattr__(allowed_gate, "plan_id", "other-plan")
    assert not is_policy_backed_approval(audited_plan, record, allowed_gate)


def test_integrity_assertion_reports_disabled_missing_and_mismatched_policy_state() -> None:
    audited_plan = _audited_plan()
    disabled_record = disabled_policy_admission_record()
    denied_missing_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=None,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_REQUIRED",),
    )
    block_result = _block_result()
    block_record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=block_result,
        safety_case=None,
        enforced=True,
        admission_allowed=False,
        reasons=("POLICY_BLOCKED",),
    )
    forged_record = _bound_allowed_record()
    object.__setattr__(forged_record, "policy_result", block_result)
    exception_marked_record = _bound_allowed_record()
    object.__setattr__(exception_marked_record, "exception_reason", "FORCED")

    for record in (
        disabled_record,
        denied_missing_record,
        block_record,
        forged_record,
        exception_marked_record,
    ):
        with pytest.raises(PolicyAdmissionIntegrityError, match="Policy admission integrity"):
            assert_policy_admission_integrity(audited_plan, record)


def test_policy_admission_record_is_frozen() -> None:
    record = disabled_policy_admission_record()

    with pytest.raises((AttributeError, TypeError)):
        record.admission_allowed = False  # type: ignore[misc]
