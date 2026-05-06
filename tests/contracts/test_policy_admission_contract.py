"""Contract tests for pipeline policy admission input and record objects."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
)
from aegis.contracts.policy_admission import (
    PolicyAdmissionInput,
    PolicyAdmissionMode,
    PolicyAdmissionRecord,
    disabled_policy_admission_record,
)
from aegis.policy import build_safety_case


def _policy() -> Policy:
    return Policy(
        "policy-1",
        "v1",
        [PolicyRule("rule-1", "locomotion.translation", [Constraint("max_velocity")])],
    )


def _capability() -> Capability:
    return Capability("locomotion.translation", parameters={"velocity_mps": 0.2})


def _allow_result() -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        PolicyDecision.ALLOW,
        "policy-1",
        ["rule-1"],
        ["rule-1:0:max_velocity"],
        [],
        ["POLICY_ALLOWED"],
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
    return build_safety_case(
        policy_result=result,
        audited_plan_id="audit-1",
        evidence={"capability_name": "locomotion.translation", "capability_version": "v1"},
    )


def test_policy_admission_mode_values_are_stable() -> None:
    assert PolicyAdmissionMode.DISABLED == "DISABLED"
    assert PolicyAdmissionMode.ENFORCE == "ENFORCE"
    assert isinstance(PolicyAdmissionMode.ENFORCE, str)


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


def test_disabled_record_is_canonical() -> None:
    record = disabled_policy_admission_record()

    assert record.mode is PolicyAdmissionMode.DISABLED
    assert record.policy_result is None
    assert record.safety_case is None
    assert record.enforced is False
    assert record.admission_allowed is True
    assert record.reasons == ("POLICY_ADMISSION_DISABLED",)


def test_allowed_enforce_record_requires_allow_result_and_safety_case() -> None:
    result = _allow_result()
    safety_case = _safety_case(result)

    record = PolicyAdmissionRecord(
        PolicyAdmissionMode.ENFORCE,
        policy_result=result,
        safety_case=safety_case,
        enforced=True,
        admission_allowed=True,
        reasons=("POLICY_ALLOWED",),
    )

    assert record.admission_allowed is True

    with pytest.raises(ValueError, match="safety_case"):
        PolicyAdmissionRecord(
            PolicyAdmissionMode.ENFORCE,
            policy_result=result,
            safety_case=None,
            enforced=True,
            admission_allowed=True,
            reasons=("POLICY_ALLOWED",),
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
        )


def test_policy_admission_record_is_frozen() -> None:
    record = disabled_policy_admission_record()

    with pytest.raises((AttributeError, TypeError)):
        record.admission_allowed = False  # type: ignore[misc]
