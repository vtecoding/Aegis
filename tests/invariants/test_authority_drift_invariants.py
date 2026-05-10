"""ADR-0014 invariants for authority drift coverage."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineOutcome
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.governance.aegis_context_authority import ContextAuthority
from aegis.governance.aegis_contract_drift import evaluate_contract_drift
from aegis.governance.aegis_coverage_sentinel import evaluate_coverage_sentinel
from aegis.pipeline import run_pipeline


def _context(request_id: str) -> ExecutionContext:
    return ExecutionContext(request_id, datetime(2026, 1, 1, tzinfo=UTC), "policy-v1")


def _intent(context: ExecutionContext) -> RawIntent:
    return RawIntent("move", {"target": {"x": 1, "y": 2}}, "operator", 5, context)


def _policy(policy_id: str, version: str = "v1") -> Policy:
    return Policy(
        policy_id,
        version,
        (
            PolicyRule(
                "rule-max-velocity",
                "locomotion.translation",
                (Constraint("max_velocity", {"max_mps": 1.0}),),
            ),
        ),
    )


def _admission(snapshot, policy_id: str) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_policy(policy_id),
        capability=Capability("locomotion.translation", parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


@given(st.integers(min_value=1, max_value=25))
@settings(max_examples=10)
def test_invariant_allowed_pipeline_binds_policy_and_context_authority(
    request_number: int,
) -> None:
    context = _context(f"authority-invariant-{request_number}")
    snapshot = fresh_world_snapshot(snapshot_id=f"authority-snapshot-{request_number}")
    kwargs = trusted_pipeline_kwargs(snapshot)
    context_authority = kwargs["context_authority"]
    assert isinstance(context_authority, ContextAuthority)

    result = run_pipeline(
        _intent(context),
        context,
        policy_admission=_admission(snapshot, f"authority-policy-{request_number}"),
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **kwargs,
    )

    assert result.outcome is PipelineOutcome.ALLOWED
    assert result.policy_admission.policy_result is not None
    assert result.approval_receipt is not None
    assert (
        result.policy_admission.policy_checksum
        == result.policy_admission.policy_result.policy_checksum
    )
    assert result.policy_admission.context_authority_checksum == context_authority.context_checksum
    assert result.approval_receipt.policy_checksum == result.policy_admission.policy_checksum
    assert result.approval_receipt.context_authority_checksum == context_authority.context_checksum


@given(st.text(alphabet=st.characters(whitelist_categories=("Ll", "Nd")), min_size=1, max_size=8))
@settings(max_examples=10)
def test_invariant_policy_checksum_changes_with_policy_version(version_suffix: str) -> None:
    first_policy = _policy("authority-version-policy", f"v1-{version_suffix}")
    second_policy = _policy("authority-version-policy", f"v2-{version_suffix}")

    assert first_policy.policy_checksum != second_policy.policy_checksum


def test_invariant_governance_sentinels_have_no_release_drift() -> None:
    assert evaluate_contract_drift().passed
    assert evaluate_coverage_sentinel().passed
