"""Canonical deterministic scenario fixture factory for ADR-0013."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from aegis.contracts.attestation_verifier import AttestationVerifierAdapterMetadata
from aegis.contracts.context import ExecutionContext
from aegis.contracts.decision_trace import DECISION_TRACE_STAGE_ORDER
from aegis.contracts.intent import RawIntent
from aegis.contracts.json_types import JsonValue
from aegis.contracts.pipeline import PipelineOutcome
from aegis.contracts.policy import Capability, Constraint, Policy, PolicyRule, WorldSnapshotStub
from aegis.contracts.world_snapshot_trust import (
    AttestationVerificationResult,
    TrustDomain,
    WorldSnapshotAttestation,
    WorldSnapshotEvidenceEnvelope,
    WorldSnapshotSourceType,
    WorldSnapshotTrustPolicy,
    world_snapshot_attestation_payload_checksum,
)
from aegis.governance.context_authority import ContextAuthority
from aegis.scenarios.contracts import (
    EvilTwinMutation,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioExpectation,
)

SCENARIO_EVALUATION_TIME_MS = 1_000_500
SCENARIO_CAPTURED_AT_MS = 1_000_000
SCENARIO_EXPIRES_AT_MS = 1_010_000
SCENARIO_CAPABILITY = "locomotion.translation"
SCENARIO_SOURCE_ID = "trusted-simulator"
SCENARIO_TRUST_POLICY_ID = "scenario-world-snapshot-trust-policy"
SCENARIO_ALGORITHM = "fixture-sha256"
SCENARIO_KEY_ID = "fixture-key"
SCENARIO_VERIFIER_ID = "fixture-verifier"
SCENARIO_ENVELOPE_ID = "world-snapshot-evidence-envelope"
SCENARIO_NONCE = "world-snapshot-evidence-nonce"

_FULL_CHAIN = tuple(DECISION_TRACE_STAGE_ORDER)
_ADMISSIBILITY_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "policy_admission",
)
_FRESHNESS_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "policy_admission",
)
_VERIFIER_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "verifier_certification",
    "policy_admission",
)
_TRUST_CONFIG_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "verifier_certification",
    "trust_policy_config",
    "policy_admission",
)
_TRUST_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "verifier_certification",
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_admission",
)
_POLICY_DENIED_PATH = (
    "raw_intent",
    "validation",
    "planning",
    "audit",
    "world_snapshot_admissibility",
    "world_snapshot_freshness",
    "verifier_certification",
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "policy_admission",
)
_DISABLED_PATH = ("raw_intent", "validation", "planning", "audit", "policy_admission")

_AFTER_ADMISSIBILITY = (
    "world_snapshot_freshness",
    "verifier_certification",
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "gate_decision",
)
_AFTER_FRESHNESS = (
    "verifier_certification",
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "gate_decision",
)
_AFTER_VERIFIER = (
    "trust_policy_config",
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "gate_decision",
)
_AFTER_TRUST_CONFIG = (
    "world_snapshot_trust",
    "policy_evaluation",
    "safety_case",
    "gate_decision",
)
_AFTER_TRUST = ("policy_evaluation", "safety_case", "gate_decision")
_AFTER_POLICY = ("gate_decision",)


class PassingScenarioAttestationVerifier:
    """Deterministic verifier that accepts matching fixture attestations."""

    @property
    def metadata(self) -> AttestationVerifierAdapterMetadata:
        """Return immutable verifier adapter metadata."""
        return AttestationVerifierAdapterMetadata(
            verifier_id=SCENARIO_VERIFIER_ID,
            verifier_version="fixture-v1",
            supported_algorithms={SCENARIO_ALGORITHM},
            supported_key_ids={SCENARIO_KEY_ID},
            adapter_kind="strict-fixture",
            unsafe_test_only=False,
        )

    def verify(
        self,
        *,
        attestation: WorldSnapshotAttestation,
        evidence_envelope: WorldSnapshotEvidenceEnvelope,
        world_snapshot_checksum: str,
    ) -> AttestationVerificationResult:
        """Verify deterministic fixture attestation bindings."""
        failure_reason = _attestation_failure_reason(
            attestation=attestation,
            evidence_envelope=evidence_envelope,
            world_snapshot_checksum=world_snapshot_checksum,
        )
        return AttestationVerificationResult(
            status="PASS" if failure_reason is None else "FAIL",
            reason_code="FIXTURE_VERIFIED" if failure_reason is None else failure_reason,
            attestation_checksum=attestation.checksum,
            evidence_envelope_checksum=evidence_envelope.checksum,
            world_snapshot_checksum=world_snapshot_checksum,
            verifier_id=SCENARIO_VERIFIER_ID,
        )


class ScenarioFixtureFactory:
    """Factory for canonical deterministic scenario definitions."""

    @staticmethod
    def canonical_scenarios() -> tuple[ScenarioDefinition, ...]:
        """Return the closed ADR-0013 scenario matrix."""
        return canonical_scenario_definitions()


def canonical_scenario_definitions() -> tuple[ScenarioDefinition, ...]:
    """Return every required ADR-0013 and ADR-0015 scenario category."""
    return (
        _positive_allowed(),
        _missing_world_snapshot(),
        _inadmissible_world_snapshot(),
        _stale_world_snapshot(),
        _future_dated_world_snapshot(),
        _missing_evidence(),
        _invalid_attestation(),
        _uncertified_verifier(),
        _invalid_trust_config(),
        _wrong_capability_scope(),
        _policy_denied(),
        _evil_twin(ScenarioCategory.SAFETY_CASE_FORGED, EvilTwinMutation.SAFETY_CASE_FORGED),
        _evil_twin(ScenarioCategory.ADMISSION_MISMATCH, EvilTwinMutation.ADMISSION_MISMATCH),
        _evil_twin(ScenarioCategory.RECEIPT_FORGED, EvilTwinMutation.RECEIPT_FIELD_FORGED),
        _direct_gate_bypass(),
        _evil_twin(ScenarioCategory.REPLAYED_RECEIPT, EvilTwinMutation.REPLAYED_RECEIPT),
        _evil_twin(ScenarioCategory.CHECKSUM_MISMATCH, EvilTwinMutation.TRACE_CHECKSUM_MISMATCH),
        _evil_twin(ScenarioCategory.CONFUSABLE_STAGE_NAME, EvilTwinMutation.CONFUSABLE_STAGE_NAME),
        _partial_receipt_overclaim(),
        *_adapter_boundary_scenarios(),
        *_adapter_replay_scenarios(),
    )


def _adapter_replay_scenarios() -> tuple[ScenarioDefinition, ...]:
    return tuple(
        _adapter_replay_category_scenario(category)
        for category in (
            ScenarioCategory.ADAPTER_REPLAY_POSITIVE,
            ScenarioCategory.ADAPTER_REPLAY_RECEIPT_DRIFT,
            ScenarioCategory.ADAPTER_REPLAY_MAPPING_DRIFT,
            ScenarioCategory.ADAPTER_REPLAY_RUNTIME_TARGET_DRIFT,
            ScenarioCategory.ADAPTER_REPLAY_CROSS_PIPELINE_SWAP,
            ScenarioCategory.ADAPTER_REPLAY_AUTHORITY_MISMATCH,
            ScenarioCategory.ADAPTER_REPLAY_QOS_NAMESPACE_MUTATION,
            ScenarioCategory.ADAPTER_REPLAY_RESOURCE_BOUNDS,
        )
    )


def _adapter_replay_category_scenario(category: ScenarioCategory) -> ScenarioDefinition:
    snapshot = _snapshot(
        snapshot_id=f"scenario-snapshot-{category.value.lower().replace('_', '-')}"
    )
    return _definition(
        scenario_id=f"scenario.{category.value.lower()}",
        name=category.value.replace("_", " ").title(),
        category=category,
        expected=_expect(
            outcome=PipelineOutcome.ALLOWED,
            reason="GATE_ALLOWED",
            terminal_stage="gate_decision",
            required=_FULL_CHAIN,
            forbidden=(),
            allow_late=True,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def make_scenario_context(request_id: str) -> ExecutionContext:
    """Return a deterministic execution context for canonical scenarios."""
    return ExecutionContext(request_id, datetime(2026, 5, 9, tzinfo=UTC), "policy-v1")


def make_scenario_context_authority(
    scenario_id: str,
    evaluation_time_ms: int,
) -> ContextAuthority:
    """Return deterministic context authority for an enforced scenario."""
    return ContextAuthority(
        context_id=f"{scenario_id}.context",
        request_id=scenario_id,
        evaluation_time_ms=evaluation_time_ms,
        caller_authority="scenario-runner",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )


def _base_intent(scenario_id: str, *, target_x: int = 1, command: str = "move") -> RawIntent:
    context = make_scenario_context(scenario_id)
    target_parameters: dict[str, JsonValue] = {"x": target_x, "y": 2}
    parameters: Mapping[str, JsonValue] = {} if command == "stop" else {"target": target_parameters}
    return RawIntent(
        command,
        parameters,
        "scenario-runner",
        5,
        context,
    )


def _capability(*, velocity_mps: float = 0.2, name: str = SCENARIO_CAPABILITY) -> Capability:
    return Capability(name, parameters={"velocity_mps": velocity_mps})


def _policy(*, max_mps: float = 1.0, capability: str = SCENARIO_CAPABILITY) -> Policy:
    return Policy(
        f"scenario-policy-{capability.replace('.', '-')}-{max_mps}",
        "v1",
        [
            PolicyRule(
                "rule-max-velocity",
                capability,
                [Constraint("max_velocity", {"max_mps": max_mps})],
            )
        ],
    )


def _snapshot(
    *,
    snapshot_id: str = "scenario-snapshot-fresh",
    captured_at_ms: int = SCENARIO_CAPTURED_AT_MS,
    expires_at_ms: int = SCENARIO_EXPIRES_AT_MS,
    checksum: str | None = "scenario-snapshot-checksum",
    declared_capability_scope: tuple[str, ...] | None = (SCENARIO_CAPABILITY,),
) -> WorldSnapshotStub:
    return WorldSnapshotStub(
        snapshot_id,
        captured_at_ms,
        expires_at_ms,
        "fixture",
        1.0,
        {"target_zone_id": "clear-zone", "nearest_human_distance_m": 10.0},
        checksum=checksum,
        declared_capability_scope=declared_capability_scope,
        declared_fact_keys=("target_zone_id", "nearest_human_distance_m"),
    )


def _trust_policy(
    *,
    capability: str = SCENARIO_CAPABILITY,
    require_attestation: bool = True,
) -> WorldSnapshotTrustPolicy:
    return WorldSnapshotTrustPolicy(
        policy_id=SCENARIO_TRUST_POLICY_ID,
        allowed_source_ids={SCENARIO_SOURCE_ID},
        allowed_source_types={WorldSnapshotSourceType.SIMULATOR},
        allowed_trust_domains={TrustDomain.SIMULATION},
        allowed_capabilities={capability},
        require_attestation=require_attestation,
        allowed_algorithms={SCENARIO_ALGORITHM},
        allowed_key_ids={SCENARIO_KEY_ID},
        max_attestation_age_ms=1_000,
    )


def _attestation(
    snapshot: WorldSnapshotStub,
    *,
    signature: str = "fixture-signature",
) -> WorldSnapshotAttestation:
    if snapshot.checksum is None:
        raise ValueError("scenario attestation requires a snapshot checksum")
    payload_checksum = world_snapshot_attestation_payload_checksum(
        subject_snapshot_checksum=snapshot.checksum,
        subject_envelope_id=SCENARIO_ENVELOPE_ID,
        source_id=SCENARIO_SOURCE_ID,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=SCENARIO_EVALUATION_TIME_MS,
        valid_from_ms=SCENARIO_EVALUATION_TIME_MS,
        valid_until_ms=SCENARIO_EVALUATION_TIME_MS + 1_000,
        algorithm=SCENARIO_ALGORITHM,
        key_id=SCENARIO_KEY_ID,
    )
    return WorldSnapshotAttestation(
        attestation_id="scenario-world-snapshot-attestation",
        subject_snapshot_checksum=snapshot.checksum,
        subject_envelope_id=SCENARIO_ENVELOPE_ID,
        source_id=SCENARIO_SOURCE_ID,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=SCENARIO_EVALUATION_TIME_MS,
        valid_from_ms=SCENARIO_EVALUATION_TIME_MS,
        valid_until_ms=SCENARIO_EVALUATION_TIME_MS + 1_000,
        algorithm=SCENARIO_ALGORITHM,
        key_id=SCENARIO_KEY_ID,
        signature=signature,
        signed_payload_checksum=payload_checksum,
    )


def _evidence(
    snapshot: WorldSnapshotStub, *, signature: str = "fixture-signature"
) -> WorldSnapshotEvidenceEnvelope:
    if snapshot.checksum is None:
        raise ValueError("scenario evidence requires a snapshot checksum")
    return WorldSnapshotEvidenceEnvelope(
        envelope_id=SCENARIO_ENVELOPE_ID,
        world_snapshot_checksum=snapshot.checksum,
        source_id=SCENARIO_SOURCE_ID,
        source_type=WorldSnapshotSourceType.SIMULATOR,
        trust_domain=TrustDomain.SIMULATION,
        issued_at_ms=SCENARIO_EVALUATION_TIME_MS,
        evidence_nonce=SCENARIO_NONCE,
        attestation=_attestation(snapshot, signature=signature),
    )


def _expect(
    *,
    outcome: PipelineOutcome,
    reason: str,
    terminal_stage: str,
    required: tuple[str, ...],
    forbidden: tuple[str, ...],
    receipt_valid: bool = True,
    receipt_required: bool = True,
    allow_late: bool = False,
) -> ScenarioExpectation:
    return ScenarioExpectation(
        expected_outcome=outcome,
        expected_reason=reason,
        expected_terminal_stage=terminal_stage,
        required_stages=required,
        forbidden_stages=forbidden,
        receipt_must_be_valid=receipt_valid,
        approval_receipt_required=receipt_required,
        allow_late_stage_artifacts=allow_late,
    )


def _definition(
    *,
    scenario_id: str,
    name: str,
    category: ScenarioCategory,
    expected: ScenarioExpectation,
    snapshot: WorldSnapshotStub | None,
    policy: Policy | None = None,
    capability: Capability | None = None,
    evidence: WorldSnapshotEvidenceEnvelope | None = None,
    trust_policy: WorldSnapshotTrustPolicy | None = None,
    verifier: PassingScenarioAttestationVerifier | None = None,
    evaluation_time_ms: int | None = SCENARIO_EVALUATION_TIME_MS,
    mutation: EvilTwinMutation = EvilTwinMutation.NONE,
    intent_command: str = "move",
) -> ScenarioDefinition:
    return ScenarioDefinition(
        scenario_id=scenario_id,
        name=name,
        category=category,
        intent=_base_intent(scenario_id, command=intent_command),
        policy=policy or _policy(),
        world_snapshot=snapshot,
        evaluation_time_ms=evaluation_time_ms,
        trust_policy_config=trust_policy,
        verifier=verifier,
        expected=expected,
        metadata={"category": category.value},
        capability=capability or _capability(),
        context_authority=make_scenario_context_authority(scenario_id, evaluation_time_ms)
        if evaluation_time_ms is not None
        else None,
        world_snapshot_evidence=evidence,
        evil_twin_mutation=mutation,
    )


def _positive_allowed() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.positive_allowed",
        name="Valid evidence path",
        category=ScenarioCategory.POSITIVE_ALLOWED,
        expected=_expect(
            outcome=PipelineOutcome.ALLOWED,
            reason="GATE_ALLOWED",
            terminal_stage="gate_decision",
            required=_FULL_CHAIN,
            forbidden=(),
            allow_late=True,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _missing_world_snapshot() -> ScenarioDefinition:
    return _definition(
        scenario_id="scenario.missing_world_snapshot",
        name="Missing world snapshot",
        category=ScenarioCategory.MISSING_WORLD_SNAPSHOT,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_MISSING",
            terminal_stage="world_snapshot_admissibility",
            required=_ADMISSIBILITY_PATH,
            forbidden=_AFTER_ADMISSIBILITY,
        ),
        snapshot=None,
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _inadmissible_world_snapshot() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-missing-checksum", checksum=None)
    return _definition(
        scenario_id="scenario.inadmissible_world_snapshot",
        name="Inadmissible world snapshot",
        category=ScenarioCategory.INADMISSIBLE_WORLD_SNAPSHOT,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_CHECKSUM_MISSING",
            terminal_stage="world_snapshot_admissibility",
            required=_ADMISSIBILITY_PATH,
            forbidden=_AFTER_ADMISSIBILITY,
        ),
        snapshot=snapshot,
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _stale_world_snapshot() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-stale", captured_at_ms=998_000)
    return _definition(
        scenario_id="scenario.stale_world_snapshot",
        name="Stale world snapshot",
        category=ScenarioCategory.STALE_WORLD_SNAPSHOT,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_STALE",
            terminal_stage="world_snapshot_freshness",
            required=_FRESHNESS_PATH,
            forbidden=_AFTER_FRESHNESS,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _future_dated_world_snapshot() -> ScenarioDefinition:
    snapshot = _snapshot(
        snapshot_id="scenario-snapshot-future",
        captured_at_ms=SCENARIO_EVALUATION_TIME_MS + 100,
        expires_at_ms=SCENARIO_EVALUATION_TIME_MS + 2_000,
    )
    return _definition(
        scenario_id="scenario.future_dated_world_snapshot",
        name="Future-dated world snapshot",
        category=ScenarioCategory.FUTURE_DATED_WORLD_SNAPSHOT,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_FUTURE_DATED",
            terminal_stage="world_snapshot_freshness",
            required=_FRESHNESS_PATH,
            forbidden=_AFTER_FRESHNESS,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _missing_evidence() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.missing_evidence",
        name="Missing evidence",
        category=ScenarioCategory.MISSING_EVIDENCE,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_EVIDENCE_MISSING",
            terminal_stage="world_snapshot_trust",
            required=_TRUST_PATH,
            forbidden=_AFTER_TRUST,
        ),
        snapshot=snapshot,
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _invalid_attestation() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.invalid_attestation",
        name="Invalid attestation",
        category=ScenarioCategory.INVALID_ATTESTATION,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_ATTESTATION_INVALID",
            terminal_stage="world_snapshot_trust",
            required=_TRUST_PATH,
            forbidden=_AFTER_TRUST,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot, signature="tampered-fixture-signature"),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _uncertified_verifier() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.uncertified_verifier",
        name="Uncertified verifier",
        category=ScenarioCategory.UNCERTIFIED_VERIFIER,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="ATTESTATION_VERIFIER_MISSING",
            terminal_stage="verifier_certification",
            required=_VERIFIER_PATH,
            forbidden=_AFTER_VERIFIER,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=None,
    )


def _invalid_trust_config() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.invalid_trust_config",
        name="Invalid trust policy config",
        category=ScenarioCategory.INVALID_TRUST_CONFIG,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="TRUST_POLICY_ATTESTATION_REQUIRED_FALSE_IN_ENFORCE",
            terminal_stage="trust_policy_config",
            required=_TRUST_CONFIG_PATH,
            forbidden=_AFTER_TRUST_CONFIG,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(require_attestation=False),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _wrong_capability_scope() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-wrong-scope")
    wrong_capability = _capability(name="manipulation.grip")
    return _definition(
        scenario_id="scenario.wrong_capability_scope",
        name="Wrong capability scope",
        category=ScenarioCategory.WRONG_CAPABILITY_SCOPE,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="WORLD_SNAPSHOT_CAPABILITY_SCOPE_MISMATCH",
            terminal_stage="world_snapshot_admissibility",
            required=_ADMISSIBILITY_PATH,
            forbidden=_AFTER_ADMISSIBILITY,
        ),
        snapshot=snapshot,
        policy=_policy(capability="manipulation.grip"),
        capability=wrong_capability,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(capability="manipulation.grip"),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _policy_denied() -> ScenarioDefinition:
    snapshot = _snapshot()
    return _definition(
        scenario_id="scenario.policy_denied",
        name="Policy denied",
        category=ScenarioCategory.POLICY_DENIED,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="POLICY_BLOCKED",
            terminal_stage="policy_evaluation",
            required=_POLICY_DENIED_PATH,
            forbidden=_AFTER_POLICY,
            allow_late=True,
        ),
        snapshot=snapshot,
        policy=_policy(max_mps=0.1),
        capability=_capability(velocity_mps=0.2),
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
    )


def _evil_twin(category: ScenarioCategory, mutation: EvilTwinMutation) -> ScenarioDefinition:
    snapshot = _snapshot(
        snapshot_id=f"scenario-snapshot-{category.value.lower().replace('_', '-')}"
    )
    return _definition(
        scenario_id=f"scenario.{category.value.lower()}",
        name=category.value.replace("_", " ").title(),
        category=category,
        expected=_expect(
            outcome=PipelineOutcome.ERROR,
            reason="APPROVAL_RECEIPT_INTEGRITY_FAILED",
            terminal_stage="receipt_validation",
            required=_FULL_CHAIN,
            forbidden=(),
            receipt_valid=False,
            allow_late=True,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
        mutation=mutation,
    )


def _direct_gate_bypass() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-direct-gate-bypass")
    return ScenarioDefinition(
        scenario_id="scenario.direct_gate_bypass",
        name="Direct gate bypass",
        category=ScenarioCategory.DIRECT_GATE_BYPASS,
        intent=_base_intent("scenario.direct_gate_bypass"),
        policy=None,
        world_snapshot=snapshot,
        evaluation_time_ms=None,
        trust_policy_config=None,
        verifier=None,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="DIRECT_GATE_BYPASS_REJECTED",
            terminal_stage="direct_gate",
            required=_DISABLED_PATH,
            forbidden=("gate_decision",),
            receipt_valid=True,
        ),
        metadata={"category": ScenarioCategory.DIRECT_GATE_BYPASS.value},
        capability=None,
        evil_twin_mutation=EvilTwinMutation.DIRECT_GATE_ONLY,
    )


def _partial_receipt_overclaim() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-partial-overclaim")
    return _definition(
        scenario_id="scenario.partial_receipt_overclaim",
        name="Partial receipt overclaim",
        category=ScenarioCategory.PARTIAL_RECEIPT_OVERCLAIM,
        expected=_expect(
            outcome=PipelineOutcome.ERROR,
            reason="APPROVAL_RECEIPT_INTEGRITY_FAILED",
            terminal_stage="receipt_validation",
            required=_TRUST_PATH,
            forbidden=("policy_evaluation", "safety_case", "gate_decision"),
            receipt_valid=False,
            allow_late=True,
        ),
        snapshot=snapshot,
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
        mutation=EvilTwinMutation.PARTIAL_RECEIPT_OVERCLAIM,
    )


def _adapter_boundary_scenarios() -> tuple[ScenarioDefinition, ...]:
    return tuple(
        _adapter_category_scenario(category)
        for category in (
            ScenarioCategory.ADAPTER_VALID_ROS2_MOVE_MAPPING,
            ScenarioCategory.ADAPTER_VALID_ROS2_STOP_MAPPING,
            ScenarioCategory.ADAPTER_BLOCKED_PIPELINE_RESULT,
            ScenarioCategory.ADAPTER_INVALID_RECEIPT,
            ScenarioCategory.ADAPTER_CAPABILITY_MISMATCH,
            ScenarioCategory.ADAPTER_COMMAND_MISMATCH,
            ScenarioCategory.ADAPTER_NAMESPACE_MISMATCH,
            ScenarioCategory.ADAPTER_QOS_INVALID,
            ScenarioCategory.ADAPTER_REQUIRED_FIELD_MISSING,
            ScenarioCategory.ADAPTER_FORBIDDEN_FIELD,
            ScenarioCategory.ADAPTER_CHECKSUM_FORGED,
            ScenarioCategory.ADAPTER_DIRECT_BYPASS,
            ScenarioCategory.ADAPTER_CONFUSABLE_RUNTIME_NAME,
            ScenarioCategory.ADAPTER_PAYLOAD_RESOURCE_EXCEEDED,
        )
    )


def _adapter_category_scenario(category: ScenarioCategory) -> ScenarioDefinition:
    if category is ScenarioCategory.ADAPTER_BLOCKED_PIPELINE_RESULT:
        return _adapter_blocked_pipeline_category()
    snapshot = _snapshot(
        snapshot_id=f"scenario-snapshot-{category.value.lower().replace('_', '-')}"
    )
    command = "stop" if category is ScenarioCategory.ADAPTER_VALID_ROS2_STOP_MAPPING else "move"
    return _definition(
        scenario_id=f"scenario.{category.value.lower()}",
        name=category.value.replace("_", " ").title(),
        category=category,
        expected=_expect(
            outcome=PipelineOutcome.ALLOWED,
            reason="GATE_ALLOWED",
            terminal_stage="gate_decision",
            required=_FULL_CHAIN,
            forbidden=(),
            allow_late=True,
        ),
        snapshot=snapshot,
        evidence=_evidence(snapshot),
        trust_policy=_trust_policy(),
        verifier=PassingScenarioAttestationVerifier(),
        intent_command=command,
    )


def _adapter_blocked_pipeline_category() -> ScenarioDefinition:
    snapshot = _snapshot(snapshot_id="scenario-snapshot-adapter-blocked-pipeline")
    return ScenarioDefinition(
        scenario_id="scenario.adapter_blocked_pipeline_result",
        name="Adapter Blocked Pipeline Result",
        category=ScenarioCategory.ADAPTER_BLOCKED_PIPELINE_RESULT,
        intent=_base_intent("scenario.adapter_blocked_pipeline_result"),
        policy=None,
        world_snapshot=snapshot,
        evaluation_time_ms=None,
        trust_policy_config=None,
        verifier=None,
        expected=_expect(
            outcome=PipelineOutcome.BLOCKED,
            reason="POLICY_ADMISSION_DISABLED",
            terminal_stage="policy_admission",
            required=_DISABLED_PATH,
            forbidden=("gate_decision",),
            receipt_valid=True,
        ),
        metadata={"category": ScenarioCategory.ADAPTER_BLOCKED_PIPELINE_RESULT.value},
        capability=None,
    )


def _attestation_failure_reason(
    *,
    attestation: WorldSnapshotAttestation,
    evidence_envelope: WorldSnapshotEvidenceEnvelope,
    world_snapshot_checksum: str,
) -> str | None:
    if evidence_envelope.world_snapshot_checksum != world_snapshot_checksum:
        return "FIXTURE_SNAPSHOT_MISMATCH"
    if attestation.subject_snapshot_checksum != world_snapshot_checksum:
        return "FIXTURE_SNAPSHOT_MISMATCH"
    if evidence_envelope.metadata and (
        evidence_envelope.metadata.get("trusted") is True
        or evidence_envelope.metadata.get("verifier_status") == "CERTIFIED"
    ):
        return "FIXTURE_METADATA_INERT"
    if attestation.subject_envelope_id != evidence_envelope.envelope_id:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.source_id != evidence_envelope.source_id:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.trust_domain is not evidence_envelope.trust_domain:
        return "FIXTURE_ENVELOPE_MISMATCH"
    if attestation.algorithm != SCENARIO_ALGORITHM:
        return "FIXTURE_ALGORITHM_UNSUPPORTED"
    if attestation.key_id != SCENARIO_KEY_ID:
        return "FIXTURE_KEY_UNSUPPORTED"
    if attestation.signature != "fixture-signature":
        return "FIXTURE_SIGNATURE_INVALID"
    expected_payload_checksum = world_snapshot_attestation_payload_checksum(
        subject_snapshot_checksum=attestation.subject_snapshot_checksum,
        subject_envelope_id=attestation.subject_envelope_id,
        source_id=attestation.source_id,
        trust_domain=attestation.trust_domain,
        issued_at_ms=attestation.issued_at_ms,
        valid_from_ms=attestation.valid_from_ms,
        valid_until_ms=attestation.valid_until_ms,
        algorithm=attestation.algorithm,
        key_id=attestation.key_id,
    )
    if attestation.signed_payload_checksum != expected_payload_checksum:
        return "FIXTURE_SIGNATURE_INVALID"
    return None


__all__ = [
    "PassingScenarioAttestationVerifier",
    "SCENARIO_CAPABILITY",
    "SCENARIO_EVALUATION_TIME_MS",
    "ScenarioFixtureFactory",
    "canonical_scenario_definitions",
    "make_scenario_context",
]
