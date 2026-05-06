"""Contract tests for Policy-v1 immutable contracts."""

from dataclasses import FrozenInstanceError

import pytest

from aegis.contracts.policy import (
    Capability,
    Constraint,
    Policy,
    PolicyDecision,
    PolicyDefaultDecision,
    PolicyEvaluationResult,
    PolicyRule,
    SafetyCase,
    WorldSnapshotStub,
)


def make_constraint() -> Constraint:
    """Return a valid Policy-v1 constraint."""
    return Constraint("max_velocity", {"meters_per_second": 0.5})


def make_rule(rule_id: str = "rule-1") -> PolicyRule:
    """Return a valid Policy-v1 rule."""
    return PolicyRule(rule_id, "locomotion.translation", [make_constraint()])


def make_block_result() -> PolicyEvaluationResult:
    """Return a valid blocking policy result."""
    return PolicyEvaluationResult(
        PolicyDecision.BLOCK,
        "policy-1",
        [],
        [],
        ["max_velocity"],
        ["velocity exceeds configured policy"],
    )


def make_allow_result() -> PolicyEvaluationResult:
    """Return a valid allow policy result."""
    return PolicyEvaluationResult(
        PolicyDecision.ALLOW,
        "policy-1",
        ["rule-1"],
        ["max_velocity"],
        [],
        [],
    )


def test_policy_accepts_valid_rules() -> None:
    """Policy accepts a deterministic immutable rule bundle."""
    policy = Policy("policy-1", "v1", [make_rule()])

    assert policy.policy_id == "policy-1"
    assert policy.version == "v1"
    assert policy.rules == (make_rule(),)
    assert policy.default_decision is PolicyDefaultDecision.BLOCK


@pytest.mark.parametrize("policy_id", ["", "   ", "\t\n"])
def test_policy_rejects_empty_id(policy_id: str) -> None:
    """Policy identifiers must be non-empty after stripping."""
    with pytest.raises(ValueError, match="policy_id"):
        Policy(policy_id, "v1", [make_rule()])


@pytest.mark.parametrize("version", ["", "   ", "\t\n"])
def test_policy_rejects_empty_version(version: str) -> None:
    """Policy versions must be non-empty after stripping."""
    with pytest.raises(ValueError, match="version"):
        Policy("policy-1", version, [make_rule()])


def test_policy_rejects_duplicate_rule_ids() -> None:
    """Policy bundles must not contain duplicate rule IDs."""
    with pytest.raises(ValueError, match="duplicate rule_id"):
        Policy("policy-1", "v1", [make_rule("rule-1"), make_rule("rule-1")])


def test_policy_rejects_default_allow() -> None:
    """Policy-v1 must fail closed when no rule matches."""
    with pytest.raises(ValueError, match="must not be ALLOW"):
        Policy("policy-1", "v1", [make_rule()], default_decision="ALLOW")


def test_policy_rejects_invalid_default_decision() -> None:
    """Policy-v1 rejects defaults outside the fail-closed default decision set."""
    with pytest.raises(ValueError, match="default_decision"):
        Policy("policy-1", "v1", [make_rule()], default_decision="DENY")


def test_policy_accepts_require_review_default() -> None:
    """Policy-v1 supports REQUIRE_REVIEW as a fail-closed default."""
    policy = Policy("policy-1", "v1", [make_rule()], PolicyDefaultDecision.REQUIRE_REVIEW)

    assert policy.default_decision is PolicyDefaultDecision.REQUIRE_REVIEW


@pytest.mark.parametrize("rule_id", ["", "   ", "\t\n"])
def test_policy_rule_rejects_empty_rule_id(rule_id: str) -> None:
    """Rules must carry stable non-empty identifiers."""
    with pytest.raises(ValueError, match="rule_id"):
        PolicyRule(rule_id, "locomotion.translation", [make_constraint()])


@pytest.mark.parametrize("capability", ["", "   ", "Locomotion.Translation", "move now"])
def test_policy_rule_rejects_empty_or_invalid_capability(capability: str) -> None:
    """Rules must reference canonical non-empty capability names."""
    with pytest.raises(ValueError, match="capability"):
        PolicyRule("rule-1", capability, [make_constraint()])


def test_policy_rule_rejects_enabled_rule_with_zero_constraints() -> None:
    """Enabled metadata-only rules are rejected to avoid false safety confidence."""
    with pytest.raises(ValueError, match="enabled rules"):
        PolicyRule("rule-1", "locomotion.translation", [])


def test_policy_rule_rejects_non_bool_enabled() -> None:
    """Rule enabled flags must be explicit bool values."""
    with pytest.raises(ValueError, match="enabled"):
        PolicyRule("rule-1", "locomotion.translation", [make_constraint()], enabled="yes")


def test_policy_rule_allows_disabled_rule_with_zero_constraints() -> None:
    """Disabled rules are preserved for future evaluator compatibility."""
    rule = PolicyRule("rule-1", "locomotion.translation", [], enabled=False)

    assert rule.constraints == ()
    assert rule.enabled is False


@pytest.mark.parametrize("constraint_type", ["", "   ", "\t\n"])
def test_constraint_rejects_empty_type(constraint_type: str) -> None:
    """Constraints must identify the future deterministic condition."""
    with pytest.raises(ValueError, match="constraint_type"):
        Constraint(constraint_type)


def test_constraint_rejects_non_bool_required() -> None:
    """Constraint required flags must be explicit bool values."""
    with pytest.raises(ValueError, match="required"):
        Constraint("max_velocity", required="yes")


@pytest.mark.parametrize("name", ["", "   ", "Locomotion.Translation", "move now"])
def test_capability_rejects_empty_or_invalid_name(name: str) -> None:
    """Capabilities must use canonical descriptive names."""
    with pytest.raises(ValueError, match="capability"):
        Capability(name)


def test_capability_accepts_parameters_without_execution_handlers() -> None:
    """Capability metadata is descriptive and stored inertly."""
    capability = Capability(
        "inspection.observe",
        parameters={"sensor": "camera", "bounds": {"max_distance_m": 2}},
    )

    assert capability.name == "inspection.observe"
    assert capability.parameters["sensor"] == "camera"


def test_capability_rejects_non_string_parameter_keys() -> None:
    """Policy metadata keys must be strings."""
    with pytest.raises(ValueError, match="keys must be strings"):
        Capability("inspection.observe", parameters={1: "unsafe"})


def test_capability_rejects_non_finite_numeric_parameter_values() -> None:
    """Policy numeric metadata must be deterministic finite values."""
    with pytest.raises(ValueError, match="finite"):
        Capability("inspection.observe", parameters={"confidence": float("nan")})


def test_capability_freezes_tuple_parameter_values() -> None:
    """Tuple metadata is recursively preserved as immutable tuple data."""
    capability = Capability("inspection.observe", parameters={"path": ("a", {"step": [1]})})

    assert capability.parameters["path"] == ("a", {"step": (1,)})


def test_world_snapshot_rejects_negative_capture_time() -> None:
    """World snapshot capture time must be explicit and non-negative."""
    with pytest.raises(ValueError, match="captured_at_ms"):
        WorldSnapshotStub("snapshot-1", -1, 1, "fixture", 1.0)


def test_world_snapshot_rejects_bool_capture_time() -> None:
    """World snapshot timestamps reject bool even though bool is numeric in Python."""
    with pytest.raises(ValueError, match="captured_at_ms"):
        WorldSnapshotStub("snapshot-1", True, 1, "fixture", 1.0)


def test_world_snapshot_rejects_expiry_before_capture() -> None:
    """World snapshot expiry must not precede capture."""
    with pytest.raises(ValueError, match="expires_at_ms"):
        WorldSnapshotStub("snapshot-1", 10, 9, "fixture", 1.0)


@pytest.mark.parametrize("confidence", [-0.1, -1.0])
def test_world_snapshot_rejects_confidence_below_zero(confidence: float) -> None:
    """World snapshot confidence must be within [0.0, 1.0]."""
    with pytest.raises(ValueError, match="confidence"):
        WorldSnapshotStub("snapshot-1", 0, 1, "fixture", confidence)


@pytest.mark.parametrize("confidence", [1.1, 2.0])
def test_world_snapshot_rejects_confidence_above_one(confidence: float) -> None:
    """World snapshot confidence must be within [0.0, 1.0]."""
    with pytest.raises(ValueError, match="confidence"):
        WorldSnapshotStub("snapshot-1", 0, 1, "fixture", confidence)


def test_world_snapshot_rejects_bool_confidence() -> None:
    """World snapshot confidence rejects bool even though bool is numeric in Python."""
    with pytest.raises(ValueError, match="confidence"):
        WorldSnapshotStub("snapshot-1", 0, 1, "fixture", True)


def test_world_snapshot_rejects_empty_checksum_when_provided() -> None:
    """Optional checksums must be non-empty when supplied."""
    with pytest.raises(ValueError, match="checksum"):
        WorldSnapshotStub("snapshot-1", 0, 1, "fixture", 1.0, checksum=" ")


def test_world_snapshot_accepts_explicit_evidence_input() -> None:
    """WorldSnapshotStub stores injected evidence without reading live state."""
    snapshot = WorldSnapshotStub(
        "snapshot-1",
        100,
        200,
        "unit-test",
        0.9,
        facts={"human_present": False},
        checksum="abc123",
    )

    assert snapshot.captured_at_ms == 100
    assert snapshot.expires_at_ms == 200
    assert snapshot.facts["human_present"] is False
    assert snapshot.checksum == "abc123"


def test_policy_evaluation_result_rejects_unknown_decision() -> None:
    """Policy decisions are closed over the PolicyDecision enum."""
    with pytest.raises(ValueError, match="PolicyDecision"):
        PolicyEvaluationResult("PARTIAL_ALLOW", "policy-1", [], [], [], ["reason"])


def test_policy_evaluation_result_rejects_allow_with_no_matched_rule() -> None:
    """ALLOW cannot appear without an explicit matched rule."""
    with pytest.raises(ValueError, match="ALLOW"):
        PolicyEvaluationResult(PolicyDecision.ALLOW, "policy-1", [], [], [], [])


def test_policy_evaluation_result_rejects_block_with_no_reason() -> None:
    """Failure decisions must carry explanation evidence."""
    with pytest.raises(ValueError, match="failure decisions"):
        PolicyEvaluationResult(PolicyDecision.BLOCK, "policy-1", [], [], ["max_velocity"], [])


def test_policy_evaluation_result_rejects_string_for_tuple_fields() -> None:
    """Tuple fields must receive iterables of strings, not a bare string."""
    with pytest.raises(ValueError, match="matched_rule_ids"):
        PolicyEvaluationResult("ALLOW", "policy-1", "rule-1", ["max_velocity"], [], [])


def test_safety_case_rejects_empty_id() -> None:
    """Safety cases must carry stable non-empty identifiers."""
    with pytest.raises(ValueError, match="safety_case_id"):
        SafetyCase("", make_block_result(), "audit-1", None)


def test_safety_case_rejects_empty_audited_plan_id() -> None:
    """Safety cases must be bound to an audited plan identifier."""
    with pytest.raises(ValueError, match="audited_plan_id"):
        SafetyCase("case-1", make_block_result(), "", None)


def test_safety_case_rejects_empty_world_snapshot_id_when_provided() -> None:
    """Optional world snapshot IDs must be non-empty when supplied."""
    with pytest.raises(ValueError, match="world_snapshot_id"):
        SafetyCase("case-1", make_block_result(), "audit-1", " ")


def test_safety_case_rejects_allow_without_evidence() -> None:
    """ALLOW explanations must include evidence in Policy-v1."""
    with pytest.raises(ValueError, match="ALLOW safety cases"):
        SafetyCase("case-1", make_allow_result(), "audit-1", "snapshot-1")


def test_safety_case_accepts_allow_with_evidence() -> None:
    """SafetyCase stores explanation evidence without granting permission itself."""
    safety_case = SafetyCase(
        "case-1",
        make_allow_result(),
        "audit-1",
        "snapshot-1",
        {"snapshot_confidence": 0.9},
    )

    assert safety_case.evidence["snapshot_confidence"] == 0.9


def test_policy_result_is_immutable() -> None:
    """PolicyEvaluationResult fields cannot be reassigned."""
    result = make_block_result()

    with pytest.raises(FrozenInstanceError):
        result.policy_id = "changed"
