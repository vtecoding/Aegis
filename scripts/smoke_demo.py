"""ADR-0009 proof demo: positive approval path + evil-twin trust-boundary failures.

Scenario A (ALLOWED):
    valid move  + ENFORCE + allowed capability + FRESH snapshot + TRUSTED evidence
    + policy ALLOW + valid SafetyCase + admission integrity PASS  =>  ALLOWED

Scenario B (BLOCKED — missing evidence):
    same valid move + ENFORCE + FRESH snapshot + NO evidence envelope
    => BLOCKED before policy evaluation

Scenario C (BLOCKED — forged attestation):
    same valid move + ENFORCE + FRESH snapshot + FAILING attestation verifier
    => BLOCKED before policy evaluation
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

# Make src/ and tests/ importable when run directly as a script.
_repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_repo_root / "src"))
sys.path.insert(0, str(_repo_root))  # exposes tests/ as namespace package

from tests.policy_freshness_fixtures import (  # noqa: E402
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import (  # noqa: E402
    FailingAttestationVerifier,
    PassingAttestationVerifier,
    trusted_evidence_envelope,
    trusted_world_snapshot_policy,
)

from aegis.contracts.aegis_context import ExecutionContext  # noqa: E402
from aegis.contracts.aegis_intent import RawIntent  # noqa: E402
from aegis.contracts.aegis_pipeline import PipelineOutcome, PipelineResult  # noqa: E402
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule  # noqa: E402
from aegis.contracts.aegis_policy import WorldSnapshotStub  # noqa: E402
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode  # noqa: E402
from aegis.pipeline import run_pipeline  # noqa: E402

# ---------------------------------------------------------------------------
# Shared deterministic constants
# ---------------------------------------------------------------------------
CAPABILITY_NAME = "locomotion.translation"

# The valid move JSON — identical across all three scenarios
_MOVE_JSON: dict[str, object] = {
    "command": "move",
    "parameters": {"target": {"x": 0.45, "y": 0.10}},
    "source_id": "operator-console",
    "priority": 5,
}


def _context(request_id: str) -> ExecutionContext:
    return ExecutionContext(
        request_id=request_id,
        submitted_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        policy_version="v1",
    )


def _intent(ctx: ExecutionContext) -> RawIntent:
    params = _MOVE_JSON["parameters"]
    assert isinstance(params, dict)
    return RawIntent(
        command=str(_MOVE_JSON["command"]),
        parameters=params,
        source_id=str(_MOVE_JSON["source_id"]),
        priority=int(_MOVE_JSON["priority"]),  # type: ignore[arg-type]
        context=ctx,
    )


def _allow_policy() -> Policy:
    """Policy that permits locomotion.translation up to 1 m/s — evaluates ALLOW."""
    return Policy(
        "smoke-demo-policy",
        "v1",
        [
            PolicyRule(
                "rule-allow-slow-translation",
                CAPABILITY_NAME,
                [Constraint("max_velocity", {"max_mps": 1.0})],
            )
        ],
    )


def _admission(snapshot: WorldSnapshotStub) -> PolicyAdmissionInput:
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=_allow_policy(),
        capability=Capability(CAPABILITY_NAME, parameters={"velocity_mps": 0.25}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
_SEP = "=" * 70


def _banner(label: str, title: str) -> None:
    print()
    print(_SEP)
    print(f"SCENARIO {label}: {title}")
    print(_SEP)


def _print_result(result: PipelineResult) -> None:
    pa = result.policy_admission
    print(f"  outcome                  : {result.outcome}")
    vr = result.validation_result
    print(f"  validation.is_valid      : {vr.is_valid if vr else 'N/A'}")
    if result.plan:
        steps = result.plan.steps
        print(f"  plan steps               : {len(steps)}")
        for i, s in enumerate(steps, 1):
            print(f"    step {i}: {s.step_type}  params={dict(s.parameters)}")
    else:
        print("  plan                     : None")
    if result.audited_plan:
        print(f"  audit_id                 : {result.audited_plan.audit_id}")
        print(f"  checksum                 : {result.audited_plan.checksum}")
    else:
        print("  audited_plan             : None")
    print(f"  gate_decision            : {result.gate_decision}")
    print(f"  admission.mode           : {pa.mode}")
    print(f"  admission.decision       : {pa.admission_decision}")
    print(f"  admission.allowed        : {pa.admission_allowed}")
    print(f"  freshness_status         : {pa.freshness_status}")
    print(f"  trust_status             : {pa.world_snapshot_trust_status}")
    print(f"  trust_reason_code        : {pa.world_snapshot_trust_reason_code}")
    if pa.policy_result is not None:
        print(f"  policy_result.decision   : {pa.policy_result.decision}")
    else:
        print("  policy_result            : None  (not reached)")
    if pa.safety_case is not None:
        print(f"  safety_case.policy_result.decision : {pa.safety_case.policy_result.decision}")
        print(
            f"  safety_case.trust_status           : {pa.safety_case.world_snapshot_trust_status}"
        )
    else:
        print("  safety_case              : None  (not reached)")
    print(f"  integrity_status         : {pa.integrity_status}")
    print(f"  reasons                  : {pa.reasons}")


def _verdict(result: PipelineResult, expected: PipelineOutcome, proof: str) -> bool:
    print()
    ok = result.outcome == expected
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}]  expected={expected}  actual={result.outcome}")
    if ok:
        print(f"  Proves: {proof}")
    else:
        print(f"  ERROR: outcome mismatch — expected {expected}, got {result.outcome}")
    return ok


# ===========================================================================
# Scenario A — Full positive approval path
# ===========================================================================
_banner(
    "A",
    "valid move + ENFORCE + FRESH + TRUSTED evidence + ALLOW policy  =>  ALLOWED",
)

snapshot_a = fresh_world_snapshot()
ctx_a = _context("adr-0009-demo-a")

result_a = run_pipeline(
    _intent(ctx_a),
    ctx_a,
    policy_admission=_admission(snapshot_a),
    evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    world_snapshot_evidence=trusted_evidence_envelope(snapshot_a),
    world_snapshot_trust_policy=trusted_world_snapshot_policy(capability=CAPABILITY_NAME),
    attestation_verifier=PassingAttestationVerifier(),
)

_print_result(result_a)
ok_a = _verdict(
    result_a,
    PipelineOutcome.ALLOWED,
    "Validated -> planned -> audited -> freshness FRESH -> trust TRUSTED -> "
    "policy ALLOW -> SafetyCase built -> integrity PASSED -> gate ALLOWED.",
)

# ===========================================================================
# Scenario B — Evil twin: missing evidence envelope
# ===========================================================================
_banner(
    "B",
    "evil twin — ENFORCE + FRESH + NO evidence envelope  =>  BLOCKED before policy eval",
)

snapshot_b = fresh_world_snapshot()
ctx_b = _context("adr-0009-demo-b")

result_b = run_pipeline(
    _intent(ctx_b),
    ctx_b,
    policy_admission=_admission(snapshot_b),
    evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    world_snapshot_evidence=None,  # <-- missing
    world_snapshot_trust_policy=trusted_world_snapshot_policy(capability=CAPABILITY_NAME),
    attestation_verifier=PassingAttestationVerifier(),
)

_print_result(result_b)
policy_not_run_b = result_b.policy_admission.policy_result is None
print(f"\n  policy layer not invoked : {policy_not_run_b}")
ok_b = _verdict(
    result_b,
    PipelineOutcome.BLOCKED,
    "Trust boundary blocked: missing evidence envelope. Policy evaluation layer was never invoked.",
)

# ===========================================================================
# Scenario C — Evil twin: forged / rejected attestation
# ===========================================================================
_banner(
    "C",
    "evil twin — ENFORCE + FRESH + envelope present + FAILING verifier  =>  BLOCKED",
)

snapshot_c = fresh_world_snapshot()
ctx_c = _context("adr-0009-demo-c")

result_c = run_pipeline(
    _intent(ctx_c),
    ctx_c,
    policy_admission=_admission(snapshot_c),
    evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
    world_snapshot_evidence=trusted_evidence_envelope(snapshot_c),  # envelope present
    world_snapshot_trust_policy=trusted_world_snapshot_policy(capability=CAPABILITY_NAME),
    attestation_verifier=FailingAttestationVerifier(),  # <-- rejects sig
)

_print_result(result_c)
policy_not_run_c = result_c.policy_admission.policy_result is None
print(f"\n  policy layer not invoked : {policy_not_run_c}")
ok_c = _verdict(
    result_c,
    PipelineOutcome.BLOCKED,
    "Trust boundary blocked: attestation verifier rejected the signature. "
    "Policy evaluation layer was never invoked.",
)

# ===========================================================================
# Summary
# ===========================================================================
print()
print(_SEP)
print("SUMMARY")
print(_SEP)

rows = [
    ("A", result_a, PipelineOutcome.ALLOWED, ok_a),
    ("B", result_b, PipelineOutcome.BLOCKED, ok_b),
    ("C", result_c, PipelineOutcome.BLOCKED, ok_c),
]

all_pass = all(ok for _, _, _, ok in rows)

for label, res, expected, ok in rows:
    pa = res.policy_admission
    trust = pa.world_snapshot_trust_status or "N/A"
    policy = str(pa.policy_result.decision) if pa.policy_result else "NOT_RUN"
    tag = "PASS" if ok else "FAIL"
    print(
        f"  [{tag}]  Scenario {label}  outcome={res.outcome:<8}  "
        f"trust={trust:<25}  policy_eval={policy}"
    )

print()
if all_pass:
    print("  All three scenarios passed. ADR-0009 trust boundary proved.")
    print("  Positive approval path: ALLOWED.")
    print("  Evil twin (missing evidence): BLOCKED before policy evaluation.")
    print("  Evil twin (forged attestation): BLOCKED before policy evaluation.")
else:
    print("  One or more scenarios FAILED.")
    sys.exit(1)
