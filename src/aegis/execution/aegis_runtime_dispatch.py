"""Build inert runtime dispatch dry-run plans from replay-verified envelopes."""

from __future__ import annotations

from aegis.contracts.aegis_adapter_replay import AdapterReplayProofResult
from aegis.contracts.aegis_execution_adapter import ExecutionAdapterEnvelope
from aegis.contracts.aegis_runtime_dispatch import (
    RUNTIME_DISPATCH_RESOURCE_BOUNDS,
    RuntimeDispatchMode,
    RuntimeDispatchPlan,
    make_runtime_dispatch_item,
    make_runtime_dispatch_plan_authorization,
    runtime_dispatch_plan_id,
)


def build_runtime_dispatch_plan(
    envelope: ExecutionAdapterEnvelope,
    replay_proof: AdapterReplayProofResult,
) -> RuntimeDispatchPlan:
    """Build a deterministic dry-run-only dispatch plan from replay proof.

    Args:
        envelope: Replay-verified ADR-0015 adapter envelope evidence.
        replay_proof: ADR-0016 proof that must be PASSED for the same envelope.

    Returns:
        An inert RuntimeDispatchPlan containing no runtime backend handles.
    """
    plan_id = runtime_dispatch_plan_id(
        source_envelope_checksum=envelope.envelope_checksum,
        source_replay_proof_checksum=replay_proof.proof_checksum,
    )
    return RuntimeDispatchPlan(
        plan_id=plan_id,
        source_envelope_checksum=envelope.envelope_checksum,
        source_replay_proof_checksum=replay_proof.proof_checksum,
        runtime_target_checksum=envelope.runtime_target_checksum,
        mapping_checksum=envelope.adapter_mapping_checksum,
        dispatch_mode=RuntimeDispatchMode.DRY_RUN_ONLY,
        dispatch_items=(make_runtime_dispatch_item(envelope),),
        resource_bounds=RUNTIME_DISPATCH_RESOURCE_BOUNDS,
        authorization=make_runtime_dispatch_plan_authorization(
            envelope=envelope,
            replay_proof=replay_proof,
        ),
    )


__all__ = ["build_runtime_dispatch_plan"]
