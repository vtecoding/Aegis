"""Explicit ADR-0016 evil-twin mutations for adapter replay proofs."""

from __future__ import annotations

from aegis.contracts.aegis_adapter_replay import AdapterReplayMutationProfile, AdapterReplayRequest
from aegis.contracts.aegis_ros2_mapping import Ros2History

FORGED_CHECKSUM = "0" * 64
ALTERNATE_CHECKSUM = "1" * 64


def mutate_adapter_replay_request_in_place(
    request: AdapterReplayRequest,
    mutation_profile: AdapterReplayMutationProfile,
) -> AdapterReplayRequest:
    """Apply one explicit evil-twin mutation to a fresh replay request."""
    object.__setattr__(request, "mutation_profile", mutation_profile)
    match mutation_profile:
        case AdapterReplayMutationProfile.NONE:
            return request
        case AdapterReplayMutationProfile.PIPELINE_RECEIPT_CHECKSUM_DRIFT:
            if request.pipeline_result.approval_receipt is not None:
                object.__setattr__(
                    request.pipeline_result.approval_receipt,
                    "approval_receipt_checksum",
                    FORGED_CHECKSUM,
                )
        case AdapterReplayMutationProfile.POLICY_RESULT_CHECKSUM_DRIFT:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "policy_result_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.SAFETY_CASE_CHECKSUM_DRIFT:
            if request.pipeline_result.policy_admission.safety_case is not None:
                object.__setattr__(
                    request.pipeline_result.policy_admission.safety_case,
                    "plan_checksum",
                    FORGED_CHECKSUM,
                )
        case AdapterReplayMutationProfile.CONTEXT_AUTHORITY_MISMATCH:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "context_authority_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.POLICY_IDENTITY_MISMATCH:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "policy_id",
                "forged-policy-id",
            )
        case AdapterReplayMutationProfile.WORLD_SNAPSHOT_ADMISSIBILITY_MISMATCH:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "world_snapshot_admissibility_result_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.WORLD_SNAPSHOT_FRESHNESS_MISMATCH:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "freshness_result_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.WORLD_SNAPSHOT_TRUST_MISMATCH:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "world_snapshot_trust_result_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.COMMAND_PLAN_MUTATION:
            if request.pipeline_result.audited_plan is not None:
                object.__setattr__(
                    request.pipeline_result.audited_plan,
                    "checksum",
                    FORGED_CHECKSUM,
                )
        case AdapterReplayMutationProfile.CAPABILITY_MUTATION:
            object.__setattr__(
                request.pipeline_result.policy_admission,
                "capability_name",
                "manipulation.grip",
            )
        case AdapterReplayMutationProfile.ROS_MESSAGE_TYPE_MUTATION:
            mapping = request.expected_envelope.adapter_mapping
            if mapping is not None:
                object.__setattr__(mapping.ros2_mapping, "message_type", "msg/TamperedCommand")
        case AdapterReplayMutationProfile.FIELD_MAP_MUTATION:
            mapping = request.expected_envelope.adapter_mapping
            if mapping is not None:
                object.__setattr__(
                    mapping.ros2_mapping,
                    "field_map",
                    {"parameters.target.x": "target.changed", "parameters.target.y": "target.y"},
                )
        case AdapterReplayMutationProfile.QOS_MUTATION:
            mapping = request.expected_envelope.adapter_mapping
            if mapping is not None:
                object.__setattr__(mapping.ros2_mapping.qos, "history", Ros2History.KEEP_ALL)
        case AdapterReplayMutationProfile.NAMESPACE_MUTATION:
            mapping = request.expected_envelope.adapter_mapping
            if mapping is not None:
                object.__setattr__(mapping.ros2_mapping, "namespace", "other_arm")
        case AdapterReplayMutationProfile.RUNTIME_TARGET_MUTATION:
            target_runtime = request.expected_envelope.target_runtime
            if target_runtime is not None:
                object.__setattr__(target_runtime, "target_robot_id", "forged-robot")
        case AdapterReplayMutationProfile.ADAPTER_RECEIPT_REPLAY_TARGET_MUTATION:
            object.__setattr__(
                request.expected_adapter_receipt,
                "runtime_target_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.ADAPTER_RECEIPT_CHECKSUM_MUTATION:
            object.__setattr__(
                request.expected_adapter_receipt,
                "adapter_receipt_checksum",
                FORGED_CHECKSUM,
            )
        case AdapterReplayMutationProfile.READY_ENVELOPE_STALE_RECEIPT:
            object.__setattr__(request.expected_envelope, "envelope_checksum", ALTERNATE_CHECKSUM)
        case AdapterReplayMutationProfile.RESOURCE_BOUNDS_MUTATION:
            object.__setattr__(
                request.expected_envelope,
                "payload_field_count",
                request.expected_envelope.payload_field_count + 1,
            )
    return request


__all__ = ["mutate_adapter_replay_request_in_place"]
