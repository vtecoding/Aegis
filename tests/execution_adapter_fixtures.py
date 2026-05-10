"""Shared deterministic fixtures for ADR-0015 execution adapter tests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from tests.policy_freshness_fixtures import (
    FRESH_EVALUATION_TIME_MS,
    fresh_policy_context,
    fresh_world_snapshot,
)
from tests.policy_trust_fixtures import trusted_pipeline_kwargs

from aegis.contracts.aegis_adapter_receipt import build_adapter_receipt
from aegis.contracts.aegis_adapter_replay import AdapterReplayRequest
from aegis.contracts.aegis_context import ExecutionContext
from aegis.contracts.aegis_execution_adapter import ExecutionAdapterMapping
from aegis.contracts.aegis_intent import RawIntent
from aegis.contracts.aegis_pipeline import PipelineResult
from aegis.contracts.aegis_policy import Capability, Constraint, Policy, PolicyRule
from aegis.contracts.aegis_policy_admission import PolicyAdmissionInput, PolicyAdmissionMode
from aegis.contracts.aegis_ros2_mapping import (
    DANGEROUS_RUNTIME_OVERRIDE_FIELDS,
    Ros2CommunicationPrimitive,
    Ros2Durability,
    Ros2History,
    Ros2Liveliness,
    Ros2MessageMapping,
    Ros2QoSProfileSpec,
    Ros2Reliability,
    RuntimeKind,
    RuntimeTarget,
)
from aegis.execution import build_execution_adapter_envelope
from aegis.pipeline import run_pipeline

ADAPTER_CAPABILITY = "locomotion.translation"
ADAPTER_NAMESPACE = "robot_arm"
ADAPTER_AUTHORITY = "aegis.adapter.registry"
ADAPTER_FORBIDDEN_FIELDS = tuple(sorted(DANGEROUS_RUNTIME_OVERRIDE_FIELDS))


def adapter_context(request_id: str = "adapter-boundary") -> ExecutionContext:
    """Return a deterministic execution context for adapter tests."""
    return ExecutionContext(request_id, datetime(2026, 5, 9, tzinfo=UTC), "policy-v1")


def adapter_intent(context: ExecutionContext, *, command: str = "move") -> RawIntent:
    """Return a deterministic raw intent for adapter tests."""
    parameters = {} if command == "stop" else {"target": {"x": 1, "y": 2}}
    return RawIntent(command, parameters, "operator", 5, context)


def adapter_policy() -> Policy:
    """Return a deterministic allow policy for adapter tests."""
    return Policy(
        "adapter-policy",
        "v1",
        [
            PolicyRule(
                "rule-1",
                ADAPTER_CAPABILITY,
                [Constraint("max_velocity", {"max_mps": 1.0})],
            )
        ],
    )


def adapter_admission() -> PolicyAdmissionInput:
    """Return enforced policy admission input for adapter tests."""
    snapshot = fresh_world_snapshot()
    return PolicyAdmissionInput(
        PolicyAdmissionMode.ENFORCE,
        policy=adapter_policy(),
        capability=Capability(ADAPTER_CAPABILITY, parameters={"velocity_mps": 0.2}),
        world_snapshot=snapshot,
        context=fresh_policy_context(),
    )


def allowed_pipeline_result(
    *,
    command: str = "move",
    request_id: str = "adapter-allowed",
) -> PipelineResult:
    """Return a full allowed, receipt-valid PipelineResult."""
    context = adapter_context(request_id)
    admission = adapter_admission()
    assert admission.world_snapshot is not None
    return run_pipeline(
        adapter_intent(context, command=command),
        context,
        policy_admission=admission,
        evaluation_time_ms=FRESH_EVALUATION_TIME_MS,
        **trusted_pipeline_kwargs(admission.world_snapshot),
    )


def blocked_pipeline_result() -> PipelineResult:
    """Return a structurally valid blocked PipelineResult."""
    context = adapter_context("adapter-blocked")
    return run_pipeline(
        adapter_intent(context),
        context,
        policy_admission=PolicyAdmissionInput(PolicyAdmissionMode.DISABLED),
    )


def runtime_target(*, namespace: str = ADAPTER_NAMESPACE) -> RuntimeTarget:
    """Return a deterministic ROS 2 runtime target contract."""
    return RuntimeTarget(
        runtime_kind=RuntimeKind.ROS2,
        runtime_id="ros2-sim-runtime",
        runtime_version="kilted",
        deployment_domain="SIMULATION",
        target_namespace=namespace,
        target_robot_id="robot-arm-1",
        runtime_authority="runtime.registry.local",
    )


def qos_profile(*, depth: object = 10) -> Ros2QoSProfileSpec:
    """Return a bounded explicit ROS 2 QoS profile contract."""
    return Ros2QoSProfileSpec(
        reliability=Ros2Reliability.RELIABLE,
        durability=Ros2Durability.VOLATILE,
        history=Ros2History.KEEP_LAST,
        depth=depth,
        deadline_ms=100,
        lifespan_ms=1_000,
        liveliness=Ros2Liveliness.AUTOMATIC,
        lease_duration_ms=1_000,
    )


def ros2_move_mapping(
    *,
    namespace: str = ADAPTER_NAMESPACE,
    source_command: str = "move",
    source_capability: str = ADAPTER_CAPABILITY,
    field_map: Mapping[str, str] | None = None,
    required_fields: Iterable[str] = ("parameters.target.x", "parameters.target.y"),
    forbidden_fields: Iterable[str] = ADAPTER_FORBIDDEN_FIELDS,
) -> Ros2MessageMapping:
    """Return a deterministic ROS 2 mapping for the abstract move command."""
    return Ros2MessageMapping(
        mapping_id="ros2-move-mapping",
        mapping_version="v1",
        source_command=source_command,
        source_capability=source_capability,
        primitive=Ros2CommunicationPrimitive.TOPIC,
        package_name="aegis_msgs",
        message_type="msg/MoveCommand",
        topic_or_service_name="command/move",
        namespace=namespace,
        frame_id="map",
        qos=qos_profile(),
        field_map=(
            field_map
            if field_map is not None
            else {"parameters.target.x": "target.x", "parameters.target.y": "target.y"}
        ),
        required_fields=required_fields,
        forbidden_fields=forbidden_fields,
        mapping_authority=ADAPTER_AUTHORITY,
    )


def ros2_stop_mapping(*, namespace: str = ADAPTER_NAMESPACE) -> Ros2MessageMapping:
    """Return a deterministic ROS 2 mapping for the abstract stop command."""
    return Ros2MessageMapping(
        mapping_id="ros2-stop-mapping",
        mapping_version="v1",
        source_command="stop",
        source_capability=ADAPTER_CAPABILITY,
        primitive=Ros2CommunicationPrimitive.TOPIC,
        package_name="aegis_msgs",
        message_type="msg/StopCommand",
        topic_or_service_name="command/stop",
        namespace=namespace,
        frame_id=None,
        qos=qos_profile(),
        field_map={"step_type": "command"},
        required_fields=("step_type",),
        forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
        mapping_authority=ADAPTER_AUTHORITY,
    )


def adapter_mapping(
    *,
    target: RuntimeTarget | None = None,
    ros2_mapping: Ros2MessageMapping | None = None,
    effective_from_ms: object = 0,
    accepted_policy_schema_version: str = "policy-v1",
) -> ExecutionAdapterMapping:
    """Return a deterministic execution adapter mapping contract."""
    resolved_target = target or runtime_target()
    return ExecutionAdapterMapping(
        adapter_mapping_id="adapter-mapping-ros2-move",
        adapter_mapping_version="v1",
        runtime_target=resolved_target,
        ros2_mapping=ros2_mapping or ros2_move_mapping(namespace=resolved_target.target_namespace),
        accepted_policy_schema_version=accepted_policy_schema_version,
        adapter_authority=ADAPTER_AUTHORITY,
        effective_from_ms=effective_from_ms,
    )


def adapter_replay_request(
    *,
    command: str = "move",
    request_id: str = "adapter-replay",
) -> AdapterReplayRequest:
    """Return a deterministic positive adapter replay request."""
    mapping = adapter_mapping(
        ros2_mapping=ros2_stop_mapping() if command == "stop" else None,
    )
    result = allowed_pipeline_result(command=command, request_id=request_id)
    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)
    return AdapterReplayRequest(
        pipeline_result=result,
        expected_envelope=envelope,
        expected_adapter_receipt=build_adapter_receipt(envelope),
    )


__all__ = [
    "ADAPTER_CAPABILITY",
    "ADAPTER_FORBIDDEN_FIELDS",
    "ADAPTER_NAMESPACE",
    "allowed_pipeline_result",
    "adapter_mapping",
    "adapter_replay_request",
    "blocked_pipeline_result",
    "qos_profile",
    "ros2_move_mapping",
    "ros2_stop_mapping",
    "runtime_target",
]
