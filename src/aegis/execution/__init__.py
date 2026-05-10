"""Non-executing adapter boundary for future runtime integrations."""

from aegis.execution.adapter_envelope import build_execution_adapter_envelope
from aegis.execution.adapter_replay import AdapterReplayOutput, replay_execution_adapter
from aegis.execution.adapter_replay_mutations import mutate_adapter_replay_request_in_place
from aegis.execution.adapter_replay_proof import prove_adapter_replay
from aegis.execution.mapping_validator import validate_execution_adapter_mapping
from aegis.execution.ros2_mapping_validator import validate_ros2_message_mapping

__all__ = [
    "build_execution_adapter_envelope",
    "AdapterReplayOutput",
    "mutate_adapter_replay_request_in_place",
    "prove_adapter_replay",
    "replay_execution_adapter",
    "validate_execution_adapter_mapping",
    "validate_ros2_message_mapping",
]
