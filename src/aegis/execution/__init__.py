"""Non-executing adapter boundary for future runtime integrations."""

from aegis.execution.adapter_envelope import build_execution_adapter_envelope
from aegis.execution.adapter_replay import AdapterReplayOutput, replay_execution_adapter
from aegis.execution.adapter_replay_mutations import mutate_adapter_replay_request_in_place
from aegis.execution.adapter_replay_proof import prove_adapter_replay
from aegis.execution.backend_certification import certify_runtime_backend
from aegis.execution.backend_receipt import (
    build_backend_dry_run_receipt,
    is_backend_dry_run_receipt_valid,
)
from aegis.execution.backend_replay import BackendReplayOutput, replay_runtime_backend
from aegis.execution.backend_replay_mutations import mutate_backend_replay_request_in_place
from aegis.execution.backend_replay_proof import prove_backend_replay
from aegis.execution.dispatch_firewall import evaluate_dispatch_firewall
from aegis.execution.dispatch_receipt import build_runtime_dispatch_receipt
from aegis.execution.mapping_validator import validate_execution_adapter_mapping
from aegis.execution.null_runtime_backend import NullRuntimeBackend, build_null_runtime_backend
from aegis.execution.ros2_mapping_validator import validate_ros2_message_mapping
from aegis.execution.runtime_dispatch import build_runtime_dispatch_plan

__all__ = [
    "build_execution_adapter_envelope",
    "build_runtime_dispatch_plan",
    "build_runtime_dispatch_receipt",
    "AdapterReplayOutput",
    "BackendReplayOutput",
    "NullRuntimeBackend",
    "build_backend_dry_run_receipt",
    "build_null_runtime_backend",
    "certify_runtime_backend",
    "evaluate_dispatch_firewall",
    "is_backend_dry_run_receipt_valid",
    "mutate_backend_replay_request_in_place",
    "mutate_adapter_replay_request_in_place",
    "prove_backend_replay",
    "prove_adapter_replay",
    "replay_runtime_backend",
    "replay_execution_adapter",
    "validate_execution_adapter_mapping",
    "validate_ros2_message_mapping",
]
