"""Non-executing adapter boundary for future runtime integrations."""

from aegis.execution.aegis_adapter_envelope import build_execution_adapter_envelope
from aegis.execution.aegis_adapter_replay import AdapterReplayOutput, replay_execution_adapter
from aegis.execution.aegis_adapter_replay_mutations import mutate_adapter_replay_request_in_place
from aegis.execution.aegis_adapter_replay_proof import prove_adapter_replay
from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerChainValidationResult,
    ApprovalLedgerEntry,
    append_approval_ledger_entry,
    approval_ledger_genesis_head_checksum,
    approval_ledger_prior_chain_block_reason,
    approval_ledger_prior_chain_quarantine_block_reason,
    validate_approval_ledger_chain,
)
from aegis.execution.aegis_approval_ledger_head import (
    ApprovalLedgerAppendResult,
    ApprovalLedgerHead,
    ApprovalLedgerHeadReason,
    ApprovalLedgerHeadValidationResult,
    LedgerEpochManifest,
    append_to_approval_ledger_head,
    approval_ledger_append_result_checksum,
    approval_ledger_head_checksum,
    approval_ledger_prior_chain_quarantine_head_block_reason,
    build_approval_ledger_head,
    build_ledger_epoch_manifest,
    ledger_epoch_manifest_checksum,
    recompute_approval_ledger_append_result_checksum,
    recompute_approval_ledger_head_checksum,
    recompute_ledger_epoch_manifest_checksum,
    validate_approval_ledger_head,
)
from aegis.execution.aegis_approval_ledger_repository import (
    ApprovalLedgerRepositoryAuthorityEvidence,
    ApprovalLedgerRepositoryReason,
    InMemoryApprovalLedgerRepository,
    RepositoryCommitResult,
    build_approval_ledger_repository_authority_evidence,
    recompute_repository_commit_result_checksum,
)
from aegis.execution.aegis_approval_ledger_state import (
    ApprovalLedgerStateReason,
    ApprovalLedgerStateSnapshot,
    ApprovalLedgerStateTransition,
    LedgerStateValidationResult,
    append_to_approval_ledger_state,
    approval_ledger_state_block_reason,
    approval_ledger_state_quarantine_block_reason,
    build_approval_ledger_state_snapshot,
    build_approval_ledger_state_transition,
    validate_approval_ledger_state_snapshot,
    validate_approval_ledger_state_transition,
)
from aegis.execution.aegis_approval_replay import (
    build_authority_bound_approval_receipt,
    validate_approval_replay,
)
from aegis.execution.aegis_backend_admission import admit_runtime_backend
from aegis.execution.aegis_backend_authority import build_backend_authority_manifest
from aegis.execution.aegis_backend_certification import certify_runtime_backend
from aegis.execution.aegis_backend_receipt import (
    build_backend_dry_run_receipt,
    is_backend_dry_run_receipt_valid,
)
from aegis.execution.aegis_backend_registry import build_backend_authority_registry
from aegis.execution.aegis_backend_replay import BackendReplayOutput, replay_runtime_backend
from aegis.execution.aegis_backend_replay_mutations import mutate_backend_replay_request_in_place
from aegis.execution.aegis_backend_replay_proof import prove_backend_replay
from aegis.execution.aegis_capability_lease import issue_runtime_capability_lease
from aegis.execution.aegis_command_quarantine import quarantine_runtime_command
from aegis.execution.aegis_dispatch_firewall import evaluate_dispatch_firewall
from aegis.execution.aegis_dispatch_receipt import build_runtime_dispatch_receipt
from aegis.execution.aegis_lease_revocation import evaluate_runtime_lease_revocation
from aegis.execution.aegis_lease_validation import validate_runtime_capability_lease
from aegis.execution.aegis_mapping_validator import validate_execution_adapter_mapping
from aegis.execution.aegis_null_runtime_backend import (
    NullRuntimeBackend,
    build_null_runtime_backend,
)
from aegis.execution.aegis_operator_approval import build_operator_approval_receipt
from aegis.execution.aegis_operator_authority import build_operator_authority_manifest
from aegis.execution.aegis_operator_identity import (
    build_operator_approval_nonce,
    build_operator_identity_claim,
)
from aegis.execution.aegis_quarantine_release import evaluate_quarantine_release
from aegis.execution.aegis_ros2_mapping_validator import validate_ros2_message_mapping
from aegis.execution.aegis_runtime_dispatch import build_runtime_dispatch_plan

__all__ = [
    "ApprovalLedgerChainValidationResult",
    "ApprovalLedgerEntry",
    "append_approval_ledger_entry",
    "approval_ledger_genesis_head_checksum",
    "approval_ledger_prior_chain_block_reason",
    "approval_ledger_prior_chain_quarantine_block_reason",
    "validate_approval_ledger_chain",
    "ApprovalLedgerAppendResult",
    "ApprovalLedgerHead",
    "ApprovalLedgerHeadReason",
    "ApprovalLedgerHeadValidationResult",
    "LedgerEpochManifest",
    "append_to_approval_ledger_head",
    "approval_ledger_append_result_checksum",
    "approval_ledger_head_checksum",
    "approval_ledger_prior_chain_quarantine_head_block_reason",
    "build_approval_ledger_head",
    "build_ledger_epoch_manifest",
    "ledger_epoch_manifest_checksum",
    "recompute_approval_ledger_append_result_checksum",
    "recompute_approval_ledger_head_checksum",
    "recompute_ledger_epoch_manifest_checksum",
    "validate_approval_ledger_head",
    "ApprovalLedgerStateReason",
    "ApprovalLedgerStateSnapshot",
    "ApprovalLedgerStateTransition",
    "LedgerStateValidationResult",
    "append_to_approval_ledger_state",
    "approval_ledger_state_block_reason",
    "approval_ledger_state_quarantine_block_reason",
    "build_approval_ledger_state_snapshot",
    "build_approval_ledger_state_transition",
    "validate_approval_ledger_state_snapshot",
    "validate_approval_ledger_state_transition",
    "ApprovalLedgerRepositoryAuthorityEvidence",
    "ApprovalLedgerRepositoryReason",
    "InMemoryApprovalLedgerRepository",
    "RepositoryCommitResult",
    "build_approval_ledger_repository_authority_evidence",
    "recompute_repository_commit_result_checksum",
    "build_execution_adapter_envelope",
    "build_runtime_dispatch_plan",
    "build_runtime_dispatch_receipt",
    "AdapterReplayOutput",
    "BackendReplayOutput",
    "NullRuntimeBackend",
    "admit_runtime_backend",
    "build_backend_authority_manifest",
    "build_backend_authority_registry",
    "build_backend_dry_run_receipt",
    "build_null_runtime_backend",
    "build_operator_approval_receipt",
    "build_operator_approval_nonce",
    "build_operator_authority_manifest",
    "build_operator_identity_claim",
    "build_authority_bound_approval_receipt",
    "certify_runtime_backend",
    "evaluate_dispatch_firewall",
    "evaluate_quarantine_release",
    "evaluate_runtime_lease_revocation",
    "issue_runtime_capability_lease",
    "is_backend_dry_run_receipt_valid",
    "mutate_backend_replay_request_in_place",
    "mutate_adapter_replay_request_in_place",
    "prove_backend_replay",
    "prove_adapter_replay",
    "quarantine_runtime_command",
    "replay_runtime_backend",
    "replay_execution_adapter",
    "validate_execution_adapter_mapping",
    "validate_runtime_capability_lease",
    "validate_approval_replay",
    "validate_ros2_message_mapping",
]
