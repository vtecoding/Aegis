"""Execution adapter authority manifests for ADR-0015 drift checks."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts.aegis_adapter_receipt import AdapterReceipt
from aegis.contracts.aegis_adapter_replay import AdapterReplayProofResult, AdapterReplayRequest
from aegis.contracts.aegis_backend_replay import BackendReplayProofResult, BackendReplayRequest
from aegis.contracts.aegis_execution_adapter import (
    ExecutionAdapterEnvelope,
    ExecutionAdapterMapping,
)
from aegis.contracts.aegis_ros2_mapping import Ros2MessageMapping, Ros2QoSProfileSpec, RuntimeTarget
from aegis.contracts.aegis_runtime_backend import (
    BackendCertificationResult,
    BackendDryRunReceipt,
    RuntimeBackendDescriptor,
)
from aegis.contracts.aegis_runtime_dispatch import (
    DispatchFirewallDecision,
    RuntimeDispatchItem,
    RuntimeDispatchPlan,
    RuntimeDispatchReceipt,
)
from aegis.execution.aegis_approval_ledger import (
    ApprovalLedgerChainValidationResult,
    ApprovalLedgerEntry,
)
from aegis.execution.aegis_approval_replay import (
    ApprovalReplayValidationResult,
    AuthorityBoundApprovalReceipt,
)
from aegis.execution.aegis_backend_admission import (
    BackendAdmissionDecision,
    BackendAdmissionRequest,
)
from aegis.execution.aegis_backend_authority import BackendAuthorityManifest
from aegis.execution.aegis_backend_registry import BackendAuthorityRegistry
from aegis.execution.aegis_capability_lease import RuntimeCapabilityLease
from aegis.execution.aegis_command_quarantine import CommandQuarantineEnvelope
from aegis.execution.aegis_lease_revocation import LeaseRevocationDecision
from aegis.execution.aegis_lease_validation import LeaseValidationResult
from aegis.execution.aegis_operator_approval import OperatorApprovalReceipt
from aegis.execution.aegis_operator_authority import OperatorAuthorityManifest
from aegis.execution.aegis_operator_identity import OperatorApprovalNonce, OperatorIdentityClaim
from aegis.execution.aegis_quarantine_release import QuarantineReleaseDecision


@dataclass(frozen=True, slots=True)
class AdapterAuthorityFieldManifest:
    """Static classification for one adapter boundary contract."""

    contract_name: str
    authoritative_fields: tuple[str, ...]
    checksum_function: str
    reason: str


@dataclass(frozen=True, slots=True)
class AdapterAuthorityContract:
    """Adapter contract type paired with its static authority manifest."""

    contract_type: type[object]
    manifest: AdapterAuthorityFieldManifest


def adapter_manifest_for(
    *,
    contract_type: type[object],
    authoritative_fields: tuple[str, ...],
    checksum_function: str,
    reason: str,
) -> AdapterAuthorityContract:
    """Return an adapter authority manifest without mutating global state."""
    return AdapterAuthorityContract(
        contract_type=contract_type,
        manifest=AdapterAuthorityFieldManifest(
            contract_name=contract_type.__name__,
            authoritative_fields=authoritative_fields,
            checksum_function=checksum_function,
            reason=reason,
        ),
    )


ADAPTER_AUTHORITY_CONTRACTS = (
    adapter_manifest_for(
        contract_type=RuntimeTarget,
        authoritative_fields=(
            "runtime_kind",
            "runtime_id",
            "runtime_version",
            "deployment_domain",
            "target_namespace",
            "target_robot_id",
            "runtime_authority",
            "runtime_target_checksum",
        ),
        checksum_function="runtime_target_checksum_value",
        reason="runtime target identity is adapter evidence, not permission",
    ),
    adapter_manifest_for(
        contract_type=Ros2QoSProfileSpec,
        authoritative_fields=(
            "reliability",
            "durability",
            "history",
            "depth",
            "deadline_ms",
            "lifespan_ms",
            "liveliness",
            "lease_duration_ms",
            "qos_checksum",
        ),
        checksum_function="ros2_qos_profile_checksum",
        reason="QoS is explicit adapter evidence and no middleware defaults are trusted",
    ),
    adapter_manifest_for(
        contract_type=Ros2MessageMapping,
        authoritative_fields=(
            "mapping_id",
            "mapping_version",
            "source_command",
            "source_capability",
            "primitive",
            "package_name",
            "message_type",
            "topic_or_service_name",
            "namespace",
            "frame_id",
            "qos",
            "field_map",
            "required_fields",
            "forbidden_fields",
            "mapping_authority",
            "mapping_checksum",
        ),
        checksum_function="ros2_message_mapping_checksum",
        reason="ROS 2 mapping evidence decides how abstract commands may be represented",
    ),
    adapter_manifest_for(
        contract_type=ExecutionAdapterMapping,
        authoritative_fields=(
            "adapter_mapping_id",
            "adapter_mapping_version",
            "runtime_target",
            "ros2_mapping",
            "accepted_pipeline_version",
            "accepted_gate_version",
            "accepted_policy_schema_version",
            "adapter_authority",
            "effective_from_ms",
            "supersedes_mapping_checksum",
            "adapter_mapping_checksum",
        ),
        checksum_function="execution_adapter_mapping_checksum",
        reason="adapter mappings bind runtime and ROS 2 evidence to Phase 2 authority",
    ),
    adapter_manifest_for(
        contract_type=ExecutionAdapterEnvelope,
        authoritative_fields=(
            "status",
            "pipeline_receipt_checksum",
            "decision_trace_checksum",
            "audited_plan_id",
            "plan_checksum",
            "policy_checksum",
            "context_authority_checksum",
            "safety_case_id",
            "adapter_mapping_checksum",
            "runtime_target_checksum",
            "ros2_mapping_checksum",
            "command_payload",
            "blocked_reasons",
            "terminal_adapter_stage",
            "payload_field_count",
            "forbidden_field_detected",
            "qos_profile_checksum",
            "adapter_authority",
            "adapter_mapping",
            "target_runtime",
            "envelope_checksum",
        ),
        checksum_function="execution_adapter_envelope_checksum",
        reason="adapter envelopes are the non-executing boundary packet for future runtimes",
    ),
    adapter_manifest_for(
        contract_type=AdapterReceipt,
        authoritative_fields=(
            "status",
            "reason",
            "pipeline_receipt_checksum",
            "decision_trace_checksum",
            "adapter_mapping_checksum",
            "runtime_target_checksum",
            "ros2_mapping_checksum",
            "envelope_checksum",
            "adapter_receipt_checksum",
        ),
        checksum_function="adapter_receipt_checksum_value",
        reason="adapter receipts bind envelope evidence for later observability export",
    ),
    adapter_manifest_for(
        contract_type=AdapterReplayRequest,
        authoritative_fields=(
            "pipeline_result",
            "expected_envelope",
            "expected_adapter_receipt",
            "replay_profile",
            "mutation_profile",
        ),
        checksum_function="adapter_replay_source_pipeline_checksum",
        reason="adapter replay requests bind source, expected envelope, receipt, and profile",
    ),
    adapter_manifest_for(
        contract_type=AdapterReplayProofResult,
        authoritative_fields=(
            "status",
            "reason",
            "source_pipeline_checksum",
            "expected_envelope_checksum",
            "replayed_envelope_checksum",
            "expected_receipt_checksum",
            "replayed_receipt_checksum",
            "mapping_checksum_match",
            "runtime_target_checksum_match",
            "qos_checksum_match",
            "namespace_match",
            "receipt_chain_match",
            "mutation_detected",
            "failure_stage",
            "proof_checksum",
        ),
        checksum_function="adapter_replay_proof_checksum",
        reason="adapter replay proofs bind every replay-critical comparison result",
    ),
    adapter_manifest_for(
        contract_type=RuntimeDispatchItem,
        authoritative_fields=(
            "sequence",
            "capability",
            "runtime_kind",
            "runtime_name",
            "namespace",
            "message_type",
            "qos_profile_checksum",
            "payload_checksum",
            "payload_size_bytes",
            "field_map_checksum",
        ),
        checksum_function="runtime_dispatch_plan_checksum",
        reason="dispatch items describe inert runtime intent without backend handles",
    ),
    adapter_manifest_for(
        contract_type=RuntimeDispatchPlan,
        authoritative_fields=(
            "plan_id",
            "source_envelope_checksum",
            "source_replay_proof_checksum",
            "runtime_target_checksum",
            "mapping_checksum",
            "dispatch_mode",
            "dispatch_items",
            "resource_bounds",
            "plan_checksum",
        ),
        checksum_function="runtime_dispatch_plan_checksum",
        reason="runtime dispatch plans bind replay proof to dry-run-only dispatch intent",
    ),
    adapter_manifest_for(
        contract_type=DispatchFirewallDecision,
        authoritative_fields=(
            "status",
            "reason_code",
            "plan_checksum",
            "source_replay_proof_checksum",
            "blocked_stage",
            "decision_checksum",
        ),
        checksum_function="dispatch_firewall_decision_checksum",
        reason="dispatch firewall decisions prove DRY_RUN_ONLY admission or fail closed",
    ),
    adapter_manifest_for(
        contract_type=RuntimeDispatchReceipt,
        authoritative_fields=(
            "status",
            "reason_code",
            "plan_checksum",
            "source_envelope_checksum",
            "source_replay_proof_checksum",
            "decision_checksum",
            "dispatch_mode",
            "dry_run_receipt_checksum",
        ),
        checksum_function="runtime_dispatch_receipt_checksum",
        reason="dry-run receipts bind runtime dispatch plans to firewall decisions",
    ),
    adapter_manifest_for(
        contract_type=RuntimeBackendDescriptor,
        authoritative_fields=(
            "backend_id",
            "backend_kind",
            "backend_mode",
            "supported_runtime_kinds",
            "supported_capabilities",
            "allows_execution",
            "allows_io",
            "allows_async",
            "descriptor_checksum",
        ),
        checksum_function="runtime_backend_descriptor_checksum",
        reason="backend descriptors declare the only non-executing ADR-0018 backend shape",
    ),
    adapter_manifest_for(
        contract_type=BackendCertificationResult,
        authoritative_fields=(
            "status",
            "reason_code",
            "dispatch_plan_checksum",
            "firewall_decision_checksum",
            "backend_descriptor_checksum",
            "no_execution_guarantee",
            "no_io_guarantee",
            "no_async_guarantee",
            "capability_scope_match",
            "runtime_kind_scope_match",
            "certification_checksum",
        ),
        checksum_function="backend_certification_result_checksum",
        reason="backend certification binds dispatch intent to a null non-execution guarantee",
    ),
    adapter_manifest_for(
        contract_type=BackendDryRunReceipt,
        authoritative_fields=(
            "receipt_id",
            "dispatch_plan_checksum",
            "firewall_decision_checksum",
            "backend_certification_checksum",
            "backend_descriptor_checksum",
            "observed_dispatch_items",
            "executed_count",
            "blocked_execution_count",
            "receipt_checksum",
        ),
        checksum_function="backend_dry_run_receipt_checksum",
        reason="backend dry-run receipts prove observed intent with zero execution",
    ),
    adapter_manifest_for(
        contract_type=BackendReplayRequest,
        authoritative_fields=(
            "dispatch_plan",
            "firewall_decision",
            "backend_descriptor",
            "expected_certification",
            "expected_receipt",
            "replay_profile",
            "mutation_profile",
        ),
        checksum_function="backend_replay_request_source_checksum",
        reason=(
            "backend replay requests bind dispatch, firewall, descriptor, and expected "
            "proof evidence"
        ),
    ),
    adapter_manifest_for(
        contract_type=BackendReplayProofResult,
        authoritative_fields=(
            "status",
            "reason_code",
            "dispatch_plan_checksum",
            "firewall_decision_checksum",
            "backend_descriptor_checksum",
            "expected_certification_checksum",
            "replayed_certification_checksum",
            "expected_receipt_checksum",
            "replayed_receipt_checksum",
            "zero_execution_verified",
            "scope_match_verified",
            "certification_match",
            "receipt_match",
            "mutation_detected",
            "failure_stage",
            "proof_checksum",
        ),
        checksum_function="backend_replay_proof_checksum",
        reason="backend replay proofs bind certification and receipt reconstruction comparisons",
    ),
    adapter_manifest_for(
        contract_type=BackendAuthorityManifest,
        authoritative_fields=(
            "backend_kind",
            "backend_version",
            "allowed_modes",
            "allowed_runtime_kinds",
            "allowed_capabilities",
            "required_certification_profile",
            "required_replay_profile",
            "allows_execution",
            "allows_io",
            "allows_async",
            "admission_status",
            "manifest_checksum",
        ),
        checksum_function="backend_authority_manifest_checksum",
        reason="backend authority manifests are the closed ADR-0020 admission scope",
    ),
    adapter_manifest_for(
        contract_type=BackendAuthorityRegistry,
        authoritative_fields=(
            "manifests",
            "registry_checksum",
        ),
        checksum_function="backend_authority_registry_checksum",
        reason="backend authority registries bind the complete admitted manifest set",
    ),
    adapter_manifest_for(
        contract_type=BackendAdmissionRequest,
        authoritative_fields=(
            "backend_descriptor",
            "backend_certification",
            "backend_replay_proof",
            "authority_manifest",
            "registry_checksum",
        ),
        checksum_function="backend_admission_request",
        reason="backend admission requests bind descriptor, certification, replay, and registry",
    ),
    adapter_manifest_for(
        contract_type=BackendAdmissionDecision,
        authoritative_fields=(
            "status",
            "reason_code",
            "backend_kind",
            "backend_descriptor_checksum",
            "certification_checksum",
            "replay_proof_checksum",
            "authority_manifest_checksum",
            "registry_checksum",
            "decision_checksum",
        ),
        checksum_function="backend_admission_decision_checksum",
        reason="backend admission decisions bind every ADR-0020 authority input checksum",
    ),
    adapter_manifest_for(
        contract_type=RuntimeCapabilityLease,
        authoritative_fields=(
            "lease_id",
            "backend_kind",
            "backend_descriptor_checksum",
            "admission_decision_checksum",
            "authority_manifest_checksum",
            "registry_checksum",
            "certification_checksum",
            "replay_proof_checksum",
            "dispatch_plan_checksum",
            "firewall_decision_checksum",
            "context_authority_checksum",
            "leased_capabilities",
            "leased_runtime_kinds",
            "lease_epoch",
            "lease_status",
            "lease_checksum",
        ),
        checksum_function="runtime_capability_lease_checksum",
        reason="capability leases bind admitted backend authority to explicit runtime scope",
    ),
    adapter_manifest_for(
        contract_type=LeaseValidationResult,
        authoritative_fields=(
            "status",
            "reason_code",
            "lease_checksum",
            "current_registry_checksum",
            "current_manifest_checksum",
            "current_context_authority_checksum",
            "scope_match",
            "evidence_chain_match",
            "validation_checksum",
        ),
        checksum_function="lease_validation_result_checksum",
        reason="lease validation binds current evidence and scope checks to validation status",
    ),
    adapter_manifest_for(
        contract_type=LeaseRevocationDecision,
        authoritative_fields=(
            "status",
            "reason_code",
            "lease_checksum",
            "revoked_evidence_checksum",
            "revocation_stage",
            "revocation_checksum",
        ),
        checksum_function="lease_revocation_decision_checksum",
        reason="lease revocation decisions record deterministic reason-coded revocation evidence",
    ),
    adapter_manifest_for(
        contract_type=CommandQuarantineEnvelope,
        authoritative_fields=(
            "quarantine_id",
            "dispatch_plan_checksum",
            "backend_admission_checksum",
            "capability_lease_checksum",
            "backend_descriptor_checksum",
            "authority_manifest_checksum",
            "registry_checksum",
            "certification_checksum",
            "backend_replay_proof_checksum",
            "context_authority_checksum",
            "quarantined_items",
            "quarantine_status",
            "quarantine_epoch",
            "quarantine_checksum",
        ),
        checksum_function="command_quarantine_envelope_checksum",
        reason="command quarantine envelopes bind every lease-valid dispatch item before approval",
    ),
    adapter_manifest_for(
        contract_type=OperatorApprovalReceipt,
        authoritative_fields=(
            "approval_id",
            "operator_id",
            "approval_status",
            "quarantine_checksum",
            "approved_scope",
            "approval_epoch",
            "approval_reason",
            "approval_checksum",
        ),
        checksum_function="operator_approval_receipt_checksum",
        reason="operator approval receipts bind explicit scope to one quarantine checksum",
    ),
    adapter_manifest_for(
        contract_type=QuarantineReleaseDecision,
        authoritative_fields=(
            "status",
            "reason_code",
            "quarantine_checksum",
            "approval_checksum",
            "approval_replay_validation_checksum",
            "lease_checksum",
            "dispatch_plan_checksum",
            "released_item_count",
            "decision_checksum",
        ),
        checksum_function="quarantine_release_decision_checksum",
        reason=(
            "quarantine release decisions prove only approved dry-run intent may leave quarantine"
        ),
    ),
    adapter_manifest_for(
        contract_type=OperatorAuthorityManifest,
        authoritative_fields=(
            "authority_id",
            "authority_version",
            "allowed_operator_roles",
            "allowed_approval_scopes",
            "required_context_authority_checksum",
            "approval_epoch",
            "manifest_status",
            "manifest_checksum",
        ),
        checksum_function="operator_authority_manifest_checksum",
        reason="operator authority manifests bind structural approval roles and scope",
    ),
    adapter_manifest_for(
        contract_type=OperatorIdentityClaim,
        authoritative_fields=(
            "operator_id",
            "operator_role",
            "operator_authority_manifest_checksum",
            "context_authority_checksum",
            "identity_epoch",
            "identity_checksum",
        ),
        checksum_function="operator_identity_claim_checksum",
        reason="operator identity claims bind a structural operator to an authority manifest",
    ),
    adapter_manifest_for(
        contract_type=OperatorApprovalNonce,
        authoritative_fields=(
            "nonce_id",
            "quarantine_checksum",
            "operator_identity_checksum",
            "approval_epoch",
            "nonce_checksum",
        ),
        checksum_function="operator_approval_nonce_checksum",
        reason="operator approval nonces bind one identity to one quarantine checksum",
    ),
    adapter_manifest_for(
        contract_type=AuthorityBoundApprovalReceipt,
        authoritative_fields=(
            "approval_id",
            "approval_status",
            "quarantine_checksum",
            "operator_identity_checksum",
            "operator_authority_manifest_checksum",
            "approval_nonce_checksum",
            "approved_scope",
            "approval_epoch",
            "authority_bound_checksum",
        ),
        checksum_function="authority_bound_approval_receipt_checksum",
        reason="authority-bound approvals bind identity, manifest, nonce, scope, and quarantine",
    ),
    adapter_manifest_for(
        contract_type=ApprovalReplayValidationResult,
        authoritative_fields=(
            "status",
            "reason_code",
            "approval_checksum",
            "quarantine_checksum",
            "operator_identity_checksum",
            "authority_manifest_checksum",
            "nonce_checksum",
            "context_authority_checksum",
            "replay_validation_checksum",
        ),
        checksum_function="approval_replay_validation_checksum",
        reason="approval replay validation binds the release proof to one evidence chain",
    ),
    adapter_manifest_for(
        contract_type=ApprovalLedgerEntry,
        authoritative_fields=(
            "sequence_index",
            "prior_entry_checksum",
            "release_decision_checksum",
            "entry_checksum",
        ),
        checksum_function="approval_ledger_entry_checksum",
        reason="approval ledger entries hash-link one release decision checksum to the prior tip",
    ),
    adapter_manifest_for(
        contract_type=ApprovalLedgerChainValidationResult,
        authoritative_fields=(
            "status",
            "reason_code",
            "chain_depth",
            "chain_tip_checksum",
            "ledger_validation_checksum",
        ),
        checksum_function="approval_ledger_chain_validation_checksum",
        reason="approval ledger chain validation binds tamper-evidence for a ledger prefix",
    ),
)
"""Closed ADR-0015 adapter authority contract manifest registry."""

ADAPTER_AUTHORITY_FIELD_MANIFESTS = tuple(item.manifest for item in ADAPTER_AUTHORITY_CONTRACTS)
"""Static adapter field manifests consumed by ADR-0015 checks."""


__all__ = [
    "ADAPTER_AUTHORITY_CONTRACTS",
    "ADAPTER_AUTHORITY_FIELD_MANIFESTS",
    "AdapterAuthorityContract",
    "AdapterAuthorityFieldManifest",
    "adapter_manifest_for",
]
