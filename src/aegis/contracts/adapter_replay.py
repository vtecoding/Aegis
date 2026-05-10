"""Adapter replay proof contracts for ADR-0016."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.contracts.adapter_receipt import AdapterReceipt
from aegis.contracts.execution_adapter import ExecutionAdapterEnvelope
from aegis.contracts.pipeline import PipelineResult

type AdapterReplayProofStatus = Literal["PASSED", "FAILED", "BLOCKED"]
type CanonicalAdapterReplayValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalAdapterReplayValue]
    | dict[str, CanonicalAdapterReplayValue]
)


class AdapterReplayProfile(StrEnum):
    """Supported deterministic adapter replay profiles."""

    STRICT_ADAPTER_REPLAY_V1 = "STRICT_ADAPTER_REPLAY_V1"


class AdapterReplayMutationProfile(StrEnum):
    """Closed set of ADR-0016 evil-twin replay mutation profiles."""

    NONE = "NONE"
    PIPELINE_RECEIPT_CHECKSUM_DRIFT = "PIPELINE_RECEIPT_CHECKSUM_DRIFT"
    POLICY_RESULT_CHECKSUM_DRIFT = "POLICY_RESULT_CHECKSUM_DRIFT"
    SAFETY_CASE_CHECKSUM_DRIFT = "SAFETY_CASE_CHECKSUM_DRIFT"
    CONTEXT_AUTHORITY_MISMATCH = "CONTEXT_AUTHORITY_MISMATCH"
    POLICY_IDENTITY_MISMATCH = "POLICY_IDENTITY_MISMATCH"
    WORLD_SNAPSHOT_ADMISSIBILITY_MISMATCH = "WORLD_SNAPSHOT_ADMISSIBILITY_MISMATCH"
    WORLD_SNAPSHOT_FRESHNESS_MISMATCH = "WORLD_SNAPSHOT_FRESHNESS_MISMATCH"
    WORLD_SNAPSHOT_TRUST_MISMATCH = "WORLD_SNAPSHOT_TRUST_MISMATCH"
    COMMAND_PLAN_MUTATION = "COMMAND_PLAN_MUTATION"
    CAPABILITY_MUTATION = "CAPABILITY_MUTATION"
    ROS_MESSAGE_TYPE_MUTATION = "ROS_MESSAGE_TYPE_MUTATION"
    FIELD_MAP_MUTATION = "FIELD_MAP_MUTATION"
    QOS_MUTATION = "QOS_MUTATION"
    NAMESPACE_MUTATION = "NAMESPACE_MUTATION"
    RUNTIME_TARGET_MUTATION = "RUNTIME_TARGET_MUTATION"
    ADAPTER_RECEIPT_REPLAY_TARGET_MUTATION = "ADAPTER_RECEIPT_REPLAY_TARGET_MUTATION"
    ADAPTER_RECEIPT_CHECKSUM_MUTATION = "ADAPTER_RECEIPT_CHECKSUM_MUTATION"
    READY_ENVELOPE_STALE_RECEIPT = "READY_ENVELOPE_STALE_RECEIPT"
    RESOURCE_BOUNDS_MUTATION = "RESOURCE_BOUNDS_MUTATION"


@dataclass(frozen=True, slots=True, init=False)
class AdapterReplayRequest:
    """Immutable request to replay a READY adapter envelope from pipeline evidence."""

    pipeline_result: PipelineResult
    expected_envelope: ExecutionAdapterEnvelope
    expected_adapter_receipt: AdapterReceipt
    replay_profile: AdapterReplayProfile
    mutation_profile: AdapterReplayMutationProfile

    def __init__(
        self,
        *,
        pipeline_result: object,
        expected_envelope: object,
        expected_adapter_receipt: object,
        replay_profile: object = AdapterReplayProfile.STRICT_ADAPTER_REPLAY_V1,
        mutation_profile: object = AdapterReplayMutationProfile.NONE,
    ) -> None:
        if not isinstance(pipeline_result, PipelineResult):
            raise ValueError("pipeline_result must be a PipelineResult")
        if not isinstance(expected_envelope, ExecutionAdapterEnvelope):
            raise ValueError("expected_envelope must be an ExecutionAdapterEnvelope")
        if not isinstance(expected_adapter_receipt, AdapterReceipt):
            raise ValueError("expected_adapter_receipt must be an AdapterReceipt")
        object.__setattr__(self, "pipeline_result", pipeline_result)
        object.__setattr__(self, "expected_envelope", expected_envelope)
        object.__setattr__(self, "expected_adapter_receipt", expected_adapter_receipt)
        object.__setattr__(self, "replay_profile", _normalize_replay_profile(replay_profile))
        object.__setattr__(self, "mutation_profile", _normalize_mutation_profile(mutation_profile))


@dataclass(frozen=True, slots=True, init=False)
class AdapterReplayProofResult:
    """Checksum-bound result of deterministic adapter replay proof."""

    status: AdapterReplayProofStatus
    reason: str
    source_pipeline_checksum: str
    expected_envelope_checksum: str | None
    replayed_envelope_checksum: str | None
    expected_receipt_checksum: str | None
    replayed_receipt_checksum: str | None
    mapping_checksum_match: bool
    runtime_target_checksum_match: bool
    qos_checksum_match: bool
    namespace_match: bool
    receipt_chain_match: bool
    mutation_detected: bool
    failure_stage: str | None
    proof_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason: str,
        source_pipeline_checksum: str,
        expected_envelope_checksum: str | None,
        replayed_envelope_checksum: str | None,
        expected_receipt_checksum: str | None,
        replayed_receipt_checksum: str | None,
        mapping_checksum_match: object,
        runtime_target_checksum_match: object,
        qos_checksum_match: object,
        namespace_match: object,
        receipt_chain_match: object,
        mutation_detected: object,
        failure_stage: str | None,
        proof_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason)
        normalized_source = _normalize_required_checksum(
            source_pipeline_checksum, "source_pipeline_checksum"
        )
        normalized_expected_envelope = _normalize_optional_checksum(
            expected_envelope_checksum, "expected_envelope_checksum"
        )
        normalized_replayed_envelope = _normalize_optional_checksum(
            replayed_envelope_checksum, "replayed_envelope_checksum"
        )
        normalized_expected_receipt = _normalize_optional_checksum(
            expected_receipt_checksum, "expected_receipt_checksum"
        )
        normalized_replayed_receipt = _normalize_optional_checksum(
            replayed_receipt_checksum, "replayed_receipt_checksum"
        )
        normalized_mapping_match = _normalize_bool(mapping_checksum_match, "mapping_checksum_match")
        normalized_runtime_match = _normalize_bool(
            runtime_target_checksum_match, "runtime_target_checksum_match"
        )
        normalized_qos_match = _normalize_bool(qos_checksum_match, "qos_checksum_match")
        normalized_namespace_match = _normalize_bool(namespace_match, "namespace_match")
        normalized_receipt_chain_match = _normalize_bool(receipt_chain_match, "receipt_chain_match")
        normalized_mutation = _normalize_bool(mutation_detected, "mutation_detected")
        normalized_failure_stage = _normalize_optional_stage(failure_stage, "failure_stage")
        if normalized_status == "PASSED":
            _validate_passed_result(
                expected_envelope_checksum=normalized_expected_envelope,
                replayed_envelope_checksum=normalized_replayed_envelope,
                expected_receipt_checksum=normalized_expected_receipt,
                replayed_receipt_checksum=normalized_replayed_receipt,
                mapping_checksum_match=normalized_mapping_match,
                runtime_target_checksum_match=normalized_runtime_match,
                qos_checksum_match=normalized_qos_match,
                namespace_match=normalized_namespace_match,
                receipt_chain_match=normalized_receipt_chain_match,
                mutation_detected=normalized_mutation,
                failure_stage=normalized_failure_stage,
            )
        computed_checksum = adapter_replay_proof_checksum(
            status=normalized_status,
            reason=normalized_reason,
            source_pipeline_checksum=normalized_source,
            expected_envelope_checksum=normalized_expected_envelope,
            replayed_envelope_checksum=normalized_replayed_envelope,
            expected_receipt_checksum=normalized_expected_receipt,
            replayed_receipt_checksum=normalized_replayed_receipt,
            mapping_checksum_match=normalized_mapping_match,
            runtime_target_checksum_match=normalized_runtime_match,
            qos_checksum_match=normalized_qos_match,
            namespace_match=normalized_namespace_match,
            receipt_chain_match=normalized_receipt_chain_match,
            mutation_detected=normalized_mutation,
            failure_stage=normalized_failure_stage,
        )
        normalized_checksum = _normalize_supplied_checksum(
            proof_checksum, computed_checksum, "proof_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "source_pipeline_checksum", normalized_source)
        object.__setattr__(self, "expected_envelope_checksum", normalized_expected_envelope)
        object.__setattr__(self, "replayed_envelope_checksum", normalized_replayed_envelope)
        object.__setattr__(self, "expected_receipt_checksum", normalized_expected_receipt)
        object.__setattr__(self, "replayed_receipt_checksum", normalized_replayed_receipt)
        object.__setattr__(self, "mapping_checksum_match", normalized_mapping_match)
        object.__setattr__(self, "runtime_target_checksum_match", normalized_runtime_match)
        object.__setattr__(self, "qos_checksum_match", normalized_qos_match)
        object.__setattr__(self, "namespace_match", normalized_namespace_match)
        object.__setattr__(self, "receipt_chain_match", normalized_receipt_chain_match)
        object.__setattr__(self, "mutation_detected", normalized_mutation)
        object.__setattr__(self, "failure_stage", normalized_failure_stage)
        object.__setattr__(self, "proof_checksum", normalized_checksum)


def adapter_replay_source_pipeline_checksum(pipeline_result: PipelineResult) -> str:
    """Return a deterministic source checksum for replay-relevant pipeline evidence."""
    admission = pipeline_result.policy_admission
    return _sha256(
        {
            "outcome": pipeline_result.outcome.value,
            "pipeline_receipt_checksum": (
                pipeline_result.approval_receipt.approval_receipt_checksum
                if pipeline_result.approval_receipt is not None
                else None
            ),
            "decision_trace_checksum": (
                pipeline_result.decision_trace.trace_checksum
                if pipeline_result.decision_trace is not None
                else None
            ),
            "audited_plan_id": (
                pipeline_result.audited_plan.audit_id
                if pipeline_result.audited_plan is not None
                else None
            ),
            "plan_checksum": (
                pipeline_result.audited_plan.checksum
                if pipeline_result.audited_plan is not None
                else None
            ),
            "policy_id": admission.policy_id,
            "policy_version": admission.policy_version,
            "policy_schema_version": admission.policy_schema_version,
            "policy_checksum": admission.policy_checksum,
            "policy_result_checksum": admission.policy_result_checksum,
            "safety_case_id": admission.safety_case_id,
            "context_authority_checksum": admission.context_authority_checksum,
            "world_snapshot_checksum": admission.world_snapshot_checksum,
            "world_snapshot_admissibility_result_checksum": (
                admission.world_snapshot_admissibility_result_checksum
            ),
            "freshness_result_checksum": admission.freshness_result_checksum,
            "world_snapshot_trust_result_checksum": admission.world_snapshot_trust_result_checksum,
            "capability_name": admission.capability_name,
        }
    )


def adapter_replay_proof_checksum(
    *,
    status: AdapterReplayProofStatus,
    reason: str,
    source_pipeline_checksum: str,
    expected_envelope_checksum: str | None,
    replayed_envelope_checksum: str | None,
    expected_receipt_checksum: str | None,
    replayed_receipt_checksum: str | None,
    mapping_checksum_match: bool,
    runtime_target_checksum_match: bool,
    qos_checksum_match: bool,
    namespace_match: bool,
    receipt_chain_match: bool,
    mutation_detected: bool,
    failure_stage: str | None,
) -> str:
    """Return the deterministic checksum for an adapter replay proof result."""
    return _sha256(
        {
            "status": status,
            "reason": reason,
            "source_pipeline_checksum": source_pipeline_checksum,
            "expected_envelope_checksum": expected_envelope_checksum,
            "replayed_envelope_checksum": replayed_envelope_checksum,
            "expected_receipt_checksum": expected_receipt_checksum,
            "replayed_receipt_checksum": replayed_receipt_checksum,
            "mapping_checksum_match": mapping_checksum_match,
            "runtime_target_checksum_match": runtime_target_checksum_match,
            "qos_checksum_match": qos_checksum_match,
            "namespace_match": namespace_match,
            "receipt_chain_match": receipt_chain_match,
            "mutation_detected": mutation_detected,
            "failure_stage": failure_stage,
        }
    )


def recompute_adapter_replay_proof_checksum(result: AdapterReplayProofResult) -> str:
    """Recompute an AdapterReplayProofResult checksum from authoritative fields."""
    return adapter_replay_proof_checksum(
        status=result.status,
        reason=result.reason,
        source_pipeline_checksum=result.source_pipeline_checksum,
        expected_envelope_checksum=result.expected_envelope_checksum,
        replayed_envelope_checksum=result.replayed_envelope_checksum,
        expected_receipt_checksum=result.expected_receipt_checksum,
        replayed_receipt_checksum=result.replayed_receipt_checksum,
        mapping_checksum_match=result.mapping_checksum_match,
        runtime_target_checksum_match=result.runtime_target_checksum_match,
        qos_checksum_match=result.qos_checksum_match,
        namespace_match=result.namespace_match,
        receipt_chain_match=result.receipt_chain_match,
        mutation_detected=result.mutation_detected,
        failure_stage=result.failure_stage,
    )


def _normalize_replay_profile(value: object) -> AdapterReplayProfile:
    if isinstance(value, AdapterReplayProfile):
        return value
    if isinstance(value, str):
        try:
            return AdapterReplayProfile(value)
        except ValueError as exc:
            raise ValueError("replay_profile must be STRICT_ADAPTER_REPLAY_V1") from exc
    raise ValueError("replay_profile must be an AdapterReplayProfile")


def _normalize_mutation_profile(value: object) -> AdapterReplayMutationProfile:
    if isinstance(value, AdapterReplayMutationProfile):
        return value
    if isinstance(value, str):
        try:
            return AdapterReplayMutationProfile(value)
        except ValueError as exc:
            raise ValueError(
                "mutation_profile must be a known AdapterReplayMutationProfile"
            ) from exc
    raise ValueError("mutation_profile must be an AdapterReplayMutationProfile")


def _normalize_status(value: object) -> AdapterReplayProofStatus:
    if value in {"PASSED", "FAILED", "BLOCKED"}:
        return cast(AdapterReplayProofStatus, value)
    raise ValueError("status must be PASSED, FAILED, or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason must be an uppercase machine reason code")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must be ASCII") from exc
    return normalized


def _normalize_optional_stage(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = _normalize_required_text(value, field_name)
    if not normalized.islower() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a lowercase machine stage")
    return normalized


def _normalize_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool")
    return value


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if len(normalized) != 64 or not all(
        character in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    normalized = _normalize_optional_checksum(supplied_checksum, field_name)
    if normalized is None:
        return computed_checksum
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


def _validate_passed_result(
    *,
    expected_envelope_checksum: str | None,
    replayed_envelope_checksum: str | None,
    expected_receipt_checksum: str | None,
    replayed_receipt_checksum: str | None,
    mapping_checksum_match: bool,
    runtime_target_checksum_match: bool,
    qos_checksum_match: bool,
    namespace_match: bool,
    receipt_chain_match: bool,
    mutation_detected: bool,
    failure_stage: str | None,
) -> None:
    if (
        expected_envelope_checksum is None
        or replayed_envelope_checksum is None
        or expected_receipt_checksum is None
        or replayed_receipt_checksum is None
    ):
        raise ValueError("PASSED replay proofs require all proof-critical checksums")
    if not all(
        (
            mapping_checksum_match,
            runtime_target_checksum_match,
            qos_checksum_match,
            namespace_match,
            receipt_chain_match,
        )
    ):
        raise ValueError("PASSED replay proofs require every sub-check to match")
    if mutation_detected:
        raise ValueError("PASSED replay proofs must not mark mutation_detected")
    if failure_stage is not None:
        raise ValueError("PASSED replay proofs must not include failure_stage")


def _sha256(payload: Mapping[str, CanonicalAdapterReplayValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalAdapterReplayValue],
) -> dict[str, CanonicalAdapterReplayValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalAdapterReplayValue) -> CanonicalAdapterReplayValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalAdapterReplayValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "AdapterReplayMutationProfile",
    "AdapterReplayProfile",
    "AdapterReplayProofResult",
    "AdapterReplayProofStatus",
    "AdapterReplayRequest",
    "adapter_replay_proof_checksum",
    "adapter_replay_source_pipeline_checksum",
    "recompute_adapter_replay_proof_checksum",
]
