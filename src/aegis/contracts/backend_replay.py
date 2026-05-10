"""Backend replay proof contracts for ADR-0019."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from aegis.constants import BACKEND_REPLAY_CONTRACT_VERSION, MAX_ADAPTER_STRING_LENGTH
from aegis.contracts.runtime_backend import (
    BackendCertificationResult,
    BackendDryRunReceipt,
    RuntimeBackendDescriptor,
)
from aegis.contracts.runtime_dispatch import DispatchFirewallDecision, RuntimeDispatchPlan

type BackendReplayProofStatus = Literal["PASSED", "FAILED", "BLOCKED"]
type CanonicalBackendReplayValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalBackendReplayValue]
    | dict[str, CanonicalBackendReplayValue]
)


class BackendReplayProfile(StrEnum):
    """Supported deterministic backend replay profiles."""

    STRICT_BACKEND_REPLAY_V1 = "STRICT_BACKEND_REPLAY_V1"


class BackendReplayMutationProfile(StrEnum):
    """Closed set of ADR-0019 backend replay mutation profiles."""

    NONE = "NONE"
    DISPATCH_PLAN_CHECKSUM_DRIFT = "DISPATCH_PLAN_CHECKSUM_DRIFT"
    FIREWALL_DECISION_CHECKSUM_DRIFT = "FIREWALL_DECISION_CHECKSUM_DRIFT"
    BACKEND_DESCRIPTOR_CHECKSUM_DRIFT = "BACKEND_DESCRIPTOR_CHECKSUM_DRIFT"
    BACKEND_KIND_DRIFT = "BACKEND_KIND_DRIFT"
    BACKEND_MODE_DRIFT = "BACKEND_MODE_DRIFT"
    EXECUTION_FLAG_DRIFT = "EXECUTION_FLAG_DRIFT"
    IO_FLAG_DRIFT = "IO_FLAG_DRIFT"
    ASYNC_FLAG_DRIFT = "ASYNC_FLAG_DRIFT"
    CAPABILITY_SCOPE_DRIFT = "CAPABILITY_SCOPE_DRIFT"
    RUNTIME_KIND_SCOPE_DRIFT = "RUNTIME_KIND_SCOPE_DRIFT"
    CERTIFICATION_CHECKSUM_DRIFT = "CERTIFICATION_CHECKSUM_DRIFT"
    RECEIPT_CHECKSUM_DRIFT = "RECEIPT_CHECKSUM_DRIFT"
    RECEIPT_EXECUTED_COUNT_DRIFT = "RECEIPT_EXECUTED_COUNT_DRIFT"
    RECEIPT_ITEM_COUNT_DRIFT = "RECEIPT_ITEM_COUNT_DRIFT"
    RECEIPT_PLAN_LINK_DRIFT = "RECEIPT_PLAN_LINK_DRIFT"
    CERTIFICATION_FIREWALL_LINK_DRIFT = "CERTIFICATION_FIREWALL_LINK_DRIFT"
    CROSS_PLAN_CERTIFICATION_SWAP = "CROSS_PLAN_CERTIFICATION_SWAP"
    CROSS_BACKEND_RECEIPT_SWAP = "CROSS_BACKEND_RECEIPT_SWAP"
    RUNTIME_OBJECT_INJECTION = "RUNTIME_OBJECT_INJECTION"
    CALLABLE_CLIENT_INJECTION = "CALLABLE_CLIENT_INJECTION"
    MUTABLE_BACKEND_DESCRIPTOR_INJECTION = "MUTABLE_BACKEND_DESCRIPTOR_INJECTION"


class BackendReplayReason(StrEnum):
    """Stable reason codes emitted by ADR-0019 backend replay proofs."""

    BACKEND_REPLAY_PASSED = "BACKEND_REPLAY_PASSED"
    BACKEND_REPLAY_INVALID_PROFILE = "BACKEND_REPLAY_INVALID_PROFILE"
    BACKEND_REPLAY_INVALID_DISPATCH_PLAN = "BACKEND_REPLAY_INVALID_DISPATCH_PLAN"
    BACKEND_REPLAY_INVALID_FIREWALL_DECISION = "BACKEND_REPLAY_INVALID_FIREWALL_DECISION"
    BACKEND_REPLAY_INVALID_BACKEND_DESCRIPTOR = "BACKEND_REPLAY_INVALID_BACKEND_DESCRIPTOR"
    BACKEND_REPLAY_INVALID_CERTIFICATION = "BACKEND_REPLAY_INVALID_CERTIFICATION"
    BACKEND_REPLAY_INVALID_RECEIPT = "BACKEND_REPLAY_INVALID_RECEIPT"
    BACKEND_REPLAY_DISPATCH_PLAN_CHECKSUM_DRIFT = "BACKEND_REPLAY_DISPATCH_PLAN_CHECKSUM_DRIFT"
    BACKEND_REPLAY_FIREWALL_DECISION_NOT_ALLOWED = "BACKEND_REPLAY_FIREWALL_DECISION_NOT_ALLOWED"
    BACKEND_REPLAY_FIREWALL_DECISION_CHECKSUM_DRIFT = (
        "BACKEND_REPLAY_FIREWALL_DECISION_CHECKSUM_DRIFT"
    )
    BACKEND_REPLAY_FIREWALL_PLAN_MISMATCH = "BACKEND_REPLAY_FIREWALL_PLAN_MISMATCH"
    BACKEND_REPLAY_DESCRIPTOR_CHECKSUM_DRIFT = "BACKEND_REPLAY_DESCRIPTOR_CHECKSUM_DRIFT"
    BACKEND_REPLAY_DESCRIPTOR_SHAPE_MISMATCH = "BACKEND_REPLAY_DESCRIPTOR_SHAPE_MISMATCH"
    BACKEND_REPLAY_BACKEND_KIND_NOT_NULL = "BACKEND_REPLAY_BACKEND_KIND_NOT_NULL"
    BACKEND_REPLAY_BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY = (
        "BACKEND_REPLAY_BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY"
    )
    BACKEND_REPLAY_EXECUTION_CAPABILITY_CLAIMED = "BACKEND_REPLAY_EXECUTION_CAPABILITY_CLAIMED"
    BACKEND_REPLAY_IO_CAPABILITY_CLAIMED = "BACKEND_REPLAY_IO_CAPABILITY_CLAIMED"
    BACKEND_REPLAY_ASYNC_CAPABILITY_CLAIMED = "BACKEND_REPLAY_ASYNC_CAPABILITY_CLAIMED"
    BACKEND_REPLAY_CAPABILITY_SCOPE_DRIFT = "BACKEND_REPLAY_CAPABILITY_SCOPE_DRIFT"
    BACKEND_REPLAY_RUNTIME_KIND_SCOPE_DRIFT = "BACKEND_REPLAY_RUNTIME_KIND_SCOPE_DRIFT"
    BACKEND_REPLAY_EXPECTED_CERTIFICATION_NOT_CERTIFIED_NULL = (
        "BACKEND_REPLAY_EXPECTED_CERTIFICATION_NOT_CERTIFIED_NULL"
    )
    BACKEND_REPLAY_CERTIFICATION_CHECKSUM_DRIFT = "BACKEND_REPLAY_CERTIFICATION_CHECKSUM_DRIFT"
    BACKEND_REPLAY_CERTIFICATION_DISPATCH_PLAN_MISMATCH = (
        "BACKEND_REPLAY_CERTIFICATION_DISPATCH_PLAN_MISMATCH"
    )
    BACKEND_REPLAY_CERTIFICATION_FIREWALL_DECISION_MISMATCH = (
        "BACKEND_REPLAY_CERTIFICATION_FIREWALL_DECISION_MISMATCH"
    )
    BACKEND_REPLAY_CERTIFICATION_DESCRIPTOR_MISMATCH = (
        "BACKEND_REPLAY_CERTIFICATION_DESCRIPTOR_MISMATCH"
    )
    BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO = "BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO"
    BACKEND_REPLAY_RECEIPT_CHECKSUM_DRIFT = "BACKEND_REPLAY_RECEIPT_CHECKSUM_DRIFT"
    BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT = "BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT"
    BACKEND_REPLAY_RECEIPT_PLAN_MISMATCH = "BACKEND_REPLAY_RECEIPT_PLAN_MISMATCH"
    BACKEND_REPLAY_RECEIPT_FIREWALL_DECISION_MISMATCH = (
        "BACKEND_REPLAY_RECEIPT_FIREWALL_DECISION_MISMATCH"
    )
    BACKEND_REPLAY_RECEIPT_CERTIFICATION_MISMATCH = "BACKEND_REPLAY_RECEIPT_CERTIFICATION_MISMATCH"
    BACKEND_REPLAY_RECEIPT_BACKEND_DESCRIPTOR_MISMATCH = (
        "BACKEND_REPLAY_RECEIPT_BACKEND_DESCRIPTOR_MISMATCH"
    )
    BACKEND_REPLAY_CERTIFICATION_MISMATCH = "BACKEND_REPLAY_CERTIFICATION_MISMATCH"
    BACKEND_REPLAY_RECEIPT_MISMATCH = "BACKEND_REPLAY_RECEIPT_MISMATCH"
    BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION = "BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION"
    BACKEND_REPLAY_REPLAY_BLOCKED = "BACKEND_REPLAY_REPLAY_BLOCKED"


@dataclass(frozen=True, slots=True, init=False)
class BackendReplayRequest:
    """Immutable request to replay backend certification and dry-run receipt evidence."""

    dispatch_plan: RuntimeDispatchPlan
    firewall_decision: DispatchFirewallDecision
    backend_descriptor: RuntimeBackendDescriptor
    expected_certification: BackendCertificationResult
    expected_receipt: BackendDryRunReceipt
    replay_profile: BackendReplayProfile
    mutation_profile: BackendReplayMutationProfile

    def __init__(
        self,
        *,
        dispatch_plan: object,
        firewall_decision: object,
        backend_descriptor: object,
        expected_certification: object,
        expected_receipt: object,
        replay_profile: object = BackendReplayProfile.STRICT_BACKEND_REPLAY_V1,
        mutation_profile: object = BackendReplayMutationProfile.NONE,
    ) -> None:
        if not isinstance(dispatch_plan, RuntimeDispatchPlan):
            raise ValueError("dispatch_plan must be a RuntimeDispatchPlan")
        if not isinstance(firewall_decision, DispatchFirewallDecision):
            raise ValueError("firewall_decision must be a DispatchFirewallDecision")
        if not isinstance(backend_descriptor, RuntimeBackendDescriptor):
            raise ValueError("backend_descriptor must be a RuntimeBackendDescriptor")
        if not isinstance(expected_certification, BackendCertificationResult):
            raise ValueError("expected_certification must be a BackendCertificationResult")
        if not isinstance(expected_receipt, BackendDryRunReceipt):
            raise ValueError("expected_receipt must be a BackendDryRunReceipt")
        object.__setattr__(self, "dispatch_plan", dispatch_plan)
        object.__setattr__(self, "firewall_decision", firewall_decision)
        object.__setattr__(self, "backend_descriptor", backend_descriptor)
        object.__setattr__(self, "expected_certification", expected_certification)
        object.__setattr__(self, "expected_receipt", expected_receipt)
        object.__setattr__(self, "replay_profile", _normalize_replay_profile(replay_profile))
        object.__setattr__(self, "mutation_profile", _normalize_mutation_profile(mutation_profile))


@dataclass(frozen=True, slots=True, init=False)
class BackendReplayProofResult:
    """Checksum-bound result of deterministic backend replay proof."""

    status: BackendReplayProofStatus
    reason_code: str
    dispatch_plan_checksum: str
    firewall_decision_checksum: str
    backend_descriptor_checksum: str
    expected_certification_checksum: str
    replayed_certification_checksum: str | None
    expected_receipt_checksum: str
    replayed_receipt_checksum: str | None
    zero_execution_verified: bool
    scope_match_verified: bool
    certification_match: bool
    receipt_match: bool
    mutation_detected: bool
    failure_stage: str | None
    proof_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        dispatch_plan_checksum: object,
        firewall_decision_checksum: object,
        backend_descriptor_checksum: object,
        expected_certification_checksum: object,
        replayed_certification_checksum: str | None,
        expected_receipt_checksum: object,
        replayed_receipt_checksum: str | None,
        zero_execution_verified: object,
        scope_match_verified: object,
        certification_match: object,
        receipt_match: object,
        mutation_detected: object,
        failure_stage: str | None,
        proof_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_dispatch_plan = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_firewall = _normalize_required_checksum(
            firewall_decision_checksum, "firewall_decision_checksum"
        )
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_expected_certification = _normalize_required_checksum(
            expected_certification_checksum, "expected_certification_checksum"
        )
        normalized_replayed_certification = _normalize_optional_checksum(
            replayed_certification_checksum, "replayed_certification_checksum"
        )
        normalized_expected_receipt = _normalize_required_checksum(
            expected_receipt_checksum, "expected_receipt_checksum"
        )
        normalized_replayed_receipt = _normalize_optional_checksum(
            replayed_receipt_checksum, "replayed_receipt_checksum"
        )
        normalized_zero_execution = _normalize_bool(
            zero_execution_verified, "zero_execution_verified"
        )
        normalized_scope = _normalize_bool(scope_match_verified, "scope_match_verified")
        normalized_certification = _normalize_bool(certification_match, "certification_match")
        normalized_receipt = _normalize_bool(receipt_match, "receipt_match")
        normalized_mutation = _normalize_bool(mutation_detected, "mutation_detected")
        normalized_failure_stage = _normalize_optional_stage(failure_stage, "failure_stage")
        if normalized_status == "PASSED":
            _validate_passed_result(
                expected_certification_checksum=normalized_expected_certification,
                replayed_certification_checksum=normalized_replayed_certification,
                expected_receipt_checksum=normalized_expected_receipt,
                replayed_receipt_checksum=normalized_replayed_receipt,
                zero_execution_verified=normalized_zero_execution,
                scope_match_verified=normalized_scope,
                certification_match=normalized_certification,
                receipt_match=normalized_receipt,
                mutation_detected=normalized_mutation,
                failure_stage=normalized_failure_stage,
            )
        computed_checksum = backend_replay_proof_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            dispatch_plan_checksum=normalized_dispatch_plan,
            firewall_decision_checksum=normalized_firewall,
            backend_descriptor_checksum=normalized_descriptor,
            expected_certification_checksum=normalized_expected_certification,
            replayed_certification_checksum=normalized_replayed_certification,
            expected_receipt_checksum=normalized_expected_receipt,
            replayed_receipt_checksum=normalized_replayed_receipt,
            zero_execution_verified=normalized_zero_execution,
            scope_match_verified=normalized_scope,
            certification_match=normalized_certification,
            receipt_match=normalized_receipt,
            mutation_detected=normalized_mutation,
            failure_stage=normalized_failure_stage,
        )
        normalized_checksum = _normalize_supplied_checksum(
            proof_checksum, computed_checksum, "proof_checksum"
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_dispatch_plan)
        object.__setattr__(self, "firewall_decision_checksum", normalized_firewall)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(
            self, "expected_certification_checksum", normalized_expected_certification
        )
        object.__setattr__(
            self, "replayed_certification_checksum", normalized_replayed_certification
        )
        object.__setattr__(self, "expected_receipt_checksum", normalized_expected_receipt)
        object.__setattr__(self, "replayed_receipt_checksum", normalized_replayed_receipt)
        object.__setattr__(self, "zero_execution_verified", normalized_zero_execution)
        object.__setattr__(self, "scope_match_verified", normalized_scope)
        object.__setattr__(self, "certification_match", normalized_certification)
        object.__setattr__(self, "receipt_match", normalized_receipt)
        object.__setattr__(self, "mutation_detected", normalized_mutation)
        object.__setattr__(self, "failure_stage", normalized_failure_stage)
        object.__setattr__(self, "proof_checksum", normalized_checksum)


def backend_replay_request_source_checksum(request: BackendReplayRequest) -> str:
    """Return a deterministic checksum over replay request authority fields."""
    return _sha256(
        {
            "backend_replay_contract_version": BACKEND_REPLAY_CONTRACT_VERSION,
            "dispatch_plan_checksum": request.dispatch_plan.plan_checksum,
            "firewall_decision_checksum": request.firewall_decision.decision_checksum,
            "backend_descriptor_checksum": request.backend_descriptor.descriptor_checksum,
            "expected_certification_checksum": (
                request.expected_certification.certification_checksum
            ),
            "expected_receipt_checksum": request.expected_receipt.receipt_checksum,
            "replay_profile": request.replay_profile.value,
            "mutation_profile": request.mutation_profile.value,
        }
    )


def backend_replay_proof_checksum(
    *,
    status: BackendReplayProofStatus,
    reason_code: str,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    backend_descriptor_checksum: str,
    expected_certification_checksum: str,
    replayed_certification_checksum: str | None,
    expected_receipt_checksum: str,
    replayed_receipt_checksum: str | None,
    zero_execution_verified: bool,
    scope_match_verified: bool,
    certification_match: bool,
    receipt_match: bool,
    mutation_detected: bool,
    failure_stage: str | None,
) -> str:
    """Return the deterministic checksum for a backend replay proof result."""
    return _sha256(
        {
            "backend_replay_contract_version": BACKEND_REPLAY_CONTRACT_VERSION,
            "status": status,
            "reason_code": reason_code,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "expected_certification_checksum": expected_certification_checksum,
            "replayed_certification_checksum": replayed_certification_checksum,
            "expected_receipt_checksum": expected_receipt_checksum,
            "replayed_receipt_checksum": replayed_receipt_checksum,
            "zero_execution_verified": zero_execution_verified,
            "scope_match_verified": scope_match_verified,
            "certification_match": certification_match,
            "receipt_match": receipt_match,
            "mutation_detected": mutation_detected,
            "failure_stage": failure_stage,
        }
    )


def recompute_backend_replay_proof_checksum(result: BackendReplayProofResult) -> str:
    """Recompute a BackendReplayProofResult checksum from authoritative fields."""
    return backend_replay_proof_checksum(
        status=result.status,
        reason_code=result.reason_code,
        dispatch_plan_checksum=result.dispatch_plan_checksum,
        firewall_decision_checksum=result.firewall_decision_checksum,
        backend_descriptor_checksum=result.backend_descriptor_checksum,
        expected_certification_checksum=result.expected_certification_checksum,
        replayed_certification_checksum=result.replayed_certification_checksum,
        expected_receipt_checksum=result.expected_receipt_checksum,
        replayed_receipt_checksum=result.replayed_receipt_checksum,
        zero_execution_verified=result.zero_execution_verified,
        scope_match_verified=result.scope_match_verified,
        certification_match=result.certification_match,
        receipt_match=result.receipt_match,
        mutation_detected=result.mutation_detected,
        failure_stage=result.failure_stage,
    )


def _normalize_replay_profile(value: object) -> BackendReplayProfile:
    if isinstance(value, BackendReplayProfile):
        return value
    if isinstance(value, str):
        try:
            return BackendReplayProfile(value)
        except ValueError as exc:
            raise ValueError("replay_profile must be STRICT_BACKEND_REPLAY_V1") from exc
    raise ValueError("replay_profile must be a BackendReplayProfile")


def _normalize_mutation_profile(value: object) -> BackendReplayMutationProfile:
    if isinstance(value, BackendReplayMutationProfile):
        return value
    if isinstance(value, str):
        try:
            return BackendReplayMutationProfile(value)
        except ValueError as exc:
            raise ValueError(
                "mutation_profile must be a known BackendReplayMutationProfile"
            ) from exc
    raise ValueError("mutation_profile must be a BackendReplayMutationProfile")


def _normalize_status(value: object) -> BackendReplayProofStatus:
    if value in {"PASSED", "FAILED", "BLOCKED"}:
        return cast(BackendReplayProofStatus, value)
    raise ValueError("status must be PASSED, FAILED, or BLOCKED")


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(f"{field_name} must not be callable")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    if len(normalized) > MAX_ADAPTER_STRING_LENGTH:
        raise ValueError(f"{field_name} exceeds max adapter string length")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must be ASCII") from exc
    if any(character.isspace() for character in normalized):
        raise ValueError(f"{field_name} must not contain whitespace")
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
    expected_certification_checksum: str,
    replayed_certification_checksum: str | None,
    expected_receipt_checksum: str,
    replayed_receipt_checksum: str | None,
    zero_execution_verified: bool,
    scope_match_verified: bool,
    certification_match: bool,
    receipt_match: bool,
    mutation_detected: bool,
    failure_stage: str | None,
) -> None:
    if replayed_certification_checksum is None or replayed_receipt_checksum is None:
        raise ValueError("PASSED backend replay proofs require replayed checksums")
    if expected_certification_checksum != replayed_certification_checksum:
        raise ValueError("PASSED backend replay proofs require exact certification match")
    if expected_receipt_checksum != replayed_receipt_checksum:
        raise ValueError("PASSED backend replay proofs require exact receipt match")
    if not all((zero_execution_verified, scope_match_verified, certification_match, receipt_match)):
        raise ValueError("PASSED backend replay proofs require every sub-check to match")
    if mutation_detected:
        raise ValueError("PASSED backend replay proofs must not mark mutation_detected")
    if failure_stage is not None:
        raise ValueError("PASSED backend replay proofs must not include failure_stage")


def _sha256(payload: Mapping[str, CanonicalBackendReplayValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalBackendReplayValue],
) -> dict[str, CanonicalBackendReplayValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalBackendReplayValue) -> CanonicalBackendReplayValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalBackendReplayValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "BackendReplayMutationProfile",
    "BackendReplayProfile",
    "BackendReplayProofResult",
    "BackendReplayProofStatus",
    "BackendReplayReason",
    "BackendReplayRequest",
    "backend_replay_proof_checksum",
    "backend_replay_request_source_checksum",
    "recompute_backend_replay_proof_checksum",
]
