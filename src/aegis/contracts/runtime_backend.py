"""Runtime backend interface and null certification contracts for ADR-0018."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Literal, Protocol, cast

from aegis.constants import MAX_ADAPTER_STRING_LENGTH, RUNTIME_BACKEND_CONTRACT_VERSION
from aegis.contracts.runtime_dispatch import RuntimeDispatchItem, RuntimeDispatchKind

type BackendCertificationStatusValue = Literal["CERTIFIED_NULL", "BLOCKED"]
type CanonicalRuntimeBackendValue = (
    str
    | int
    | float
    | bool
    | None
    | list[CanonicalRuntimeBackendValue]
    | dict[str, CanonicalRuntimeBackendValue]
)


class RuntimeBackendKind(StrEnum):
    """Backend kinds admitted by ADR-0018."""

    NULL_BACKEND_V1 = "NULL_BACKEND_V1"


class RuntimeBackendMode(StrEnum):
    """Backend modes admitted by ADR-0018."""

    DRY_RUN_CERTIFICATION_ONLY = "DRY_RUN_CERTIFICATION_ONLY"


class BackendCertificationStatus(StrEnum):
    """Stable ADR-0018 backend certification states."""

    CERTIFIED_NULL = "CERTIFIED_NULL"
    BLOCKED = "BLOCKED"


class BackendCertificationReason(StrEnum):
    """Stable reason codes for backend certification and receipt validation."""

    BACKEND_CERTIFIED_NULL = "BACKEND_CERTIFIED_NULL"
    BACKEND_FIREWALL_DECISION_NOT_ALLOWED = "BACKEND_FIREWALL_DECISION_NOT_ALLOWED"
    BACKEND_DISPATCH_MODE_NOT_DRY_RUN_ONLY = "BACKEND_DISPATCH_MODE_NOT_DRY_RUN_ONLY"
    BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH = "BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH"
    BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH = "BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH"
    BACKEND_FIREWALL_PLAN_MISMATCH = "BACKEND_FIREWALL_PLAN_MISMATCH"
    BACKEND_UNSUPPORTED_IMPLEMENTATION = "BACKEND_UNSUPPORTED_IMPLEMENTATION"
    BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH = "BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH"
    BACKEND_KIND_NOT_NULL = "BACKEND_KIND_NOT_NULL"
    BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY = "BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY"
    BACKEND_EXECUTION_CAPABILITY_CLAIMED = "BACKEND_EXECUTION_CAPABILITY_CLAIMED"
    BACKEND_IO_CAPABILITY_CLAIMED = "BACKEND_IO_CAPABILITY_CLAIMED"
    BACKEND_ASYNC_CAPABILITY_CLAIMED = "BACKEND_ASYNC_CAPABILITY_CLAIMED"
    BACKEND_RUNTIME_OBJECT_INJECTION = "BACKEND_RUNTIME_OBJECT_INJECTION"
    BACKEND_CAPABILITY_SCOPE_DRIFT = "BACKEND_CAPABILITY_SCOPE_DRIFT"
    BACKEND_RUNTIME_KIND_SCOPE_DRIFT = "BACKEND_RUNTIME_KIND_SCOPE_DRIFT"
    BACKEND_CERTIFICATION_CHECKSUM_DRIFT = "BACKEND_CERTIFICATION_CHECKSUM_DRIFT"
    BACKEND_RECEIPT_EXECUTED_COUNT_NONZERO = "BACKEND_RECEIPT_EXECUTED_COUNT_NONZERO"
    BACKEND_RECEIPT_CHECKSUM_MISMATCH = "BACKEND_RECEIPT_CHECKSUM_MISMATCH"


class RuntimeBackendContract(Protocol):
    """Descriptor-only runtime backend interface for future integrations."""

    @property
    def descriptor(self) -> RuntimeBackendDescriptor:
        """Return immutable backend identity and declared scope evidence."""
        ...


@dataclass(frozen=True, slots=True, init=False)
class RuntimeBackendDescriptor:
    """Immutable backend identity, scope, and non-execution declaration."""

    backend_id: str
    backend_kind: RuntimeBackendKind
    backend_mode: RuntimeBackendMode
    supported_runtime_kinds: frozenset[RuntimeDispatchKind]
    supported_capabilities: frozenset[str]
    allows_execution: bool
    allows_io: bool
    allows_async: bool
    descriptor_checksum: str

    def __init__(
        self,
        *,
        backend_id: object,
        backend_kind: object,
        backend_mode: object,
        supported_runtime_kinds: Iterable[object],
        supported_capabilities: Iterable[object],
        allows_execution: object,
        allows_io: object,
        allows_async: object,
        descriptor_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_identifier(backend_id, "backend_id")
        normalized_kind = _normalize_backend_kind(backend_kind)
        normalized_mode = _normalize_backend_mode(backend_mode)
        normalized_runtime_kinds = _normalize_runtime_kind_scope(supported_runtime_kinds)
        normalized_capabilities = _normalize_capability_scope(supported_capabilities)
        normalized_execution = _normalize_bool(allows_execution, "allows_execution")
        normalized_io = _normalize_bool(allows_io, "allows_io")
        normalized_async = _normalize_bool(allows_async, "allows_async")
        computed_checksum = runtime_backend_descriptor_checksum(
            backend_id=normalized_id,
            backend_kind=normalized_kind,
            backend_mode=normalized_mode,
            supported_runtime_kinds=normalized_runtime_kinds,
            supported_capabilities=normalized_capabilities,
            allows_execution=normalized_execution,
            allows_io=normalized_io,
            allows_async=normalized_async,
        )
        normalized_checksum = _normalize_supplied_checksum(
            descriptor_checksum,
            computed_checksum,
            "descriptor_checksum",
        )

        object.__setattr__(self, "backend_id", normalized_id)
        object.__setattr__(self, "backend_kind", normalized_kind)
        object.__setattr__(self, "backend_mode", normalized_mode)
        object.__setattr__(self, "supported_runtime_kinds", normalized_runtime_kinds)
        object.__setattr__(self, "supported_capabilities", normalized_capabilities)
        object.__setattr__(self, "allows_execution", normalized_execution)
        object.__setattr__(self, "allows_io", normalized_io)
        object.__setattr__(self, "allows_async", normalized_async)
        object.__setattr__(self, "descriptor_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class BackendCertificationResult:
    """Checksum-bound result of certifying a runtime backend for one dry-run plan."""

    status: BackendCertificationStatus
    reason_code: str
    dispatch_plan_checksum: str
    firewall_decision_checksum: str
    backend_descriptor_checksum: str
    no_execution_guarantee: bool
    no_io_guarantee: bool
    no_async_guarantee: bool
    capability_scope_match: bool
    runtime_kind_scope_match: bool
    certification_checksum: str

    def __init__(
        self,
        *,
        status: object,
        reason_code: object,
        dispatch_plan_checksum: object,
        firewall_decision_checksum: object,
        backend_descriptor_checksum: object,
        no_execution_guarantee: object,
        no_io_guarantee: object,
        no_async_guarantee: object,
        capability_scope_match: object,
        runtime_kind_scope_match: object,
        certification_checksum: str | None = None,
    ) -> None:
        normalized_status = _normalize_certification_status(status)
        normalized_reason = _normalize_reason(reason_code)
        normalized_plan = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_decision = _normalize_required_checksum(
            firewall_decision_checksum, "firewall_decision_checksum"
        )
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_no_execution = _normalize_bool(no_execution_guarantee, "no_execution_guarantee")
        normalized_no_io = _normalize_bool(no_io_guarantee, "no_io_guarantee")
        normalized_no_async = _normalize_bool(no_async_guarantee, "no_async_guarantee")
        normalized_capability = _normalize_bool(capability_scope_match, "capability_scope_match")
        normalized_runtime_kind = _normalize_bool(
            runtime_kind_scope_match, "runtime_kind_scope_match"
        )
        if normalized_status is BackendCertificationStatus.CERTIFIED_NULL:
            _validate_certified_null_fields(
                reason_code=normalized_reason,
                no_execution_guarantee=normalized_no_execution,
                no_io_guarantee=normalized_no_io,
                no_async_guarantee=normalized_no_async,
                capability_scope_match=normalized_capability,
                runtime_kind_scope_match=normalized_runtime_kind,
            )
        computed_checksum = backend_certification_result_checksum(
            status=normalized_status,
            reason_code=normalized_reason,
            dispatch_plan_checksum=normalized_plan,
            firewall_decision_checksum=normalized_decision,
            backend_descriptor_checksum=normalized_descriptor,
            no_execution_guarantee=normalized_no_execution,
            no_io_guarantee=normalized_no_io,
            no_async_guarantee=normalized_no_async,
            capability_scope_match=normalized_capability,
            runtime_kind_scope_match=normalized_runtime_kind,
        )
        normalized_checksum = _normalize_supplied_checksum(
            certification_checksum,
            computed_checksum,
            "certification_checksum",
        )

        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_code", normalized_reason)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_plan)
        object.__setattr__(self, "firewall_decision_checksum", normalized_decision)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(self, "no_execution_guarantee", normalized_no_execution)
        object.__setattr__(self, "no_io_guarantee", normalized_no_io)
        object.__setattr__(self, "no_async_guarantee", normalized_no_async)
        object.__setattr__(self, "capability_scope_match", normalized_capability)
        object.__setattr__(self, "runtime_kind_scope_match", normalized_runtime_kind)
        object.__setattr__(self, "certification_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class BackendDryRunReceipt:
    """Receipt proving null backend observation without execution."""

    receipt_id: str
    dispatch_plan_checksum: str
    firewall_decision_checksum: str
    backend_certification_checksum: str
    backend_descriptor_checksum: str
    observed_dispatch_items: tuple[str, ...]
    executed_count: int
    blocked_execution_count: int
    receipt_checksum: str

    def __init__(
        self,
        *,
        receipt_id: object,
        dispatch_plan_checksum: object,
        firewall_decision_checksum: object,
        backend_certification_checksum: object,
        backend_descriptor_checksum: object,
        observed_dispatch_items: Iterable[object],
        executed_count: object,
        blocked_execution_count: object,
        receipt_checksum: str | None = None,
    ) -> None:
        normalized_id = _normalize_identifier(receipt_id, "receipt_id")
        normalized_plan = _normalize_required_checksum(
            dispatch_plan_checksum, "dispatch_plan_checksum"
        )
        normalized_decision = _normalize_required_checksum(
            firewall_decision_checksum, "firewall_decision_checksum"
        )
        normalized_certification = _normalize_required_checksum(
            backend_certification_checksum, "backend_certification_checksum"
        )
        normalized_descriptor = _normalize_required_checksum(
            backend_descriptor_checksum, "backend_descriptor_checksum"
        )
        normalized_items = _normalize_observed_dispatch_items(observed_dispatch_items)
        normalized_executed = _normalize_zero_executed_count(executed_count)
        normalized_blocked = _normalize_non_negative_int(
            blocked_execution_count, "blocked_execution_count"
        )
        computed_checksum = backend_dry_run_receipt_checksum(
            receipt_id=normalized_id,
            dispatch_plan_checksum=normalized_plan,
            firewall_decision_checksum=normalized_decision,
            backend_certification_checksum=normalized_certification,
            backend_descriptor_checksum=normalized_descriptor,
            observed_dispatch_items=normalized_items,
            executed_count=normalized_executed,
            blocked_execution_count=normalized_blocked,
        )
        normalized_checksum = _normalize_supplied_checksum(
            receipt_checksum,
            computed_checksum,
            "receipt_checksum",
        )

        object.__setattr__(self, "receipt_id", normalized_id)
        object.__setattr__(self, "dispatch_plan_checksum", normalized_plan)
        object.__setattr__(self, "firewall_decision_checksum", normalized_decision)
        object.__setattr__(self, "backend_certification_checksum", normalized_certification)
        object.__setattr__(self, "backend_descriptor_checksum", normalized_descriptor)
        object.__setattr__(self, "observed_dispatch_items", normalized_items)
        object.__setattr__(self, "executed_count", normalized_executed)
        object.__setattr__(self, "blocked_execution_count", normalized_blocked)
        object.__setattr__(self, "receipt_checksum", normalized_checksum)


def runtime_backend_descriptor_checksum(
    *,
    backend_id: str,
    backend_kind: RuntimeBackendKind,
    backend_mode: RuntimeBackendMode,
    supported_runtime_kinds: Iterable[RuntimeDispatchKind],
    supported_capabilities: Iterable[str],
    allows_execution: bool,
    allows_io: bool,
    allows_async: bool,
) -> str:
    """Return the deterministic checksum for a runtime backend descriptor."""
    return _sha256(
        {
            "runtime_backend_contract_version": RUNTIME_BACKEND_CONTRACT_VERSION,
            "backend_id": backend_id,
            "backend_kind": _backend_kind_checksum_value(backend_kind),
            "backend_mode": _backend_mode_checksum_value(backend_mode),
            "supported_runtime_kinds": _canonical_string_sequence(
                sorted(
                    _runtime_kind_checksum_value(runtime_kind)
                    for runtime_kind in supported_runtime_kinds
                )
            ),
            "supported_capabilities": _canonical_string_sequence(sorted(supported_capabilities)),
            "allows_execution": allows_execution,
            "allows_io": allows_io,
            "allows_async": allows_async,
        }
    )


def backend_certification_result_checksum(
    *,
    status: BackendCertificationStatus,
    reason_code: str,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    backend_descriptor_checksum: str,
    no_execution_guarantee: bool,
    no_io_guarantee: bool,
    no_async_guarantee: bool,
    capability_scope_match: bool,
    runtime_kind_scope_match: bool,
) -> str:
    """Return the deterministic checksum for a backend certification result."""
    return _sha256(
        {
            "runtime_backend_contract_version": RUNTIME_BACKEND_CONTRACT_VERSION,
            "status": _certification_status_checksum_value(status),
            "reason_code": reason_code,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "no_execution_guarantee": no_execution_guarantee,
            "no_io_guarantee": no_io_guarantee,
            "no_async_guarantee": no_async_guarantee,
            "capability_scope_match": capability_scope_match,
            "runtime_kind_scope_match": runtime_kind_scope_match,
        }
    )


def backend_dry_run_receipt_id(
    *,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    backend_certification_checksum: str,
) -> str:
    """Return the deterministic identifier for a backend dry-run receipt."""
    return _sha256(
        {
            "runtime_backend_contract_version": RUNTIME_BACKEND_CONTRACT_VERSION,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "backend_certification_checksum": backend_certification_checksum,
        }
    )


def backend_dry_run_receipt_checksum(
    *,
    receipt_id: str,
    dispatch_plan_checksum: str,
    firewall_decision_checksum: str,
    backend_certification_checksum: str,
    backend_descriptor_checksum: str,
    observed_dispatch_items: Iterable[str],
    executed_count: int,
    blocked_execution_count: int,
) -> str:
    """Return the deterministic checksum for a backend dry-run receipt."""
    return _sha256(
        {
            "runtime_backend_contract_version": RUNTIME_BACKEND_CONTRACT_VERSION,
            "receipt_id": receipt_id,
            "dispatch_plan_checksum": dispatch_plan_checksum,
            "firewall_decision_checksum": firewall_decision_checksum,
            "backend_certification_checksum": backend_certification_checksum,
            "backend_descriptor_checksum": backend_descriptor_checksum,
            "observed_dispatch_items": list(observed_dispatch_items),
            "executed_count": executed_count,
            "blocked_execution_count": blocked_execution_count,
        }
    )


def runtime_backend_observed_dispatch_items(
    dispatch_items: Iterable[RuntimeDispatchItem],
) -> tuple[str, ...]:
    """Return inert observed dispatch item identifiers for backend receipts."""
    return tuple(_observed_dispatch_item_id(item) for item in dispatch_items)


def recompute_runtime_backend_descriptor_checksum(descriptor: RuntimeBackendDescriptor) -> str:
    """Recompute a RuntimeBackendDescriptor checksum from authoritative fields."""
    return runtime_backend_descriptor_checksum(
        backend_id=descriptor.backend_id,
        backend_kind=descriptor.backend_kind,
        backend_mode=descriptor.backend_mode,
        supported_runtime_kinds=descriptor.supported_runtime_kinds,
        supported_capabilities=descriptor.supported_capabilities,
        allows_execution=descriptor.allows_execution,
        allows_io=descriptor.allows_io,
        allows_async=descriptor.allows_async,
    )


def recompute_backend_certification_checksum(result: BackendCertificationResult) -> str:
    """Recompute a BackendCertificationResult checksum from authoritative fields."""
    return backend_certification_result_checksum(
        status=result.status,
        reason_code=result.reason_code,
        dispatch_plan_checksum=result.dispatch_plan_checksum,
        firewall_decision_checksum=result.firewall_decision_checksum,
        backend_descriptor_checksum=result.backend_descriptor_checksum,
        no_execution_guarantee=result.no_execution_guarantee,
        no_io_guarantee=result.no_io_guarantee,
        no_async_guarantee=result.no_async_guarantee,
        capability_scope_match=result.capability_scope_match,
        runtime_kind_scope_match=result.runtime_kind_scope_match,
    )


def recompute_backend_dry_run_receipt_checksum(receipt: BackendDryRunReceipt) -> str:
    """Recompute a BackendDryRunReceipt checksum from authoritative fields."""
    return backend_dry_run_receipt_checksum(
        receipt_id=receipt.receipt_id,
        dispatch_plan_checksum=receipt.dispatch_plan_checksum,
        firewall_decision_checksum=receipt.firewall_decision_checksum,
        backend_certification_checksum=receipt.backend_certification_checksum,
        backend_descriptor_checksum=receipt.backend_descriptor_checksum,
        observed_dispatch_items=receipt.observed_dispatch_items,
        executed_count=receipt.executed_count,
        blocked_execution_count=receipt.blocked_execution_count,
    )


def _validate_certified_null_fields(
    *,
    reason_code: str,
    no_execution_guarantee: bool,
    no_io_guarantee: bool,
    no_async_guarantee: bool,
    capability_scope_match: bool,
    runtime_kind_scope_match: bool,
) -> None:
    if reason_code != BackendCertificationReason.BACKEND_CERTIFIED_NULL.value:
        raise ValueError("CERTIFIED_NULL requires BACKEND_CERTIFIED_NULL reason")
    if not (
        no_execution_guarantee
        and no_io_guarantee
        and no_async_guarantee
        and capability_scope_match
        and runtime_kind_scope_match
    ):
        raise ValueError("CERTIFIED_NULL requires all guarantees and exact scope matches")


def _observed_dispatch_item_id(item: RuntimeDispatchItem) -> str:
    return _sha256(
        {
            "sequence": item.sequence,
            "capability": item.capability,
            "runtime_kind": item.runtime_kind.value,
            "runtime_name": item.runtime_name,
            "namespace": item.namespace,
            "message_type": item.message_type,
            "qos_profile_checksum": item.qos_profile_checksum,
            "payload_checksum": item.payload_checksum,
            "payload_size_bytes": item.payload_size_bytes,
            "field_map_checksum": item.field_map_checksum,
        }
    )


def _normalize_backend_kind(value: object) -> RuntimeBackendKind:
    if isinstance(value, RuntimeBackendKind):
        return value
    if not isinstance(value, str):
        raise ValueError("backend_kind must be a RuntimeBackendKind")
    if value != RuntimeBackendKind.NULL_BACKEND_V1.value:
        raise ValueError(BackendCertificationReason.BACKEND_KIND_NOT_NULL.value)
    return RuntimeBackendKind.NULL_BACKEND_V1


def _normalize_backend_mode(value: object) -> RuntimeBackendMode:
    if isinstance(value, RuntimeBackendMode):
        return value
    if not isinstance(value, str):
        raise ValueError("backend_mode must be a RuntimeBackendMode")
    if value != RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY.value:
        raise ValueError(
            BackendCertificationReason.BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY.value
        )
    return RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY


def _normalize_runtime_kind_scope(
    values: Iterable[object],
) -> frozenset[RuntimeDispatchKind]:
    if isinstance(values, str):
        raise ValueError("supported_runtime_kinds must be an iterable of runtime kinds")
    normalized: set[RuntimeDispatchKind] = set()
    for value in values:
        if callable(value):
            raise ValueError("supported_runtime_kinds must not contain callable values")
        if isinstance(value, RuntimeDispatchKind):
            normalized.add(value)
            continue
        if isinstance(value, str):
            try:
                normalized.add(RuntimeDispatchKind(value))
            except ValueError:
                raise ValueError("supported_runtime_kinds contains an undeclared kind") from None
            continue
        raise ValueError("supported_runtime_kinds must contain RuntimeDispatchKind values")
    if not normalized:
        raise ValueError("supported_runtime_kinds must be non-empty")
    return frozenset(normalized)


def _normalize_capability_scope(values: Iterable[object]) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError("supported_capabilities must be an iterable of capabilities")
    normalized = frozenset(_normalize_capability(value) for value in values)
    if not normalized:
        raise ValueError("supported_capabilities must be non-empty")
    return normalized


def _normalize_observed_dispatch_items(values: Iterable[object]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError("observed_dispatch_items must be an iterable of item checksums")
    normalized = tuple(
        _normalize_required_checksum(value, "observed_dispatch_items") for value in values
    )
    if not normalized:
        raise ValueError("observed_dispatch_items must be non-empty")
    return normalized


def _normalize_zero_executed_count(value: object) -> int:
    normalized = _normalize_non_negative_int(value, "executed_count")
    if normalized != 0:
        raise ValueError(BackendCertificationReason.BACKEND_RECEIPT_EXECUTED_COUNT_NONZERO.value)
    return normalized


def _normalize_certification_status(value: object) -> BackendCertificationStatus:
    if isinstance(value, BackendCertificationStatus):
        return value
    if value in {"CERTIFIED_NULL", "BLOCKED"}:
        return BackendCertificationStatus(cast(BackendCertificationStatusValue, value))
    raise ValueError("status must be CERTIFIED_NULL or BLOCKED")


def _normalize_capability(value: object) -> str:
    normalized = _normalize_required_text(value, "supported_capabilities")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("supported_capabilities must be canonical dotted lowercase identifiers")
    return normalized


def _normalize_identifier(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical backend identifier")
    return normalized


def _normalize_reason(value: object) -> str:
    normalized = _normalize_required_text(value, "reason_code")
    if not normalized.isupper() or not all(
        character.isalnum() or character == "_" for character in normalized
    ):
        raise ValueError("reason_code must be an uppercase machine reason code")
    return normalized


def _normalize_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool")
    return value


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


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


def _normalize_required_checksum(value: object, field_name: str) -> str:
    normalized = _normalize_required_text(value, field_name)
    if len(normalized) != 64 or not all(
        character in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
    return normalized


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_required_checksum(value, field_name)


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


def _backend_kind_checksum_value(value: object) -> str:
    if isinstance(value, RuntimeBackendKind):
        return value.value
    if isinstance(value, str):
        return value
    raise ValueError("backend_kind must be checksum-serializable")


def _backend_mode_checksum_value(value: object) -> str:
    if isinstance(value, RuntimeBackendMode):
        return value.value
    if isinstance(value, str):
        return value
    raise ValueError("backend_mode must be checksum-serializable")


def _runtime_kind_checksum_value(value: object) -> str:
    if isinstance(value, RuntimeDispatchKind):
        return value.value
    if isinstance(value, str):
        return value
    raise ValueError("runtime kind must be checksum-serializable")


def _certification_status_checksum_value(value: object) -> str:
    if isinstance(value, BackendCertificationStatus):
        return value.value
    if isinstance(value, str):
        return value
    raise ValueError("certification status must be checksum-serializable")


def _canonical_string_sequence(values: Iterable[str]) -> list[CanonicalRuntimeBackendValue]:
    return [value for value in values]


def _sha256(payload: Mapping[str, CanonicalRuntimeBackendValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalRuntimeBackendValue],
) -> dict[str, CanonicalRuntimeBackendValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalRuntimeBackendValue) -> CanonicalRuntimeBackendValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalRuntimeBackendValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "BackendCertificationReason",
    "BackendCertificationResult",
    "BackendCertificationStatus",
    "BackendCertificationStatusValue",
    "BackendDryRunReceipt",
    "RuntimeBackendContract",
    "RuntimeBackendDescriptor",
    "RuntimeBackendKind",
    "RuntimeBackendMode",
    "backend_certification_result_checksum",
    "backend_dry_run_receipt_checksum",
    "backend_dry_run_receipt_id",
    "recompute_backend_certification_checksum",
    "recompute_backend_dry_run_receipt_checksum",
    "recompute_runtime_backend_descriptor_checksum",
    "runtime_backend_descriptor_checksum",
    "runtime_backend_observed_dispatch_items",
]
