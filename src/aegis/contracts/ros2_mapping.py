"""Immutable ROS 2 message mapping contracts without ROS dependencies."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from types import MappingProxyType
from typing import cast

from aegis.constants import (
    MAX_ADAPTER_FIELD_COUNT,
    MAX_ADAPTER_FORBIDDEN_FIELD_COUNT,
    MAX_ADAPTER_REQUIRED_FIELD_COUNT,
    MAX_ADAPTER_STRING_LENGTH,
    MAX_ROS2_QOS_DEPTH,
)
from aegis.governance.resource_bounds import validate_resource_bounds

type CanonicalRos2MappingValue = (
    str | int | bool | None | list[CanonicalRos2MappingValue] | dict[str, CanonicalRos2MappingValue]
)

DANGEROUS_RUNTIME_OVERRIDE_FIELDS = frozenset(
    {
        "disable_safety",
        "bypass_policy",
        "force_execute",
        "ignore_collision",
        "unsafe_mode",
        "override_limits",
        "raw_command",
    }
)
"""Runtime fields that must always be declared forbidden by adapter mappings."""


class RuntimeKind(StrEnum):
    """Runtime kinds modelled by Phase 3 Part 1."""

    ROS2 = "ros2"


class Ros2Reliability(StrEnum):
    """ROS 2 reliability policy values represented as inert data."""

    RELIABLE = "reliable"
    BEST_EFFORT = "best_effort"


class Ros2Durability(StrEnum):
    """ROS 2 durability policy values represented as inert data."""

    VOLATILE = "volatile"
    TRANSIENT_LOCAL = "transient_local"


class Ros2History(StrEnum):
    """ROS 2 history policy values represented as inert data."""

    KEEP_LAST = "keep_last"
    KEEP_ALL = "keep_all"


class Ros2Liveliness(StrEnum):
    """ROS 2 liveliness policy values represented as inert data."""

    AUTOMATIC = "automatic"
    MANUAL_BY_TOPIC = "manual_by_topic"


class Ros2CommunicationPrimitive(StrEnum):
    """ROS 2 communication primitive selected by a mapping contract."""

    TOPIC = "topic"
    SERVICE = "service"
    ACTION = "action"


@dataclass(frozen=True, slots=True, init=False)
class RuntimeTarget:
    """Immutable runtime identity evidence for an adapter target.

    The target is not permission. It is checksum-bound identity evidence used
    by the adapter mapping validator.
    """

    runtime_kind: RuntimeKind
    runtime_id: str
    runtime_version: str
    deployment_domain: str
    target_namespace: str
    target_robot_id: str
    runtime_authority: str
    runtime_target_checksum: str

    def __init__(
        self,
        *,
        runtime_kind: object,
        runtime_id: str,
        runtime_version: str,
        deployment_domain: str,
        target_namespace: str,
        target_robot_id: str,
        runtime_authority: str,
        runtime_target_checksum: str | None = None,
    ) -> None:
        normalized_kind = _normalize_runtime_kind(runtime_kind)
        normalized_runtime_id = _normalize_identifier(runtime_id, "runtime_id")
        normalized_runtime_version = _normalize_identifier(runtime_version, "runtime_version")
        normalized_domain = _normalize_identifier(deployment_domain, "deployment_domain")
        normalized_namespace = _normalize_namespace(target_namespace, "target_namespace")
        normalized_robot_id = _normalize_identifier(target_robot_id, "target_robot_id")
        normalized_authority = _normalize_identifier(runtime_authority, "runtime_authority")
        computed_checksum = runtime_target_checksum_value(
            runtime_kind=normalized_kind,
            runtime_id=normalized_runtime_id,
            runtime_version=normalized_runtime_version,
            deployment_domain=normalized_domain,
            target_namespace=normalized_namespace,
            target_robot_id=normalized_robot_id,
            runtime_authority=normalized_authority,
        )
        normalized_checksum = _normalize_supplied_checksum(
            runtime_target_checksum,
            computed_checksum,
            "runtime_target_checksum",
        )

        object.__setattr__(self, "runtime_kind", normalized_kind)
        object.__setattr__(self, "runtime_id", normalized_runtime_id)
        object.__setattr__(self, "runtime_version", normalized_runtime_version)
        object.__setattr__(self, "deployment_domain", normalized_domain)
        object.__setattr__(self, "target_namespace", normalized_namespace)
        object.__setattr__(self, "target_robot_id", normalized_robot_id)
        object.__setattr__(self, "runtime_authority", normalized_authority)
        object.__setattr__(self, "runtime_target_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class Ros2QoSProfileSpec:
    """Immutable ROS 2 QoS profile data with no middleware defaults."""

    reliability: Ros2Reliability
    durability: Ros2Durability
    history: Ros2History
    depth: int | None
    deadline_ms: int | None
    lifespan_ms: int | None
    liveliness: Ros2Liveliness
    lease_duration_ms: int | None
    qos_checksum: str

    def __init__(
        self,
        *,
        reliability: object,
        durability: object,
        history: object,
        depth: object,
        deadline_ms: object,
        lifespan_ms: object,
        liveliness: object,
        lease_duration_ms: object,
        qos_checksum: str | None = None,
    ) -> None:
        normalized_reliability = _normalize_enum(reliability, Ros2Reliability, "reliability")
        normalized_durability = _normalize_enum(durability, Ros2Durability, "durability")
        normalized_history = _normalize_enum(history, Ros2History, "history")
        normalized_depth = _normalize_qos_depth(normalized_history, depth)
        normalized_deadline = _normalize_optional_non_negative_int(deadline_ms, "deadline_ms")
        normalized_lifespan = _normalize_optional_non_negative_int(lifespan_ms, "lifespan_ms")
        normalized_liveliness = _normalize_enum(liveliness, Ros2Liveliness, "liveliness")
        normalized_lease = _normalize_optional_non_negative_int(
            lease_duration_ms, "lease_duration_ms"
        )
        computed_checksum = ros2_qos_profile_checksum(
            reliability=normalized_reliability,
            durability=normalized_durability,
            history=normalized_history,
            depth=normalized_depth,
            deadline_ms=normalized_deadline,
            lifespan_ms=normalized_lifespan,
            liveliness=normalized_liveliness,
            lease_duration_ms=normalized_lease,
        )
        normalized_checksum = _normalize_supplied_checksum(
            qos_checksum, computed_checksum, "qos_checksum"
        )

        object.__setattr__(self, "reliability", normalized_reliability)
        object.__setattr__(self, "durability", normalized_durability)
        object.__setattr__(self, "history", normalized_history)
        object.__setattr__(self, "depth", normalized_depth)
        object.__setattr__(self, "deadline_ms", normalized_deadline)
        object.__setattr__(self, "lifespan_ms", normalized_lifespan)
        object.__setattr__(self, "liveliness", normalized_liveliness)
        object.__setattr__(self, "lease_duration_ms", normalized_lease)
        object.__setattr__(self, "qos_checksum", normalized_checksum)


@dataclass(frozen=True, slots=True, init=False)
class Ros2MessageMapping:
    """Explicit mapping from one Aegis abstract command to ROS 2 message data."""

    mapping_id: str
    mapping_version: str
    source_command: str
    source_capability: str
    primitive: Ros2CommunicationPrimitive
    package_name: str
    message_type: str
    topic_or_service_name: str
    namespace: str
    frame_id: str | None
    qos: Ros2QoSProfileSpec
    field_map: Mapping[str, str]
    required_fields: tuple[str, ...]
    forbidden_fields: tuple[str, ...]
    mapping_authority: str
    mapping_checksum: str

    def __init__(
        self,
        *,
        mapping_id: str,
        mapping_version: str,
        source_command: str,
        source_capability: str,
        primitive: object,
        package_name: str,
        message_type: str,
        topic_or_service_name: str,
        namespace: str,
        frame_id: str | None,
        qos: object,
        field_map: object,
        required_fields: Iterable[str],
        forbidden_fields: Iterable[str],
        mapping_authority: str,
        mapping_checksum: str | None = None,
    ) -> None:
        if not isinstance(qos, Ros2QoSProfileSpec):
            raise ValueError("qos must be a Ros2QoSProfileSpec")
        normalized_mapping_id = _normalize_identifier(mapping_id, "mapping_id")
        normalized_mapping_version = _normalize_identifier(mapping_version, "mapping_version")
        normalized_source_command = _normalize_command(source_command)
        normalized_source_capability = _normalize_capability_name(source_capability)
        normalized_primitive = _normalize_enum(primitive, Ros2CommunicationPrimitive, "primitive")
        normalized_package = _normalize_package_name(package_name)
        normalized_message_type = _normalize_message_type(message_type)
        normalized_topic = _normalize_namespace(topic_or_service_name, "topic_or_service_name")
        normalized_namespace = _normalize_namespace(namespace, "namespace")
        normalized_frame_id = _normalize_optional_namespace(frame_id, "frame_id")
        normalized_field_map = _normalize_field_map(field_map)
        normalized_required = _normalize_source_path_tuple(
            required_fields,
            "required_fields",
            MAX_ADAPTER_REQUIRED_FIELD_COUNT,
        )
        normalized_forbidden = _normalize_field_path_tuple(
            forbidden_fields,
            "forbidden_fields",
            MAX_ADAPTER_FORBIDDEN_FIELD_COUNT,
        )
        _require_dangerous_forbidden_fields(normalized_forbidden)
        normalized_authority = _normalize_identifier(mapping_authority, "mapping_authority")
        computed_checksum = ros2_message_mapping_checksum(
            mapping_id=normalized_mapping_id,
            mapping_version=normalized_mapping_version,
            source_command=normalized_source_command,
            source_capability=normalized_source_capability,
            primitive=normalized_primitive,
            package_name=normalized_package,
            message_type=normalized_message_type,
            topic_or_service_name=normalized_topic,
            namespace=normalized_namespace,
            frame_id=normalized_frame_id,
            qos_checksum=qos.qos_checksum,
            field_map=normalized_field_map,
            required_fields=normalized_required,
            forbidden_fields=normalized_forbidden,
            mapping_authority=normalized_authority,
        )
        normalized_checksum = _normalize_supplied_checksum(
            mapping_checksum, computed_checksum, "mapping_checksum"
        )

        object.__setattr__(self, "mapping_id", normalized_mapping_id)
        object.__setattr__(self, "mapping_version", normalized_mapping_version)
        object.__setattr__(self, "source_command", normalized_source_command)
        object.__setattr__(self, "source_capability", normalized_source_capability)
        object.__setattr__(self, "primitive", normalized_primitive)
        object.__setattr__(self, "package_name", normalized_package)
        object.__setattr__(self, "message_type", normalized_message_type)
        object.__setattr__(self, "topic_or_service_name", normalized_topic)
        object.__setattr__(self, "namespace", normalized_namespace)
        object.__setattr__(self, "frame_id", normalized_frame_id)
        object.__setattr__(self, "qos", qos)
        object.__setattr__(self, "field_map", normalized_field_map)
        object.__setattr__(self, "required_fields", normalized_required)
        object.__setattr__(self, "forbidden_fields", normalized_forbidden)
        object.__setattr__(self, "mapping_authority", normalized_authority)
        object.__setattr__(self, "mapping_checksum", normalized_checksum)


def runtime_target_checksum_value(
    *,
    runtime_kind: RuntimeKind,
    runtime_id: str,
    runtime_version: str,
    deployment_domain: str,
    target_namespace: str,
    target_robot_id: str,
    runtime_authority: str,
) -> str:
    """Return the deterministic checksum for a runtime target."""
    return _sha256(
        {
            "runtime_kind": runtime_kind.value,
            "runtime_id": runtime_id,
            "runtime_version": runtime_version,
            "deployment_domain": deployment_domain,
            "target_namespace": target_namespace,
            "target_robot_id": target_robot_id,
            "runtime_authority": runtime_authority,
        }
    )


def ros2_qos_profile_checksum(
    *,
    reliability: Ros2Reliability,
    durability: Ros2Durability,
    history: Ros2History,
    depth: int | None,
    deadline_ms: int | None,
    lifespan_ms: int | None,
    liveliness: Ros2Liveliness,
    lease_duration_ms: int | None,
) -> str:
    """Return the deterministic checksum for a ROS 2 QoS profile."""
    return _sha256(
        {
            "reliability": reliability.value,
            "durability": durability.value,
            "history": history.value,
            "depth": depth,
            "deadline_ms": deadline_ms,
            "lifespan_ms": lifespan_ms,
            "liveliness": liveliness.value,
            "lease_duration_ms": lease_duration_ms,
        }
    )


def ros2_message_mapping_checksum(
    *,
    mapping_id: str,
    mapping_version: str,
    source_command: str,
    source_capability: str,
    primitive: Ros2CommunicationPrimitive,
    package_name: str,
    message_type: str,
    topic_or_service_name: str,
    namespace: str,
    frame_id: str | None,
    qos_checksum: str,
    field_map: Mapping[str, str],
    required_fields: Iterable[str],
    forbidden_fields: Iterable[str],
    mapping_authority: str,
) -> str:
    """Return the deterministic checksum for a ROS 2 message mapping."""
    required_field_values: list[CanonicalRos2MappingValue] = [
        field for field in sorted(required_fields)
    ]
    forbidden_field_values: list[CanonicalRos2MappingValue] = [
        field for field in sorted(forbidden_fields)
    ]
    return _sha256(
        {
            "mapping_id": mapping_id,
            "mapping_version": mapping_version,
            "source_command": source_command,
            "source_capability": source_capability,
            "primitive": primitive.value,
            "package_name": package_name,
            "message_type": message_type,
            "topic_or_service_name": topic_or_service_name,
            "namespace": namespace,
            "frame_id": frame_id,
            "qos_checksum": qos_checksum,
            "field_map": {key: field_map[key] for key in sorted(field_map)},
            "required_fields": required_field_values,
            "forbidden_fields": forbidden_field_values,
            "mapping_authority": mapping_authority,
        }
    )


def recompute_runtime_target_checksum(target: RuntimeTarget) -> str:
    """Recompute a RuntimeTarget checksum from its authoritative fields."""
    return runtime_target_checksum_value(
        runtime_kind=target.runtime_kind,
        runtime_id=target.runtime_id,
        runtime_version=target.runtime_version,
        deployment_domain=target.deployment_domain,
        target_namespace=target.target_namespace,
        target_robot_id=target.target_robot_id,
        runtime_authority=target.runtime_authority,
    )


def recompute_ros2_qos_profile_checksum(qos: Ros2QoSProfileSpec) -> str:
    """Recompute a Ros2QoSProfileSpec checksum from its authoritative fields."""
    return ros2_qos_profile_checksum(
        reliability=qos.reliability,
        durability=qos.durability,
        history=qos.history,
        depth=qos.depth,
        deadline_ms=qos.deadline_ms,
        lifespan_ms=qos.lifespan_ms,
        liveliness=qos.liveliness,
        lease_duration_ms=qos.lease_duration_ms,
    )


def recompute_ros2_message_mapping_checksum(mapping: Ros2MessageMapping) -> str:
    """Recompute a Ros2MessageMapping checksum from its authoritative fields."""
    return ros2_message_mapping_checksum(
        mapping_id=mapping.mapping_id,
        mapping_version=mapping.mapping_version,
        source_command=mapping.source_command,
        source_capability=mapping.source_capability,
        primitive=mapping.primitive,
        package_name=mapping.package_name,
        message_type=mapping.message_type,
        topic_or_service_name=mapping.topic_or_service_name,
        namespace=mapping.namespace,
        frame_id=mapping.frame_id,
        qos_checksum=mapping.qos.qos_checksum,
        field_map=mapping.field_map,
        required_fields=mapping.required_fields,
        forbidden_fields=mapping.forbidden_fields,
        mapping_authority=mapping.mapping_authority,
    )


def _normalize_runtime_kind(value: object) -> RuntimeKind:
    if isinstance(value, RuntimeKind):
        return value
    if not isinstance(value, str):
        raise ValueError("runtime_kind must be a RuntimeKind")
    if value != value.strip():
        raise ValueError("runtime_kind must not contain leading or trailing whitespace")
    try:
        return RuntimeKind(value)
    except ValueError:
        raise ValueError("runtime_kind must be a supported RuntimeKind") from None


def _normalize_enum[T: StrEnum](value: object, enum_type: type[T], field_name: str) -> T:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a {enum_type.__name__}")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    try:
        return enum_type(value)
    except ValueError:
        raise ValueError(f"{field_name} must be a valid {enum_type.__name__}") from None


def _normalize_identifier(value: object, field_name: str) -> str:
    normalized = _normalize_security_text(value, field_name)
    if fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", normalized) is None:
        raise ValueError(
            f"{field_name} must contain only ASCII letters, digits, '.', '_', ':', '-'"
        )
    return normalized


def _normalize_namespace(value: object, field_name: str) -> str:
    normalized = _normalize_security_text(value, field_name)
    if fullmatch(r"[a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError(f"{field_name} must be namespace-scoped and lowercase")
    return normalized


def _normalize_optional_namespace(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_namespace(value, field_name)


def _normalize_package_name(value: object) -> str:
    normalized = _normalize_security_text(value, "package_name")
    if fullmatch(r"[a-z][a-z0-9_]*", normalized) is None:
        raise ValueError("package_name must be a canonical ROS package identifier")
    return normalized


def _normalize_message_type(value: object) -> str:
    normalized = _normalize_security_text(value, "message_type")
    if fullmatch(r"(?:msg|srv|action)/[A-Za-z][A-Za-z0-9_]*", normalized) is None:
        raise ValueError("message_type must be namespace-scoped as msg|srv|action/Type")
    return normalized


def _normalize_command(value: object) -> str:
    normalized = _normalize_security_text(value, "source_command")
    if fullmatch(r"[a-z][a-z0-9_]*", normalized) is None:
        raise ValueError("source_command must be a lowercase command identifier")
    return normalized


def _normalize_capability_name(value: object) -> str:
    normalized = _normalize_security_text(value, "source_capability")
    if fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", normalized) is None:
        raise ValueError("source_capability must be a canonical dotted lowercase identifier")
    return normalized


def _normalize_security_text(value: object, field_name: str) -> str:
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
        raise ValueError(f"{field_name} must be ASCII to avoid confusable runtime strings") from exc
    if any(character.isspace() for character in normalized):
        raise ValueError(f"{field_name} must not contain whitespace")
    validate_resource_bounds(normalized, label=field_name)
    return normalized


def _normalize_qos_depth(history: Ros2History, value: object) -> int | None:
    if history is Ros2History.KEEP_ALL:
        raise ValueError("ROS2_QOS_KEEP_ALL_UNSUPPORTED")
    if value is None:
        raise ValueError("depth is required when history is KEEP_LAST")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("depth must be an integer")
    if value <= 0:
        raise ValueError("depth must be greater than 0")
    if value > MAX_ROS2_QOS_DEPTH:
        raise ValueError("depth exceeds MAX_ROS2_QOS_DEPTH")
    return value


def _normalize_optional_non_negative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_field_map(values: object) -> Mapping[str, str]:
    if not isinstance(values, Mapping):
        raise ValueError("field_map must be a mapping")
    mapping_values = cast(Mapping[object, object], values)
    if not mapping_values:
        raise ValueError("field_map must be explicit and non-empty")
    if len(mapping_values) > MAX_ADAPTER_FIELD_COUNT:
        raise ValueError("field_map exceeds MAX_ADAPTER_FIELD_COUNT")
    normalized: dict[str, str] = {}
    target_fields: set[str] = set()
    for source_path, target_path in mapping_values.items():
        normalized_source = _normalize_source_path(source_path, "field_map source")
        normalized_target = _normalize_field_path(target_path, "field_map target")
        if normalized_source in normalized:
            raise ValueError("field_map must not contain duplicate source paths")
        if normalized_target in target_fields:
            raise ValueError("field_map must not contain duplicate target fields")
        target_fields.add(normalized_target)
        normalized[normalized_source] = normalized_target
    return MappingProxyType({key: normalized[key] for key in sorted(normalized)})


def _normalize_source_path(value: object, field_name: str) -> str:
    normalized = _normalize_security_text(value, field_name)
    if (
        fullmatch(r"(?:step_type|sequence|parameters(?:\.[A-Za-z_][A-Za-z0-9_]*)+)", normalized)
        is None
    ):
        raise ValueError(f"{field_name} must reference step_type, sequence, or parameters.*")
    return normalized


def _normalize_field_path(value: object, field_name: str) -> str:
    normalized = _normalize_security_text(value, field_name)
    if fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", normalized) is None:
        raise ValueError(f"{field_name} must be a canonical field path")
    return normalized


def _normalize_source_path_tuple(
    values: Iterable[str],
    field_name: str,
    max_count: int,
) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of source paths")
    normalized = tuple(sorted(_normalize_source_path(value, field_name) for value in values))
    if len(normalized) > max_count:
        raise ValueError(f"{field_name} exceeds maximum field count")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return normalized


def _normalize_field_path_tuple(
    values: Iterable[str],
    field_name: str,
    max_count: int,
) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be an iterable of field paths")
    normalized = tuple(sorted(_normalize_field_path(value, field_name) for value in values))
    if len(normalized) > max_count:
        raise ValueError(f"{field_name} exceeds maximum field count")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return normalized


def _require_dangerous_forbidden_fields(forbidden_fields: tuple[str, ...]) -> None:
    missing = DANGEROUS_RUNTIME_OVERRIDE_FIELDS.difference(forbidden_fields)
    if missing:
        raise ValueError("forbidden_fields must include dangerous runtime override fields")


def _normalize_optional_checksum(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    normalized = _normalize_security_text(value, field_name)
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


def _sha256(payload: Mapping[str, CanonicalRos2MappingValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalRos2MappingValue],
) -> dict[str, CanonicalRos2MappingValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(value: CanonicalRos2MappingValue) -> CanonicalRos2MappingValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalRos2MappingValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "DANGEROUS_RUNTIME_OVERRIDE_FIELDS",
    "Ros2CommunicationPrimitive",
    "Ros2Durability",
    "Ros2History",
    "Ros2Liveliness",
    "Ros2MessageMapping",
    "Ros2QoSProfileSpec",
    "Ros2Reliability",
    "RuntimeKind",
    "RuntimeTarget",
    "recompute_ros2_message_mapping_checksum",
    "recompute_ros2_qos_profile_checksum",
    "recompute_runtime_target_checksum",
    "ros2_message_mapping_checksum",
    "ros2_qos_profile_checksum",
    "runtime_target_checksum_value",
]
