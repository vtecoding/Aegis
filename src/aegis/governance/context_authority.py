"""Explicit deterministic context authority records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

type CanonicalContextAuthorityValue = str | int | None | dict[str, str | int | None]


@dataclass(frozen=True, slots=True, init=False)
class ContextAuthority:
    """Caller-supplied authority context bound into approval evidence."""

    context_id: str
    request_id: str
    evaluation_time_ms: int
    caller_authority: str
    deployment_domain: str
    context_schema_version: str
    context_checksum: str

    def __init__(
        self,
        *,
        context_id: str,
        request_id: str,
        evaluation_time_ms: object,
        caller_authority: str,
        deployment_domain: str,
        context_schema_version: str,
        context_checksum: str | None = None,
    ) -> None:
        normalized_context_id = _normalize_required_text(context_id, "context_id")
        normalized_request_id = _normalize_required_text(request_id, "request_id")
        normalized_evaluation_time_ms = _normalize_non_negative_int(
            evaluation_time_ms, "evaluation_time_ms"
        )
        normalized_caller_authority = _normalize_required_text(caller_authority, "caller_authority")
        normalized_deployment_domain = _normalize_required_text(
            deployment_domain, "deployment_domain"
        )
        normalized_schema_version = _normalize_required_text(
            context_schema_version, "context_schema_version"
        )
        computed_checksum = context_authority_checksum(
            context_id=normalized_context_id,
            request_id=normalized_request_id,
            evaluation_time_ms=normalized_evaluation_time_ms,
            caller_authority=normalized_caller_authority,
            deployment_domain=normalized_deployment_domain,
            context_schema_version=normalized_schema_version,
        )
        normalized_checksum = _normalize_supplied_checksum(
            context_checksum, computed_checksum, "context_checksum"
        )

        object.__setattr__(self, "context_id", normalized_context_id)
        object.__setattr__(self, "request_id", normalized_request_id)
        object.__setattr__(self, "evaluation_time_ms", normalized_evaluation_time_ms)
        object.__setattr__(self, "caller_authority", normalized_caller_authority)
        object.__setattr__(self, "deployment_domain", normalized_deployment_domain)
        object.__setattr__(self, "context_schema_version", normalized_schema_version)
        object.__setattr__(self, "context_checksum", normalized_checksum)


def context_authority_checksum(
    *,
    context_id: str,
    request_id: str,
    evaluation_time_ms: int,
    caller_authority: str,
    deployment_domain: str,
    context_schema_version: str,
) -> str:
    """Return the deterministic checksum for explicit context authority."""
    return _sha256(
        {
            "context_id": context_id,
            "request_id": request_id,
            "evaluation_time_ms": evaluation_time_ms,
            "caller_authority": caller_authority,
            "deployment_domain": deployment_domain,
            "context_schema_version": context_schema_version,
        }
    )


def _sha256(payload: dict[str, CanonicalContextAuthorityValue]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if normalized == "":
        raise ValueError(f"{field_name} must be non-empty")
    if normalized != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    return normalized


def _normalize_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return value


def _normalize_supplied_checksum(
    supplied_checksum: str | None,
    computed_checksum: str,
    field_name: str,
) -> str:
    if supplied_checksum is None:
        return computed_checksum
    normalized = _normalize_required_text(supplied_checksum, field_name)
    if normalized != computed_checksum:
        raise ValueError(f"{field_name} must match canonical recomputation")
    return normalized


__all__ = ["ContextAuthority", "context_authority_checksum"]
