"""Closed backend authority registry for ADR-0020."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import cast

from aegis.aegis_constants import BACKEND_AUTHORITY_CONTRACT_VERSION
from aegis.contracts.aegis_runtime_backend import RuntimeBackendKind
from aegis.execution.aegis_backend_authority import (
    BackendAuthorityManifest,
    recompute_backend_authority_manifest_checksum,
)

type CanonicalBackendRegistryValue = (
    str
    | int
    | bool
    | None
    | list[CanonicalBackendRegistryValue]
    | dict[str, CanonicalBackendRegistryValue]
)


@dataclass(frozen=True, slots=True, init=False)
class BackendAuthorityRegistry:
    """Immutable closed registry of admitted backend authority manifests."""

    manifests: tuple[BackendAuthorityManifest, ...]
    registry_checksum: str

    def __init__(
        self,
        *,
        manifests: Iterable[object],
        registry_checksum: str | None = None,
    ) -> None:
        normalized_manifests = _normalize_manifest_tuple(manifests)
        computed_checksum = backend_authority_registry_checksum(normalized_manifests)
        normalized_checksum = _normalize_supplied_checksum(
            registry_checksum,
            computed_checksum,
            "registry_checksum",
        )
        object.__setattr__(self, "manifests", normalized_manifests)
        object.__setattr__(self, "registry_checksum", normalized_checksum)

    def manifest_for(self, backend_kind: object) -> BackendAuthorityManifest | None:
        """Return the registered manifest for a backend kind, if present."""
        kind_value = _backend_kind_value(backend_kind)
        for manifest in self.manifests:
            if manifest.backend_kind.value == kind_value:
                return manifest
        return None


def build_backend_authority_registry(
    manifest: BackendAuthorityManifest,
) -> BackendAuthorityRegistry:
    """Return the closed ADR-0020 registry containing one null backend manifest."""
    return BackendAuthorityRegistry(manifests=(manifest,))


def backend_authority_registry_checksum(
    manifests: Iterable[BackendAuthorityManifest],
) -> str:
    """Return the deterministic checksum for a backend authority registry."""
    registry_entries: list[CanonicalBackendRegistryValue] = []
    for backend_kind, manifest_checksum in sorted(
        (manifest.backend_kind.value, manifest.manifest_checksum) for manifest in manifests
    ):
        entry: dict[str, CanonicalBackendRegistryValue] = {
            "backend_kind": backend_kind,
            "manifest_checksum": manifest_checksum,
        }
        registry_entries.append(entry)
    return _sha256(
        {
            "backend_authority_contract_version": BACKEND_AUTHORITY_CONTRACT_VERSION,
            "registry_entries": registry_entries,
        }
    )


def recompute_backend_authority_registry_checksum(
    registry: BackendAuthorityRegistry,
) -> str:
    """Recompute a BackendAuthorityRegistry checksum from authoritative fields."""
    return backend_authority_registry_checksum(registry.manifests)


def _normalize_manifest_tuple(
    manifests: Iterable[object],
) -> tuple[BackendAuthorityManifest, ...]:
    if isinstance(manifests, (str, Mapping)):
        raise ValueError("manifests must be an immutable iterable of manifests")
    normalized: list[BackendAuthorityManifest] = []
    seen_kinds: set[str] = set()
    for manifest in manifests:
        if not isinstance(manifest, BackendAuthorityManifest):
            raise ValueError("manifests must contain BackendAuthorityManifest values")
        if manifest.backend_kind is not RuntimeBackendKind.NULL_BACKEND_V1:
            raise ValueError("BACKEND_AUTHORITY_REGISTRY_NON_NULL_KIND")
        if manifest.manifest_checksum != recompute_backend_authority_manifest_checksum(manifest):
            raise ValueError("BACKEND_AUTHORITY_MANIFEST_CHECKSUM_DRIFT")
        if manifest.backend_kind.value in seen_kinds:
            raise ValueError("BACKEND_AUTHORITY_REGISTRY_DUPLICATE_KIND")
        seen_kinds.add(manifest.backend_kind.value)
        normalized.append(manifest)
    if not normalized:
        raise ValueError("manifests must be non-empty")
    return tuple(sorted(normalized, key=lambda manifest: manifest.backend_kind.value))


def _normalize_required_text(value: object, field_name: str) -> str:
    if callable(value):
        raise ValueError(f"{field_name} must not be callable")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if len(value) != 64 or not all(character in "0123456789abcdef" for character in value):
        raise ValueError(f"{field_name} must be a 64-char lowercase hex SHA-256")
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


def _backend_kind_value(value: object) -> str | None:
    if isinstance(value, RuntimeBackendKind):
        return value.value
    if isinstance(value, str):
        return value
    return None


def _sha256(payload: Mapping[str, CanonicalBackendRegistryValue]) -> str:
    canonical = json.dumps(
        _canonical_mapping(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_mapping(
    values: Mapping[str, CanonicalBackendRegistryValue],
) -> dict[str, CanonicalBackendRegistryValue]:
    return {key: _canonical_value(values[key]) for key in sorted(values)}


def _canonical_value(
    value: CanonicalBackendRegistryValue,
) -> CanonicalBackendRegistryValue:
    if isinstance(value, Mapping):
        return _canonical_mapping(cast(Mapping[str, CanonicalBackendRegistryValue], value))
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


__all__ = [
    "BackendAuthorityRegistry",
    "backend_authority_registry_checksum",
    "build_backend_authority_registry",
    "recompute_backend_authority_registry_checksum",
]
