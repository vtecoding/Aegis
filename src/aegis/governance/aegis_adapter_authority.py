"""Deterministic ADR-0015 adapter authority drift checks."""

from __future__ import annotations

from dataclasses import dataclass, fields

from aegis.governance.aegis_adapter_fields import (
    ADAPTER_AUTHORITY_CONTRACTS,
    AdapterAuthorityContract,
)


@dataclass(frozen=True, slots=True)
class AdapterAuthorityDriftResult:
    """Machine-checkable adapter authority drift result."""

    passed: bool
    errors: tuple[str, ...]


def evaluate_adapter_authority_drift(
    contracts: tuple[AdapterAuthorityContract, ...] = ADAPTER_AUTHORITY_CONTRACTS,
) -> AdapterAuthorityDriftResult:
    """Return deterministic drift errors for adapter authority manifests."""
    errors: list[str] = []
    seen_names: set[str] = set()
    for contract in contracts:
        contract_name = contract.contract_type.__name__
        if contract_name in seen_names:
            errors.append(f"{contract_name}: duplicate adapter authority manifest")
        seen_names.add(contract_name)
        dataclass_fields = tuple(
            field.name
            for field in fields(contract.contract_type)  # pyright: ignore[reportArgumentType]
        )
        manifest_fields = contract.manifest.authoritative_fields
        missing = tuple(field for field in dataclass_fields if field not in manifest_fields)
        extra = tuple(field for field in manifest_fields if field not in dataclass_fields)
        if missing:
            errors.append(f"{contract_name}: missing adapter manifest fields {','.join(missing)}")
        if extra:
            errors.append(f"{contract_name}: unknown adapter manifest fields {','.join(extra)}")
    return AdapterAuthorityDriftResult(passed=not errors, errors=tuple(errors))


def assert_no_adapter_authority_drift() -> None:
    """Raise ValueError when adapter authority manifests drift from contracts."""
    result = evaluate_adapter_authority_drift()
    if not result.passed:
        raise ValueError("; ".join(result.errors))


__all__ = [
    "AdapterAuthorityDriftResult",
    "assert_no_adapter_authority_drift",
    "evaluate_adapter_authority_drift",
]
