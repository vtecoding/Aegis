"""Deterministic contract drift sentinel for authority manifests."""

from __future__ import annotations

from dataclasses import dataclass, fields

from aegis.governance.aegis_authority_fields import APPROVAL_PATH_CONTRACTS, ApprovalPathContract


@dataclass(frozen=True, slots=True)
class ContractDriftResult:
    """Machine-checkable authority manifest drift result."""

    passed: bool
    errors: tuple[str, ...]


def evaluate_contract_drift(
    contracts: tuple[ApprovalPathContract, ...] = APPROVAL_PATH_CONTRACTS,
) -> ContractDriftResult:
    """Return all contract field classification drift errors."""
    errors: list[str] = []
    seen_contracts: set[str] = set()
    for item in contracts:
        manifest = item.manifest
        contract_name = item.contract_type.__name__
        if manifest.contract_name != contract_name:
            errors.append(f"{manifest.contract_name}: manifest contract_name mismatch")
        if contract_name in seen_contracts:
            errors.append(f"{contract_name}: duplicate authority manifest")
        seen_contracts.add(contract_name)
        dataclass_fields = {
            field.name
            for field in fields(item.contract_type)  # pyright: ignore[reportArgumentType]
        }
        authoritative = set(manifest.authoritative_fields)
        non_authoritative = set(manifest.non_authoritative_fields)
        duplicate_fields = authoritative.intersection(non_authoritative)
        missing = dataclass_fields.difference(authoritative).difference(non_authoritative)
        unknown = authoritative.union(non_authoritative).difference(dataclass_fields)
        if duplicate_fields:
            errors.append(
                f"{contract_name}: fields classified twice: {','.join(sorted(duplicate_fields))}"
            )
        if missing:
            errors.append(f"{contract_name}: unclassified fields: {','.join(sorted(missing))}")
        if unknown:
            errors.append(
                f"{contract_name}: manifest names unknown fields: {','.join(sorted(unknown))}"
            )
        if not manifest.checksum_function.strip():
            errors.append(f"{contract_name}: checksum_function missing")
        if not manifest.reason.strip():
            errors.append(f"{contract_name}: manifest reason missing")
    return ContractDriftResult(passed=not errors, errors=tuple(errors))


def assert_no_contract_drift(
    contracts: tuple[ApprovalPathContract, ...] = APPROVAL_PATH_CONTRACTS,
) -> None:
    """Raise ValueError if any approval-path field escapes classification."""
    result = evaluate_contract_drift(contracts)
    if not result.passed:
        raise ValueError("; ".join(result.errors))


__all__ = ["ContractDriftResult", "assert_no_contract_drift", "evaluate_contract_drift"]
