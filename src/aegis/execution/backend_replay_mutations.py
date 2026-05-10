"""Explicit ADR-0019 evil-twin mutations for backend replay proofs."""

from __future__ import annotations

from aegis.contracts.backend_replay import BackendReplayMutationProfile, BackendReplayRequest
from aegis.contracts.runtime_backend import (
    recompute_backend_certification_checksum,
    recompute_backend_dry_run_receipt_checksum,
    recompute_runtime_backend_descriptor_checksum,
)

FORGED_CHECKSUM = "0" * 64
ALTERNATE_CHECKSUM = "1" * 64


class _InjectedRuntimeClient:
    """Backend-shaped injection target used only as inert mutation evidence."""

    def __init__(self, descriptor: object) -> None:
        self.descriptor = descriptor
        self.client_handle = _injected_callable


def _injected_callable() -> None:
    return None


def mutate_backend_replay_request_in_place(
    request: BackendReplayRequest,
    mutation_profile: BackendReplayMutationProfile,
) -> BackendReplayRequest:
    """Apply one explicit evil-twin mutation to a fresh backend replay request."""
    object.__setattr__(request, "mutation_profile", mutation_profile)
    match mutation_profile:
        case BackendReplayMutationProfile.NONE:
            return request
        case BackendReplayMutationProfile.DISPATCH_PLAN_CHECKSUM_DRIFT:
            object.__setattr__(request.dispatch_plan, "plan_checksum", FORGED_CHECKSUM)
        case BackendReplayMutationProfile.FIREWALL_DECISION_CHECKSUM_DRIFT:
            object.__setattr__(request.firewall_decision, "decision_checksum", FORGED_CHECKSUM)
        case BackendReplayMutationProfile.BACKEND_DESCRIPTOR_CHECKSUM_DRIFT:
            object.__setattr__(request.backend_descriptor, "descriptor_checksum", FORGED_CHECKSUM)
        case BackendReplayMutationProfile.BACKEND_KIND_DRIFT:
            object.__setattr__(request.backend_descriptor, "backend_kind", "ROS_BACKEND_V1")
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.BACKEND_MODE_DRIFT:
            object.__setattr__(request.backend_descriptor, "backend_mode", "EXECUTE")
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.EXECUTION_FLAG_DRIFT:
            object.__setattr__(request.backend_descriptor, "allows_execution", True)
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.IO_FLAG_DRIFT:
            object.__setattr__(request.backend_descriptor, "allows_io", True)
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.ASYNC_FLAG_DRIFT:
            object.__setattr__(request.backend_descriptor, "allows_async", True)
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.CAPABILITY_SCOPE_DRIFT:
            object.__setattr__(
                request.backend_descriptor,
                "supported_capabilities",
                frozenset({"locomotion.stop"}),
            )
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.RUNTIME_KIND_SCOPE_DRIFT:
            object.__setattr__(request.backend_descriptor, "supported_runtime_kinds", frozenset())
            _rechecksum_descriptor(request)
        case BackendReplayMutationProfile.CERTIFICATION_CHECKSUM_DRIFT:
            object.__setattr__(
                request.expected_certification,
                "certification_checksum",
                FORGED_CHECKSUM,
            )
        case BackendReplayMutationProfile.RECEIPT_CHECKSUM_DRIFT:
            object.__setattr__(request.expected_receipt, "receipt_checksum", FORGED_CHECKSUM)
        case BackendReplayMutationProfile.RECEIPT_EXECUTED_COUNT_DRIFT:
            object.__setattr__(request.expected_receipt, "executed_count", 1)
            _rechecksum_receipt(request)
        case BackendReplayMutationProfile.RECEIPT_ITEM_COUNT_DRIFT:
            object.__setattr__(
                request.expected_receipt,
                "observed_dispatch_items",
                request.expected_receipt.observed_dispatch_items + (ALTERNATE_CHECKSUM,),
            )
            object.__setattr__(
                request.expected_receipt,
                "blocked_execution_count",
                request.expected_receipt.blocked_execution_count + 1,
            )
            _rechecksum_receipt(request)
        case BackendReplayMutationProfile.RECEIPT_PLAN_LINK_DRIFT:
            object.__setattr__(
                request.expected_receipt,
                "dispatch_plan_checksum",
                ALTERNATE_CHECKSUM,
            )
            _rechecksum_receipt(request)
        case BackendReplayMutationProfile.CERTIFICATION_FIREWALL_LINK_DRIFT:
            object.__setattr__(
                request.expected_certification,
                "firewall_decision_checksum",
                ALTERNATE_CHECKSUM,
            )
            _rechecksum_certification(request)
        case BackendReplayMutationProfile.CROSS_PLAN_CERTIFICATION_SWAP:
            object.__setattr__(
                request.expected_certification,
                "dispatch_plan_checksum",
                ALTERNATE_CHECKSUM,
            )
            _rechecksum_certification(request)
        case BackendReplayMutationProfile.CROSS_BACKEND_RECEIPT_SWAP:
            object.__setattr__(
                request.expected_receipt,
                "backend_descriptor_checksum",
                ALTERNATE_CHECKSUM,
            )
            _rechecksum_receipt(request)
        case BackendReplayMutationProfile.RUNTIME_OBJECT_INJECTION:
            object.__setattr__(
                request,
                "backend_descriptor",
                _InjectedRuntimeClient(request.backend_descriptor),
            )
        case BackendReplayMutationProfile.CALLABLE_CLIENT_INJECTION:
            object.__setattr__(request, "backend_descriptor", _injected_callable)
        case BackendReplayMutationProfile.MUTABLE_BACKEND_DESCRIPTOR_INJECTION:
            object.__setattr__(request, "backend_descriptor", [request.backend_descriptor])
    return request


def _rechecksum_descriptor(request: BackendReplayRequest) -> None:
    object.__setattr__(
        request.backend_descriptor,
        "descriptor_checksum",
        recompute_runtime_backend_descriptor_checksum(request.backend_descriptor),
    )


def _rechecksum_certification(request: BackendReplayRequest) -> None:
    object.__setattr__(
        request.expected_certification,
        "certification_checksum",
        recompute_backend_certification_checksum(request.expected_certification),
    )


def _rechecksum_receipt(request: BackendReplayRequest) -> None:
    object.__setattr__(
        request.expected_receipt,
        "receipt_checksum",
        recompute_backend_dry_run_receipt_checksum(request.expected_receipt),
    )


__all__ = ["mutate_backend_replay_request_in_place"]
