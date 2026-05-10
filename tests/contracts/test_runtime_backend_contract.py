"""Contract tests for ADR-0018 runtime backend descriptors."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from tests.execution_adapter_fixtures import adapter_replay_request

from aegis.contracts.runtime_backend import (
    BackendCertificationReason,
    BackendCertificationResult,
    BackendCertificationStatus,
    BackendDryRunReceipt,
    RuntimeBackendDescriptor,
    RuntimeBackendKind,
    RuntimeBackendMode,
    backend_dry_run_receipt_id,
    recompute_runtime_backend_descriptor_checksum,
)
from aegis.contracts.runtime_dispatch import RuntimeDispatchKind
from aegis.execution import (
    build_null_runtime_backend,
    build_runtime_dispatch_plan,
    prove_adapter_replay,
)


def test_null_runtime_backend_descriptor_binds_exact_dispatch_scope() -> None:
    request = adapter_replay_request(request_id="backend-contract-descriptor")
    proof = prove_adapter_replay(request)
    plan = build_runtime_dispatch_plan(request.expected_envelope, proof)

    backend = build_null_runtime_backend(plan)

    assert backend.descriptor.backend_kind is RuntimeBackendKind.NULL_BACKEND_V1
    assert backend.descriptor.backend_mode is RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY
    assert backend.descriptor.supported_runtime_kinds == frozenset({RuntimeDispatchKind.TOPIC})
    assert backend.descriptor.supported_capabilities == frozenset(
        item.capability for item in plan.dispatch_items
    )
    assert backend.descriptor.allows_execution is False
    assert backend.descriptor.allows_io is False
    assert backend.descriptor.allows_async is False
    assert backend.descriptor.descriptor_checksum == recompute_runtime_backend_descriptor_checksum(
        backend.descriptor
    )


def test_runtime_backend_descriptor_is_immutable() -> None:
    request = adapter_replay_request(request_id="backend-contract-immutable")
    plan = build_runtime_dispatch_plan(request.expected_envelope, prove_adapter_replay(request))
    backend = build_null_runtime_backend(plan)

    with pytest.raises(FrozenInstanceError):
        backend.descriptor.backend_id = "changed"


def test_runtime_backend_descriptor_rejects_non_null_kind_and_mode() -> None:
    with pytest.raises(ValueError, match="BACKEND_KIND_NOT_NULL"):
        RuntimeBackendDescriptor(
            backend_id="bad-kind",
            backend_kind="ROS_BACKEND_V1",
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY"):
        RuntimeBackendDescriptor(
            backend_id="bad-mode",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode="EXECUTE",
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )


def test_runtime_backend_descriptor_rejects_callable_and_mutable_scope_injection() -> None:
    with pytest.raises(ValueError, match="supported_capabilities"):
        RuntimeBackendDescriptor(
            backend_id="callable-capability",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities={lambda: "execute"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="supported_runtime_kinds"):
        RuntimeBackendDescriptor(
            backend_id="undeclared-runtime-kind",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={"publisher"},
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )


def test_runtime_backend_descriptor_rejects_malformed_scope_shapes() -> None:
    with pytest.raises(ValueError, match="backend_kind"):
        RuntimeBackendDescriptor(
            backend_id="bad-kind-object",
            backend_kind=object(),
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="backend_mode"):
        RuntimeBackendDescriptor(
            backend_id="bad-mode-object",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=object(),
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="supported_runtime_kinds"):
        RuntimeBackendDescriptor(
            backend_id="runtime-kinds-string",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds="topic",
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="supported_runtime_kinds"):
        RuntimeBackendDescriptor(
            backend_id="runtime-kinds-empty",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds=set(),
            supported_capabilities={"locomotion.translation"},
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="supported_capabilities"):
        RuntimeBackendDescriptor(
            backend_id="capabilities-string",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities="locomotion.translation",
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )
    with pytest.raises(ValueError, match="supported_capabilities"):
        RuntimeBackendDescriptor(
            backend_id="capabilities-empty",
            backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
            backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
            supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
            supported_capabilities=set(),
            allows_execution=False,
            allows_io=False,
            allows_async=False,
        )


def test_runtime_backend_descriptor_accepts_string_runtime_kind_scope() -> None:
    descriptor = RuntimeBackendDescriptor(
        backend_id="string-runtime-kind-scope",
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
        backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
        supported_runtime_kinds={"topic"},
        supported_capabilities={"locomotion.translation"},
        allows_execution=False,
        allows_io=False,
        allows_async=False,
    )

    assert descriptor.supported_runtime_kinds == frozenset({RuntimeDispatchKind.TOPIC})


def test_runtime_backend_descriptor_checksum_changes_on_bound_field_change() -> None:
    descriptor = RuntimeBackendDescriptor(
        backend_id="checksum-baseline",
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
        backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
        supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
        supported_capabilities={"locomotion.translation"},
        allows_execution=False,
        allows_io=False,
        allows_async=False,
    )
    changed = RuntimeBackendDescriptor(
        backend_id="checksum-baseline",
        backend_kind=RuntimeBackendKind.NULL_BACKEND_V1,
        backend_mode=RuntimeBackendMode.DRY_RUN_CERTIFICATION_ONLY,
        supported_runtime_kinds={RuntimeDispatchKind.TOPIC},
        supported_capabilities={"locomotion.stop"},
        allows_execution=False,
        allows_io=False,
        allows_async=False,
    )

    assert descriptor.descriptor_checksum != changed.descriptor_checksum


def test_backend_certification_result_rejects_invalid_certified_null_fields() -> None:
    checksum = "1" * 64

    with pytest.raises(ValueError, match="BACKEND_CERTIFIED_NULL"):
        BackendCertificationResult(
            status=BackendCertificationStatus.CERTIFIED_NULL,
            reason_code=BackendCertificationReason.BACKEND_IO_CAPABILITY_CLAIMED.value,
            dispatch_plan_checksum=checksum,
            firewall_decision_checksum=checksum,
            backend_descriptor_checksum=checksum,
            no_execution_guarantee=True,
            no_io_guarantee=True,
            no_async_guarantee=True,
            capability_scope_match=True,
            runtime_kind_scope_match=True,
        )
    with pytest.raises(ValueError, match="all guarantees"):
        BackendCertificationResult(
            status="CERTIFIED_NULL",
            reason_code=BackendCertificationReason.BACKEND_CERTIFIED_NULL.value,
            dispatch_plan_checksum=checksum,
            firewall_decision_checksum=checksum,
            backend_descriptor_checksum=checksum,
            no_execution_guarantee=True,
            no_io_guarantee=False,
            no_async_guarantee=True,
            capability_scope_match=True,
            runtime_kind_scope_match=True,
        )


def test_backend_contracts_reject_malformed_receipt_fields() -> None:
    checksum = "2" * 64
    receipt_id = backend_dry_run_receipt_id(
        dispatch_plan_checksum=checksum,
        firewall_decision_checksum=checksum,
        backend_certification_checksum=checksum,
    )

    with pytest.raises(ValueError, match="observed_dispatch_items"):
        BackendDryRunReceipt(
            receipt_id=receipt_id,
            dispatch_plan_checksum=checksum,
            firewall_decision_checksum=checksum,
            backend_certification_checksum=checksum,
            backend_descriptor_checksum=checksum,
            observed_dispatch_items="not-a-tuple",
            executed_count=0,
            blocked_execution_count=1,
        )
    with pytest.raises(ValueError, match="observed_dispatch_items"):
        BackendDryRunReceipt(
            receipt_id=receipt_id,
            dispatch_plan_checksum=checksum,
            firewall_decision_checksum=checksum,
            backend_certification_checksum=checksum,
            backend_descriptor_checksum=checksum,
            observed_dispatch_items=(),
            executed_count=0,
            blocked_execution_count=1,
        )
    with pytest.raises(ValueError, match="executed_count"):
        BackendDryRunReceipt(
            receipt_id=receipt_id,
            dispatch_plan_checksum=checksum,
            firewall_decision_checksum=checksum,
            backend_certification_checksum=checksum,
            backend_descriptor_checksum=checksum,
            observed_dispatch_items=(checksum,),
            executed_count=True,
            blocked_execution_count=1,
        )
