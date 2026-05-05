"""Contract tests for ExecutionContext."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from aegis.contracts.context import ExecutionContext


def test_execution_context_accepts_valid_explicit_utc_datetime() -> None:
    """ExecutionContext accepts caller-provided UTC metadata."""
    submitted_at = datetime(2026, 5, 4, 12, 30, tzinfo=UTC)

    context = ExecutionContext(
        request_id=" request-123 ",
        submitted_at=submitted_at,
        policy_version=" policy-v1 ",
        run_id=" run-123 ",
    )

    assert context.request_id == "request-123"
    assert context.submitted_at == submitted_at
    assert context.policy_version == "policy-v1"
    assert context.run_id == "run-123"


@pytest.mark.parametrize("request_id", ["", "   ", "\t\n"])
def test_execution_context_rejects_empty_request_id(request_id: str) -> None:
    """request_id must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="request_id"):
        ExecutionContext(
            request_id=request_id,
            submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
            policy_version="policy-v1",
        )


def test_execution_context_canonicalizes_whitespace_request_id() -> None:
    """Whitespace-padded request_id values are stripped and stored canonically."""
    context = ExecutionContext(
        request_id=" request-123 ",
        submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
        policy_version="policy-v1",
    )

    assert context.request_id == "request-123"


@pytest.mark.parametrize("policy_version", ["", "   ", "\t\n"])
def test_execution_context_rejects_empty_policy_version(policy_version: str) -> None:
    """policy_version must be non-empty after stripping whitespace."""
    with pytest.raises(ValueError, match="policy_version"):
        ExecutionContext(
            request_id="request-123",
            submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
            policy_version=policy_version,
        )


def test_execution_context_canonicalizes_whitespace_policy_version() -> None:
    """Whitespace-padded policy_version values are stripped and stored canonically."""
    context = ExecutionContext(
        request_id="request-123",
        submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
        policy_version=" policy-v1 ",
    )

    assert context.policy_version == "policy-v1"


def test_execution_context_rejects_empty_run_id_when_provided() -> None:
    """run_id is optional, but cannot be blank when supplied."""
    with pytest.raises(ValueError, match="run_id"):
        ExecutionContext(
            request_id="request-123",
            submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
            policy_version="policy-v1",
            run_id="   ",
        )


def test_execution_context_rejects_naive_datetime() -> None:
    """Naive datetimes are rejected instead of silently normalized."""
    with pytest.raises(ValueError, match="timezone-aware"):
        ExecutionContext(
            request_id="request-123",
            submitted_at=datetime(2026, 5, 4),
            policy_version="policy-v1",
        )


def test_execution_context_rejects_non_utc_aware_datetime() -> None:
    """Aware datetimes with non-UTC offsets are rejected."""
    non_utc = timezone(timedelta(hours=1))

    with pytest.raises(ValueError, match="UTC"):
        ExecutionContext(
            request_id="request-123",
            submitted_at=datetime(2026, 5, 4, tzinfo=non_utc),
            policy_version="policy-v1",
        )


def test_execution_context_is_immutable() -> None:
    """ExecutionContext fields cannot be reassigned after construction."""
    context = ExecutionContext(
        request_id="request-123",
        submitted_at=datetime(2026, 5, 4, tzinfo=UTC),
        policy_version="policy-v1",
    )

    with pytest.raises(FrozenInstanceError):
        context.request_id = "request-456"


def test_execution_context_equality_is_stable_for_same_explicit_inputs() -> None:
    """Same explicit inputs produce equal ExecutionContext objects."""
    submitted_at = datetime(2026, 5, 4, 12, 30, tzinfo=UTC)

    first = ExecutionContext("request-123", submitted_at, "policy-v1", "run-123")
    second = ExecutionContext("request-123", submitted_at, "policy-v1", "run-123")

    assert first == second
