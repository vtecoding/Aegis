"""Unit tests for aegis.logging — AegisLogEvent, make_log_event, serialise_log_event."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from aegis.logging import AegisLogEvent, make_log_event, serialise_log_event

# ---------------------------------------------------------------------------
# AegisLogEvent construction — happy paths
# ---------------------------------------------------------------------------


def test_log_event_minimal_fields() -> None:
    event = AegisLogEvent(event_type="pipeline_allowed", layer="pipeline", outcome="allowed")
    assert event.event_type == "pipeline_allowed"
    assert event.layer == "pipeline"
    assert event.outcome == "allowed"
    assert event.audit_id is None
    assert event.plan_id is None
    assert event.reason is None
    assert event.timestamp is None
    assert dict(event.metadata) == {}


def test_log_event_all_fields() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    event = AegisLogEvent(
        event_type="gate_blocked",
        layer="gate",
        outcome="blocked",
        audit_id="abc123",
        plan_id="plan-001",
        reason="checksum_mismatch",
        timestamp=ts,
        metadata={"extra": "value"},
    )
    assert event.audit_id == "abc123"
    assert event.plan_id == "plan-001"
    assert event.reason == "checksum_mismatch"
    assert event.timestamp == ts
    assert event.metadata["extra"] == "value"


def test_log_event_is_frozen() -> None:
    event = AegisLogEvent(event_type="test", layer="validation", outcome="valid")
    with pytest.raises(FrozenInstanceError):
        event.outcome = "invalid"  # type: ignore[misc]


def test_log_event_strips_whitespace_fields() -> None:
    event = AegisLogEvent(event_type="  test  ", layer="  gate  ", outcome="  allowed  ")
    assert event.event_type == "test"
    assert event.layer == "gate"
    assert event.outcome == "allowed"


def test_log_event_metadata_frozen_on_construction() -> None:
    mutable: dict[str, object] = {"key": "val"}
    event = AegisLogEvent(event_type="test", layer="pipeline", outcome="ok", metadata=mutable)
    mutable["key"] = "mutated"
    # The stored metadata must not reflect the mutation.
    assert event.metadata["key"] == "val"


def test_log_event_equality() -> None:
    e1 = AegisLogEvent(event_type="x", layer="gate", outcome="blocked")
    e2 = AegisLogEvent(event_type="x", layer="gate", outcome="blocked")
    assert e1 == e2


# ---------------------------------------------------------------------------
# AegisLogEvent construction — validation failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_type, layer, outcome",
    [
        ("", "gate", "blocked"),
        ("   ", "gate", "blocked"),
    ],
)
def test_log_event_empty_event_type_raises(event_type: str, layer: str, outcome: str) -> None:
    with pytest.raises(ValueError, match="event_type must be non-empty"):
        AegisLogEvent(event_type=event_type, layer=layer, outcome=outcome)


@pytest.mark.parametrize(
    "event_type, layer, outcome",
    [
        ("test", "", "blocked"),
        ("test", "   ", "blocked"),
    ],
)
def test_log_event_empty_layer_raises(event_type: str, layer: str, outcome: str) -> None:
    with pytest.raises(ValueError, match="layer must be non-empty"):
        AegisLogEvent(event_type=event_type, layer=layer, outcome=outcome)


@pytest.mark.parametrize(
    "event_type, layer, outcome",
    [
        ("test", "gate", ""),
        ("test", "gate", "   "),
    ],
)
def test_log_event_empty_outcome_raises(event_type: str, layer: str, outcome: str) -> None:
    with pytest.raises(ValueError, match="outcome must be non-empty"):
        AegisLogEvent(event_type=event_type, layer=layer, outcome=outcome)


# ---------------------------------------------------------------------------
# make_log_event
# ---------------------------------------------------------------------------


def test_make_log_event_minimal() -> None:
    event = make_log_event("pipeline_allowed", "pipeline", "allowed")
    assert isinstance(event, AegisLogEvent)
    assert event.event_type == "pipeline_allowed"
    assert event.layer == "pipeline"
    assert event.outcome == "allowed"


def test_make_log_event_full() -> None:
    ts = datetime(2026, 5, 1, tzinfo=UTC)
    event = make_log_event(
        "gate_blocked",
        "gate",
        "blocked",
        audit_id="aaa",
        plan_id="ppp",
        reason="checksum_mismatch",
        timestamp=ts,
        metadata={"info": 42},
    )
    assert event.audit_id == "aaa"
    assert event.plan_id == "ppp"
    assert event.reason == "checksum_mismatch"
    assert event.timestamp == ts
    assert event.metadata["info"] == 42


def test_make_log_event_no_timestamp_by_default() -> None:
    event = make_log_event("test", "validation", "invalid")
    assert event.timestamp is None


# ---------------------------------------------------------------------------
# serialise_log_event
# ---------------------------------------------------------------------------


def test_serialise_log_event_returns_dict() -> None:
    event = AegisLogEvent(event_type="test", layer="gate", outcome="allowed")
    result = serialise_log_event(event)
    assert isinstance(result, dict)


def test_serialise_log_event_minimal_fields() -> None:
    event = AegisLogEvent(event_type="test", layer="gate", outcome="allowed")
    result = serialise_log_event(event)
    assert result["event_type"] == "test"
    assert result["layer"] == "gate"
    assert result["outcome"] == "allowed"
    assert result["audit_id"] is None
    assert result["plan_id"] is None
    assert result["reason"] is None
    assert result["timestamp"] is None
    assert result["metadata"] == {}


def test_serialise_log_event_timestamp_as_iso_string() -> None:
    ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    event = AegisLogEvent(event_type="test", layer="gate", outcome="ok", timestamp=ts)
    result = serialise_log_event(event)
    assert isinstance(result["timestamp"], str)
    assert "2026-01-15" in str(result["timestamp"])


def test_serialise_log_event_metadata_plain_dict() -> None:
    event = AegisLogEvent(event_type="test", layer="gate", outcome="ok", metadata={"k": "v"})
    result = serialise_log_event(event)
    assert isinstance(result["metadata"], dict)
    assert result["metadata"] == {"k": "v"}


def test_serialise_log_event_all_fields_present() -> None:
    event = AegisLogEvent(
        event_type="a",
        layer="b",
        outcome="c",
        audit_id="d",
        plan_id="e",
        reason="f",
    )
    result = serialise_log_event(event)
    assert set(result.keys()) == {
        "event_type",
        "layer",
        "outcome",
        "audit_id",
        "plan_id",
        "reason",
        "timestamp",
        "metadata",
    }
