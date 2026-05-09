"""Tests for explicit context authority contracts."""

from __future__ import annotations

import pytest

from aegis.governance.context_authority import ContextAuthority, context_authority_checksum


def test_context_authority_checksum_binds_context_identity() -> None:
    authority = ContextAuthority(
        context_id="ctx-1",
        request_id="request-1",
        evaluation_time_ms=1000,
        caller_authority="operator",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )

    expected = context_authority_checksum(
        context_id="ctx-1",
        request_id="request-1",
        evaluation_time_ms=1000,
        caller_authority="operator",
        deployment_domain="SIMULATION",
        context_schema_version="context-authority-v1",
    )

    assert authority.context_checksum == expected


def test_context_authority_rejects_forged_checksum() -> None:
    with pytest.raises(ValueError, match="context_checksum must match"):
        ContextAuthority(
            context_id="ctx-1",
            request_id="request-1",
            evaluation_time_ms=1000,
            caller_authority="operator",
            deployment_domain="SIMULATION",
            context_schema_version="context-authority-v1",
            context_checksum="0" * 64,
        )


@pytest.mark.parametrize("bad_time", [True, -1])
def test_context_authority_rejects_invalid_evaluation_time(bad_time: object) -> None:
    with pytest.raises(ValueError, match="evaluation_time_ms"):
        ContextAuthority(
            context_id="ctx-1",
            request_id="request-1",
            evaluation_time_ms=bad_time,
            caller_authority="operator",
            deployment_domain="SIMULATION",
            context_schema_version="context-authority-v1",
        )
