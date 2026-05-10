"""Invariant tests for ADR-0010 verifier and trust-policy hardening."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st
from tests.policy_trust_fixtures import (
    TRUST_CAPABILITY,
    TRUST_VERIFIER_METADATA,
    PassingAttestationVerifier,
    trusted_world_snapshot_policy,
)

from aegis.contracts.aegis_attestation_verifier import certify_attestation_verifier_adapter
from aegis.contracts.aegis_trust_policy_config import validate_trust_policy_config
from aegis.contracts.aegis_world_snapshot_trust import TrustDomain


@given(replay_count=st.integers(min_value=1, max_value=4))
def test_invariant_verifier_certification_is_deterministic(replay_count: int) -> None:
    first = certify_attestation_verifier_adapter(
        PassingAttestationVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
        deterministic_replay_count=replay_count,
    )
    second = certify_attestation_verifier_adapter(
        PassingAttestationVerifier(),
        enforce_mode=True,
        runtime_domain=TrustDomain.SIMULATION,
        deterministic_replay_count=replay_count,
    )

    assert first == second
    assert first.checksum == second.checksum


@given(enforce_mode=st.booleans())
def test_invariant_trust_policy_config_validation_is_deterministic(enforce_mode: bool) -> None:
    policy = trusted_world_snapshot_policy()

    first = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=enforce_mode,
    )
    second = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=enforce_mode,
    )

    assert first == second
    assert first.checksum == second.checksum
