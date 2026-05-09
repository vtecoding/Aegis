"""Contract tests for trust-policy configuration hardening."""

from __future__ import annotations

from tests.policy_trust_fixtures import (
    TRUST_ALGORITHM,
    TRUST_CAPABILITY,
    TRUST_KEY_ID,
    TRUST_VERIFIER_METADATA,
    trusted_world_snapshot_policy,
)

from aegis.contracts.attestation_verifier import AttestationVerifierAdapterMetadata
from aegis.contracts.trust_policy_config import (
    TrustPolicyConfigStatus,
    validate_trust_policy_config,
)
from aegis.contracts.world_snapshot_trust import TrustDomain, WorldSnapshotSourceType


def test_fixture_trust_policy_config_validates_for_simulation_enforce() -> None:
    policy = trusted_world_snapshot_policy()

    result = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )

    assert result.status is TrustPolicyConfigStatus.VALID
    assert result.reason_code == "TRUST_POLICY_CONFIG_VALID"
    assert result.trust_policy_checksum == policy.checksum
    assert result.verifier_metadata_checksum == TRUST_VERIFIER_METADATA.checksum


def test_attestation_disabled_in_enforce_is_invalid() -> None:
    result = validate_trust_policy_config(
        trusted_world_snapshot_policy(require_attestation=False),
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )

    assert result.status is TrustPolicyConfigStatus.ATTESTATION_REQUIRED_FALSE_IN_ENFORCE
    assert result.reason_code == "TRUST_POLICY_ATTESTATION_REQUIRED_FALSE_IN_ENFORCE"


def test_physical_runtime_rejects_test_sources_and_simulation_domain() -> None:
    test_source_result = validate_trust_policy_config(
        trusted_world_snapshot_policy(
            source_type=WorldSnapshotSourceType.TEST_FIXTURE,
            trust_domain=TrustDomain.PHYSICAL_RUNTIME,
        ),
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.PHYSICAL_RUNTIME,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    simulation_domain_result = validate_trust_policy_config(
        trusted_world_snapshot_policy(trust_domain=TrustDomain.SIMULATION),
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.PHYSICAL_RUNTIME,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )

    assert test_source_result.status is TrustPolicyConfigStatus.TEST_SOURCE_FOR_PHYSICAL_RUNTIME
    assert (
        simulation_domain_result.status
        is TrustPolicyConfigStatus.SIMULATION_DOMAIN_FOR_PHYSICAL_RUNTIME
    )


def test_verifier_metadata_must_cover_policy_algorithm_and_key() -> None:
    metadata = AttestationVerifierAdapterMetadata(
        verifier_id="mismatched-verifier",
        verifier_version="v1",
        supported_algorithms={TRUST_ALGORITHM},
        supported_key_ids={"other-key"},
    )

    result = validate_trust_policy_config(
        trusted_world_snapshot_policy(),
        verifier_metadata=metadata,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )

    assert result.status is TrustPolicyConfigStatus.POLICY_VERIFIER_KEY_MISMATCH
    assert TRUST_KEY_ID not in metadata.supported_key_ids
