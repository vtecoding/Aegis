"""Contract tests for trust-policy configuration hardening."""

from __future__ import annotations

import pytest
from tests.policy_trust_fixtures import (
    TRUST_ALGORITHM,
    TRUST_CAPABILITY,
    TRUST_KEY_ID,
    TRUST_VERIFIER_METADATA,
    trusted_world_snapshot_policy,
)

from aegis.contracts.aegis_attestation_verifier import AttestationVerifierAdapterMetadata
from aegis.contracts.aegis_trust_policy_config import (
    TrustPolicyConfigStatus,
    validate_trust_policy_config,
)
from aegis.contracts.aegis_world_snapshot_trust import TrustDomain, WorldSnapshotSourceType


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


@pytest.mark.parametrize(
    ("verifier_metadata", "expected_status"),
    [
        (None, TrustPolicyConfigStatus.MALFORMED_POLICY),
        (object(), TrustPolicyConfigStatus.MALFORMED_POLICY),
        (
            type(
                "BadMetadata",
                (),
                {
                    "checksum": 123,
                    "supported_algorithms": frozenset({TRUST_ALGORITHM}),
                    "supported_key_ids": frozenset({TRUST_KEY_ID}),
                },
            )(),
            TrustPolicyConfigStatus.MALFORMED_POLICY,
        ),
        (
            type(
                "BadMetadata",
                (),
                {
                    "checksum": "c" * 64,
                    "supported_algorithms": {"not-frozenset"},
                    "supported_key_ids": frozenset({TRUST_KEY_ID}),
                },
            )(),
            TrustPolicyConfigStatus.MALFORMED_POLICY,
        ),
    ],
)
def test_malformed_verifier_metadata_is_rejected(
    verifier_metadata: object,
    expected_status,
) -> None:
    result = validate_trust_policy_config(
        trusted_world_snapshot_policy(),
        verifier_metadata=verifier_metadata,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    assert result.status is expected_status


def test_physical_runtime_rejects_policy_disabling_test_source_rejection() -> None:
    policy = trusted_world_snapshot_policy(
        source_type=WorldSnapshotSourceType.SENSOR_BRIDGE,
        trust_domain=TrustDomain.PHYSICAL_RUNTIME,
    )
    object.__setattr__(policy, "reject_test_sources_for_physical_runtime", False)
    result = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.PHYSICAL_RUNTIME,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    assert result.status is TrustPolicyConfigStatus.CONFLICTING_POLICY_FIELDS
    assert result.reason_code == "TRUST_POLICY_TEST_REJECTION_DISABLED"


def test_missing_and_malformed_policy_fail_closed() -> None:
    missing = validate_trust_policy_config(
        None,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    malformed = validate_trust_policy_config(
        object(),
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    assert missing.status is TrustPolicyConfigStatus.MISSING_POLICY
    assert malformed.status is TrustPolicyConfigStatus.MALFORMED_POLICY


def test_wildcard_source_and_capability_are_rejected() -> None:
    wildcard_source_policy = trusted_world_snapshot_policy(source_id="*")
    wildcard_source = validate_trust_policy_config(
        wildcard_source_policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    wildcard_capability_policy = trusted_world_snapshot_policy()
    object.__setattr__(wildcard_capability_policy, "allowed_capabilities", frozenset({"*"}))
    wildcard_capability = validate_trust_policy_config(
        wildcard_capability_policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    assert wildcard_source.status is TrustPolicyConfigStatus.WILDCARD_SOURCE_NOT_ALLOWED
    assert wildcard_capability.status is TrustPolicyConfigStatus.WILDCARD_CAPABILITY_NOT_ALLOWED


def test_runtime_domain_and_capability_context_mismatch_are_rejected() -> None:
    policy = trusted_world_snapshot_policy(
        capability="locomotion.rotation",
        trust_domain=TrustDomain.SIMULATION,
    )
    capability_mismatch = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.SIMULATION,
        capability=TRUST_CAPABILITY,
        enforce_mode=True,
    )
    runtime_domain_mismatch = validate_trust_policy_config(
        policy,
        verifier_metadata=TRUST_VERIFIER_METADATA,
        runtime_domain=TrustDomain.DEVELOPMENT,
        capability="locomotion.rotation",
        enforce_mode=True,
    )
    assert capability_mismatch.status is TrustPolicyConfigStatus.POLICY_CAPABILITY_CONTEXT_MISMATCH
    assert runtime_domain_mismatch.status is TrustPolicyConfigStatus.CONFLICTING_POLICY_FIELDS
