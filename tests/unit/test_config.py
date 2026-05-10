"""Unit tests for AegisConfig."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from aegis.aegis_config import AegisConfig

# ---------------------------------------------------------------------------
# Default construction
# ---------------------------------------------------------------------------


def test_aegis_config_defaults() -> None:
    config = AegisConfig()
    assert config.strict_mode is True
    assert config.max_plan_steps == 32
    assert config.allow_unknown_metadata is False
    assert config.audit_algorithm == "sha256"
    assert config.gate_version == "gate-v1"
    assert config.pipeline_version == "pipeline-v1"


def test_aegis_config_is_frozen() -> None:
    config = AegisConfig()
    with pytest.raises(FrozenInstanceError):
        config.strict_mode = False  # type: ignore[misc]


def test_aegis_config_equality() -> None:
    assert AegisConfig() == AegisConfig()


def test_aegis_config_is_hashable() -> None:
    config = AegisConfig()
    assert hash(config) == hash(AegisConfig())


# ---------------------------------------------------------------------------
# Custom values
# ---------------------------------------------------------------------------


def test_aegis_config_custom_strict_mode_false() -> None:
    config = AegisConfig(strict_mode=False)
    assert config.strict_mode is False


def test_aegis_config_custom_max_plan_steps() -> None:
    config = AegisConfig(max_plan_steps=1)
    assert config.max_plan_steps == 1


def test_aegis_config_allow_unknown_metadata_true() -> None:
    config = AegisConfig(allow_unknown_metadata=True)
    assert config.allow_unknown_metadata is True


def test_aegis_config_custom_gate_version() -> None:
    config = AegisConfig(gate_version="gate-v2")
    assert config.gate_version == "gate-v2"


def test_aegis_config_custom_pipeline_version() -> None:
    config = AegisConfig(pipeline_version="pipeline-v2")
    assert config.pipeline_version == "pipeline-v2"


def test_aegis_config_gate_version_stripped() -> None:
    config = AegisConfig(gate_version="  gate-v1  ")
    assert config.gate_version == "gate-v1"


def test_aegis_config_pipeline_version_stripped() -> None:
    config = AegisConfig(pipeline_version="  pipeline-v1  ")
    assert config.pipeline_version == "pipeline-v1"


# ---------------------------------------------------------------------------
# Validation — max_plan_steps
# ---------------------------------------------------------------------------


def test_aegis_config_max_plan_steps_zero_raises() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        AegisConfig(max_plan_steps=0)


def test_aegis_config_max_plan_steps_negative_raises() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        AegisConfig(max_plan_steps=-1)


def test_aegis_config_max_plan_steps_bool_raises() -> None:
    with pytest.raises(ValueError, match="bool is not allowed"):
        AegisConfig(max_plan_steps=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Validation — version strings
# ---------------------------------------------------------------------------


def test_aegis_config_empty_gate_version_raises() -> None:
    with pytest.raises(ValueError, match="gate_version must be non-empty"):
        AegisConfig(gate_version="")


def test_aegis_config_whitespace_gate_version_raises() -> None:
    with pytest.raises(ValueError, match="gate_version must be non-empty"):
        AegisConfig(gate_version="   ")


def test_aegis_config_empty_pipeline_version_raises() -> None:
    with pytest.raises(ValueError, match="pipeline_version must be non-empty"):
        AegisConfig(pipeline_version="")


def test_aegis_config_whitespace_pipeline_version_raises() -> None:
    with pytest.raises(ValueError, match="pipeline_version must be non-empty"):
        AegisConfig(pipeline_version="   ")
