"""Bootstrap unit test: aegis package is importable and exposes expected metadata.

This is a structural smoke test only. It does not test pipeline behaviour.
Pipeline behaviour tests begin in feat/contracts-v1.
"""

import aegis


def test_aegis_package_importable() -> None:
    """aegis must be importable without error."""
    assert aegis.__name__ == "aegis"


def test_aegis_version_is_string() -> None:
    """__version__ must be a non-empty string."""
    assert isinstance(aegis.__version__, str)
    assert aegis.__version__ != ""
