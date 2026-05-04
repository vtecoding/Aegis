"""Bootstrap invariant: aegis package import is idempotent.

This is the first real invariant in the suite. It asserts a structural property
of the Python module system as it applies to Aegis: importing aegis multiple times
must always return the same module object. This is a prerequisite for deterministic
test harness behaviour.

Real pipeline invariants (ExecutionContext, contract determinism, etc.) are added
in feat/contracts-v1 once the contracts layer exists.
"""

import sys

import aegis


def test_invariant_aegis_import_is_idempotent() -> None:
    """Importing aegis twice must return the same module object.

    This verifies that the module does not have import-time side-effects that
    produce different objects across calls — a precondition for deterministic tests.
    """
    import aegis as aegis2  # noqa: PLC0415

    assert aegis is aegis2, (
        "Module identity is not stable: two imports of 'aegis' returned different objects. "
        "This indicates import-time side-effects or sys.modules mutation."
    )


def test_invariant_aegis_registered_in_sys_modules() -> None:
    """aegis must be registered in sys.modules after import."""
    assert "aegis" in sys.modules, (
        "'aegis' is not present in sys.modules after import. "
        "This would cause non-deterministic behaviour in test isolation."
    )


def test_invariant_aegis_version_stable_across_accesses() -> None:
    """__version__ must return the same value on every access."""
    v1 = aegis.__version__
    v2 = aegis.__version__
    assert v1 == v2, (
        f"__version__ returned different values on successive reads: {v1!r} then {v2!r}"
    )
