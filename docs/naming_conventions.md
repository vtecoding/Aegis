# Aegis Naming Conventions

Source modules under `src/aegis/` use the short `aegis_` prefix. Package directories keep their layer names, and package `__init__.py` files may re-export stable public functions.

Examples:

- `src/aegis/contracts/aegis_runtime_backend.py`
- `src/aegis/execution/aegis_capability_lease.py`
- `src/aegis/validation/aegis_schema_validator.py`
- `src/aegis/planning/aegis_command_planner.py`

Avoid generic ownership names such as `utils.py`, `helpers.py`, `manager.py`, `processor.py`, `common.py`, and `misc.py`.

## Supported Import Surface

The supported public import surface is the package-level API exported from package
`__init__.py` files, such as `aegis.execution` and `aegis.contracts`. Direct imports from
private implementation modules like `aegis.execution.aegis_command_quarantine` are permitted
inside the repository tests and implementation, but they are not a compatibility guarantee for
external callers.

The `aegis_*` source-module rename is intentional. Package-level aliases protect supported
imports; private/direct module imports outside that supported API may break and are not covered
by compatibility policy.
