# Aegis Naming Conventions

Source modules under `src/aegis/` use the short `aegis_` prefix. Package directories keep their layer names, and package `__init__.py` files may re-export stable public functions.

Examples:

- `src/aegis/contracts/aegis_runtime_backend.py`
- `src/aegis/execution/aegis_capability_lease.py`
- `src/aegis/validation/aegis_schema_validator.py`
- `src/aegis/planning/aegis_command_planner.py`

Avoid generic ownership names such as `utils.py`, `helpers.py`, `manager.py`, `processor.py`, `common.py`, and `misc.py`.
