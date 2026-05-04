# Changelog

All notable changes to Aegis are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Contracts v1 spine: `ExecutionContext`, JSON boundary types, `RawIntent`, validation result contracts, and typed Aegis errors
- Contract, invariant, and adversarial tests for deterministic contract behavior and boundary mutation protection
- Bootstrap tooling scaffold: `pyproject.toml`, `Makefile`, CI workflow, `.gitignore`
- Canonical `src/aegis/` DIG layer structure: `contracts/`, `intent/`, `validation/`, `planning/`, `audit/`, `gate/`
- `make verify` quality gate (pyright strict, ruff, pytest --cov, invariant suite)
- Bootstrap import test and invariant test

### Removed
- Non-canonical `src/aegis/core/` and `src/aegis/sim/` scaffolding (replaced by DIG layer structure)

---

*Releases appear below this line once tagged.*
