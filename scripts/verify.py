"""Cross-platform verification runner for Aegis quality gates."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class GateCommand:
    """One Python module command in a verification sequence."""

    label: str
    module_args: tuple[str, ...]


TYPECHECK = GateCommand("typecheck", ("pyright", "--project", "pyproject.toml"))
LINT = GateCommand("lint", ("ruff", "check", "src", "tests"))
FORMAT_CHECK = GateCommand("format-check", ("ruff", "format", "--check", "src", "tests"))
FORMAT = GateCommand("format", ("ruff", "format", "src", "tests"))
TEST = GateCommand("test", ("pytest", "tests"))
COVERAGE = GateCommand(
    "coverage",
    (
        "pytest",
        "tests",
        "--cov=src",
        "--cov-report=term-missing",
        "--cov-fail-under=90",
    ),
)
COVERAGE_HTML = GateCommand(
    "coverage-html",
    ("pytest", "tests", "--cov=src", "--cov-report=term-missing", "--cov-report=html"),
)
INVARIANTS = GateCommand("invariants", ("pytest", "tests/invariants", "-v", "--tb=short"))
ADVERSARIAL = GateCommand("adversarial", ("pytest", "tests/adversarial", "-v", "--tb=short"))

COMMANDS: Mapping[str, tuple[GateCommand, ...]] = MappingProxyType(
    {
        "verify": (TYPECHECK, LINT, FORMAT_CHECK, COVERAGE, INVARIANTS),
        "typecheck": (TYPECHECK,),
        "lint": (LINT,),
        "format": (FORMAT,),
        "test": (TEST,),
        "test-invariants": (INVARIANTS,),
        "test-adversarial": (ADVERSARIAL,),
        "coverage": (COVERAGE_HTML,),
    }
)


def run_gate(command: GateCommand) -> int:
    """Run one gate command with the active Python interpreter.

    Args:
        command: Gate command to execute.

    Returns:
        The subprocess exit code.
    """
    process_args = (sys.executable, "-m", *command.module_args)
    print(f"==> {command.label}: {' '.join(process_args)}", flush=True)
    completed = subprocess.run(process_args, check=False)
    return completed.returncode


def run_sequence(commands: Sequence[GateCommand]) -> int:
    """Run gate commands in order and stop on first failure.

    Args:
        commands: Ordered gate commands.

    Returns:
        Zero when every command passes, otherwise the first failing exit code.
    """
    for command in commands:
        exit_code = run_gate(command)
        if exit_code != 0:
            return exit_code
    return 0


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run Aegis verification gates.")
    parser.add_argument("command", choices=tuple(COMMANDS), help="Gate command to run.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested verification command."""
    args = parse_args(argv)
    command_name = str(args.command)
    return run_sequence(COMMANDS[command_name])


if __name__ == "__main__":
    raise SystemExit(main())
