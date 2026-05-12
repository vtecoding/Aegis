"""Cross-platform verification runner for Aegis quality gates."""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class GateCommand:
    """One Python module command in a verification sequence."""

    label: str
    module_args: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GateResult:
    """Outcome for one gate command execution."""

    command: GateCommand
    process_exit_code: int
    effective_exit_code: int
    failure_reasons: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.effective_exit_code == 0 and not self.failure_reasons


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

COVERAGE_THRESHOLD = 90.0
COVERAGE_REPORT_PATH = Path(".aegis_verify_coverage.json")
_FAILURE_MARKER_PREFIXES = ("FAIL ", "FAILED ", "ERROR ")

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


def run_gate(command: GateCommand) -> GateResult:
    """Run one gate command with the active Python interpreter.

    Args:
        command: Gate command to execute.

    Returns:
        Gate result including conservative failure-closed status.
    """
    if command.label == COVERAGE.label:
        return _run_coverage_gate(command)
    return _run_standard_gate(command)


def _run_standard_gate(command: GateCommand) -> GateResult:
    process_args = (sys.executable, "-m", *command.module_args)
    return _run_process(command=command, process_args=process_args)


def _run_coverage_gate(command: GateCommand) -> GateResult:
    coverage_json_arg = f"--cov-report=json:{COVERAGE_REPORT_PATH.as_posix()}"
    process_args = (sys.executable, "-m", *command.module_args, coverage_json_arg)
    result = _run_process(command=command, process_args=process_args)
    if not result.passed and result.process_exit_code != 0:
        return result
    try:
        coverage_percent = _load_coverage_percent(COVERAGE_REPORT_PATH)
        if coverage_percent is None:
            return _with_failure_reason(
                result,
                "coverage report missing or malformed; failing closed",
            )
        if coverage_percent < COVERAGE_THRESHOLD:
            return _with_failure_reason(
                result,
                (
                    f"coverage {coverage_percent:.2f}% is below required "
                    f"threshold {COVERAGE_THRESHOLD:.2f}%"
                ),
            )
        return result
    finally:
        with contextlib.suppress(FileNotFoundError):
            COVERAGE_REPORT_PATH.unlink()


def _run_process(command: GateCommand, process_args: tuple[str, ...]) -> GateResult:
    print(f"==> {command.label}: {' '.join(process_args)}", flush=True)
    completed = subprocess.run(process_args, check=False, capture_output=True, text=True)
    _emit_process_output(completed)
    reasons: list[str] = []
    if completed.returncode != 0:
        reasons.append(f"process exit code {completed.returncode}")
    if _has_failure_marker(completed.stdout) or _has_failure_marker(completed.stderr):
        reasons.append("failure marker detected in gate output")
    effective_exit_code = (
        completed.returncode if completed.returncode != 0 else (1 if reasons else 0)
    )
    return GateResult(
        command=command,
        process_exit_code=completed.returncode,
        effective_exit_code=effective_exit_code,
        failure_reasons=tuple(reasons),
    )


def _emit_process_output(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(
            completed.stderr,
            end="" if completed.stderr.endswith("\n") else "\n",
            file=sys.stderr,
        )


def _has_failure_marker(stream: str | None) -> bool:
    if stream is None:
        return False
    for line in stream.splitlines():
        normalized = line.strip()
        if normalized.startswith(_FAILURE_MARKER_PREFIXES):
            return True
    return False


def _load_coverage_percent(report_path: Path) -> float | None:
    try:
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    totals = report_payload.get("totals")
    if not isinstance(totals, dict):
        return None
    percent_covered = totals.get("percent_covered")
    if not isinstance(percent_covered, int | float):
        return None
    return float(percent_covered)


def _with_failure_reason(result: GateResult, reason: str) -> GateResult:
    combined_reasons = (*result.failure_reasons, reason)
    return GateResult(
        command=result.command,
        process_exit_code=result.process_exit_code,
        effective_exit_code=(result.effective_exit_code if result.effective_exit_code != 0 else 1),
        failure_reasons=combined_reasons,
    )


def run_sequence(commands: Sequence[GateCommand]) -> int:
    """Run gate commands in order and stop on first failure.

    Args:
        commands: Ordered gate commands.

    Returns:
        Zero when every command passes, otherwise the first failing exit code.
    """
    for command in commands:
        result = run_gate(command)
        if not result.passed:
            for reason in result.failure_reasons:
                print(f"!! {command.label}: {reason}", flush=True)
            print("==> verify summary: FAILURE", flush=True)
            return result.effective_exit_code
    print("==> verify summary: SUCCESS", flush=True)
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
