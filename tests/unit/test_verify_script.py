"""Unit tests for the cross-platform verification runner."""

import json
import subprocess
from pathlib import Path

import scripts.verify as verify_script


def test_verify_sequence_matches_required_gate_order() -> None:
    """The verify command keeps the documented quality gate order."""
    labels = tuple(command.label for command in verify_script.COMMANDS["verify"])

    assert labels == ("typecheck", "lint", "format-check", "coverage", "invariants")


def test_verify_runner_uses_active_python_and_stops_on_first_failure(monkeypatch) -> None:
    """Gate execution uses sys.executable and returns the first failing exit code."""
    calls: list[tuple[str, ...]] = []

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert check is False
        assert capture_output is True
        assert text is True
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(verify_script.sys, "executable", "venv-python")
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)

    exit_code = verify_script.run_sequence(verify_script.COMMANDS["verify"])

    assert exit_code == 7
    assert calls == [("venv-python", "-m", "pyright", "--project", "pyproject.toml")]


def test_verify_stage_failure_marker_is_aggregated_even_with_zero_exit(monkeypatch) -> None:
    """Failure marker in output must fail closed even when subprocess exits 0."""

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="FAIL synthetic gate failure marker\n",
            stderr="",
        )

    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)
    exit_code = verify_script.run_sequence((verify_script.TYPECHECK,))
    assert exit_code == 1


def test_verify_coverage_below_threshold_fails(monkeypatch, tmp_path: Path) -> None:
    """Coverage below policy floor must fail even if pytest exits 0."""
    report_path = tmp_path / "cov.json"

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        report_path.write_text(json.dumps({"totals": {"percent_covered": 89.72}}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(verify_script, "COVERAGE_REPORT_PATH", report_path)
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)

    exit_code = verify_script.run_sequence((verify_script.COVERAGE,))
    assert exit_code == 1


def test_verify_missing_or_malformed_coverage_report_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    """Missing structured coverage evidence must fail closed."""
    report_path = tmp_path / "cov.json"

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        report_path.write_text("{not-json}", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(verify_script, "COVERAGE_REPORT_PATH", report_path)
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)

    exit_code = verify_script.run_sequence((verify_script.COVERAGE,))
    assert exit_code == 1


def test_verify_cannot_print_fail_and_return_zero(monkeypatch, tmp_path: Path) -> None:
    """A gate printing FAIL must never lead to verify success."""
    report_path = tmp_path / "cov.json"

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        report_path.write_text(json.dumps({"totals": {"percent_covered": 91.0}}), encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="FAIL Required test coverage of 90% not reached.\n",
            stderr="",
        )

    monkeypatch.setattr(verify_script, "COVERAGE_REPORT_PATH", report_path)
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)

    exit_code = verify_script.run_sequence((verify_script.COVERAGE,))
    assert exit_code == 1


def test_verify_success_path_returns_zero(monkeypatch, tmp_path: Path) -> None:
    """Verify returns zero only when all required evidence reports pass."""
    report_path = tmp_path / "cov.json"

    def fake_run(
        command: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        module = command[2]
        if module == "pytest" and any(arg.startswith("--cov-report=json:") for arg in command):
            report_path.write_text(
                json.dumps({"totals": {"percent_covered": 95.0}}), encoding="utf-8"
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(verify_script, "COVERAGE_REPORT_PATH", report_path)
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)
    monkeypatch.setattr(verify_script.sys, "executable", "venv-python")

    exit_code = verify_script.run_sequence(verify_script.COMMANDS["verify"])
    assert exit_code == 0
