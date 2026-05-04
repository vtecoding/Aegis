"""Unit tests for the cross-platform verification runner."""

import subprocess

import scripts.verify as verify_script


def test_verify_sequence_matches_required_gate_order() -> None:
    """The verify command keeps the documented quality gate order."""
    labels = tuple(command.label for command in verify_script.COMMANDS["verify"])

    assert labels == ("typecheck", "lint", "format-check", "coverage", "invariants")


def test_verify_runner_uses_active_python_and_stops_on_first_failure(monkeypatch) -> None:
    """Gate execution uses sys.executable and returns the first failing exit code."""
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], check: bool) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert check is False
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(verify_script.sys, "executable", "venv-python")
    monkeypatch.setattr(verify_script.subprocess, "run", fake_run)

    exit_code = verify_script.run_sequence(verify_script.COMMANDS["verify"])

    assert exit_code == 7
    assert calls == [("venv-python", "-m", "pyright", "--project", "pyproject.toml")]
