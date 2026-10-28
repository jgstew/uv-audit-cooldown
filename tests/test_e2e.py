"""End to end, through real uv, PyPI and OSV, against tests/fixtures/cooldown-project."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.network

# urllib3 1.26.4 -> 1.26.5 (uploaded 2021-05-26) fixes this one.
ADVISORY = "GHSA-q2q7-5pp4-w6pg"


def run_tool(project: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    environ = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "VIRTUAL_ENV")}
    environ.update(env)
    return subprocess.run(
        [sys.executable, "-m", "uv_audit_cooldown", *args],
        cwd=project,
        env=environ,
        capture_output=True,
        text=True,
        check=False,
    )


def test_fixes_inside_the_cooldown_warn_and_pass(cooldown_project: Path) -> None:
    lock = (cooldown_project / "uv.lock").read_bytes()
    # --unfixed warning: an advisory published later with no fix yet must not
    # turn this test red; that path is covered by the unit tests
    result = run_tool(cooldown_project, "--unfixed", "warning", "--verbose")
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"warning: urllib3 1.26.4: {ADVISORY}" in result.stdout
    assert "wait on the exclude-newer cooldown: urllib3 1.26.4 (" in result.stdout
    assert "already the newest version" in result.stdout
    assert (cooldown_project / "uv.lock").read_bytes() == lock


def test_fix_allowed_now_fails(cooldown_project: Path) -> None:
    lock = (cooldown_project / "uv.lock").read_bytes()
    # a cooldown that has moved past 1.26.5's upload
    result = run_tool(
        cooldown_project, "--unfixed", "warning", UV_EXCLUDE_NEWER="2021-06-01T00:00:00Z"
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"error: urllib3 1.26.4: {ADVISORY}" in result.stdout
    assert "1.26.5" in result.stdout
    assert (cooldown_project / "uv.lock").read_bytes() == lock


def test_ignore_passes_through(cooldown_project: Path) -> None:
    result = run_tool(
        cooldown_project,
        "--unfixed",
        "warning",
        "--ignore",
        ADVISORY,
        UV_EXCLUDE_NEWER="2021-06-01T00:00:00Z",
    )
    assert ADVISORY not in result.stdout
