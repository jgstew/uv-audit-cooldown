"""action.yml: pinned, never installs itself from PyPI, and runs from github.action_path."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent


def action() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((ROOT / "action.yml").read_text())
    return data


def steps() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = action()["runs"]["steps"]
    return result


def main_step() -> dict[str, Any]:
    (step,) = (s for s in steps() if s.get("name") == "uv-audit-cooldown")
    return step


def test_marketplace_metadata() -> None:
    meta = action()
    assert meta["runs"]["using"] == "composite"
    assert meta["branding"]["icon"]
    assert meta["branding"]["color"]
    assert meta["description"]


def test_third_party_actions_pinned_by_sha() -> None:
    for step in steps():
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_no_expression_interpolated_into_scripts() -> None:
    # inputs reach the shell through env:, never ${{ }} spliced into the script
    for step in steps():
        assert "${{" not in step.get("run", ""), step


def test_runs_its_own_checkout_not_pypi() -> None:
    script = main_step()["run"]
    assert '--project "$GITHUB_ACTION_PATH"' in script
    assert "--frozen" in script
    assert "uvx" not in script
    assert "pip install" not in script


@pytest.mark.network
def test_runs_from_action_path(cooldown_project: Path, tmp_path: Path) -> None:
    """Run the step's script as a runner would: from a copy of the repo somewhere else."""
    action_path = tmp_path / "_actions" / "jgstew" / "uv-audit-cooldown" / "v1"
    action_path.mkdir(parents=True)
    for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE", "action.yml"):
        shutil.copyfile(ROOT / name, action_path / name)
    shutil.copytree(ROOT / "src", action_path / "src", ignore=shutil.ignore_patterns("__pycache__"))

    step = main_step()
    inputs = {k: str(v.get("default", "")) for k, v in action()["inputs"].items()}
    inputs["unfixed"] = "warning"
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "UV")}
    for key, value in step["env"].items():
        match = re.fullmatch(r"\$\{\{ inputs\.([\w-]+) \}\}", value)
        assert match, value
        env[key] = inputs[match.group(1)]
    env["GITHUB_ACTION_PATH"] = str(action_path)
    env["GITHUB_ACTIONS"] = "true"

    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=cooldown_project,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "::warning title=uv-audit-cooldown::" in result.stdout
    assert "wait on the exclude-newer cooldown: urllib3 1.26.4 (" in result.stdout
    # the tool ran from the copy, not from this checkout
    assert (action_path / ".venv").is_dir()
