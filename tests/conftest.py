from __future__ import annotations

import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "cooldown-project"


@pytest.fixture
def cooldown_project(tmp_path: Path) -> Path:
    """A copy of the fixture project, with its files under their real names."""
    if shutil.which("uv") is None:
        pytest.skip("needs uv on PATH")
    dest = tmp_path / "project"
    dest.mkdir()
    for src in FIXTURE.glob("*.fixture"):
        shutil.copyfile(src, dest / src.name.removesuffix(".fixture"))
    return dest
