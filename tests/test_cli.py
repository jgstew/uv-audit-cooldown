"""The command line: which uv commands run, in what order, and what is printed."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from uv_audit_cooldown.cli import RunResult, main, workflow_command

DATA = Path(__file__).parent / "data"

DRY_RUN_VIRTUALENV = "Resolved 56 packages in 136ms\nUpdate virtualenv v21.14.11 -> v21.14.12\n"
DRY_RUN_LIFTED = "Resolved 56 packages in 132ms\nUpdate virtualenv v21.14.11 -> v21.15.1\n"
DRY_RUN_FIXED = "Resolved 56 packages in 136ms\nUpdate virtualenv v21.14.11 -> v21.14.13\n"


class FakeUv:
    """Answers `uv audit` / `uv lock --dry-run` from canned output and records each call."""

    def __init__(
        self,
        audit: str | RunResult,
        lock: str | RunResult = DRY_RUN_VIRTUALENV,
        lifted: str | RunResult = DRY_RUN_LIFTED,
    ) -> None:
        self.audit = audit if isinstance(audit, RunResult) else RunResult(1, audit, "")
        self.lock = lock if isinstance(lock, RunResult) else RunResult(0, "", lock)
        self.lifted = lifted if isinstance(lifted, RunResult) else RunResult(0, "", lifted)
        self.calls: list[list[str]] = []
        self.envs: list[Mapping[str, str]] = []

    def __call__(self, cmd: Sequence[str], env: Mapping[str, str]) -> RunResult:
        self.calls.append(list(cmd))
        self.envs.append(env)
        if cmd[1] == "audit":
            return self.audit
        assert cmd[1:3] == ["lock", "--dry-run"], cmd
        return self.lifted if "--exclude-newer" in cmd else self.lock


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "uv.lock").write_text("version = 1\n")
    return tmp_path


def run(
    argv: list[str],
    fake: FakeUv,
    cwd: Path,
    environ: dict[str, str] | None = None,
) -> int:
    return main(argv, runner=fake, environ=environ or {}, cwd=cwd)


def audit_json(name: str) -> str:
    return (DATA / name).read_text()


def test_clean_audit_makes_no_other_call(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(RunResult(0, audit_json("audit_clean.json"), ""))
    assert run([], fake, project) == 0
    assert len(fake.calls) == 1
    assert fake.calls[0] == [
        "uv",
        "audit",
        "--preview-features",
        "audit-command,json-output",
        "--frozen",
        "--output-format",
        "json",
        "--color",
        "never",
    ]
    assert "no known vulnerabilities" in capsys.readouterr().out


def test_virtualenv_inside_cooldown_passes_with_a_warning(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    assert run([], fake, project) == 0
    lock = ["uv", "lock", "--dry-run", "--color", "never", "--upgrade-package"]
    assert fake.calls[1] == [*lock, "virtualenv"]
    assert fake.calls[2] == [
        *lock,
        "virtualenv",
        "--exclude-newer",
        "false",
        "--exclude-newer-package",
        "virtualenv=false",
    ]
    out = capsys.readouterr().out
    # everything waits on the cooldown: one summary line, exit 0
    assert out.count("\n") == 1
    assert out.startswith("warning: 1 finding waits on the exclude-newer cooldown: ")
    assert "virtualenv 21.14.11 (GHSA-cx6f-vjhg-g3cc, fixed in 21.14.13)" in out
    # an upgrade is allowed now but does not reach the fix: surfaced, not failed
    assert "virtualenv can go to 21.14.12 now, which does not fix it yet" in out
    assert "::warning" not in out


def test_verbose_adds_one_line_per_finding(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    assert run(["--verbose"], fake, project) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("warning: virtualenv 21.14.11: GHSA-cx6f-vjhg-g3cc ")
    assert lines[1].startswith("warning: 1 finding waits")


def test_github_actions_annotations(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    assert run([], fake, project, {"GITHUB_ACTIONS": "true"}) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert out.startswith("::warning title=uv-audit-cooldown::1 finding waits")


def test_fix_allowed_now_fails(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"), lock=DRY_RUN_FIXED)
    assert run([], fake, project, {"GITHUB_ACTIONS": "true"}) == 1
    assert len(fake.calls) == 2  # no lifted probe needed
    assert capsys.readouterr().out.startswith("::error title=uv-audit-cooldown::")


def test_one_dry_run_per_package(project: Path) -> None:
    # 22 urllib3 advisories, one package: one dry-run plus one lifted probe
    fake = FakeUv(
        audit_json("audit_urllib3.json"),
        lock="No lockfile changes detected\n",
        lifted="Update urllib3 v1.26.4 -> v2.6.3, v2.8.0\n",
    )
    run(["--unfixed", "warning"], fake, project)
    assert [c[1] for c in fake.calls] == ["audit", "lock", "lock"]


def test_summary_counts_per_package(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(
        audit_json("audit_urllib3.json"),
        lock="No lockfile changes detected\n",
        lifted="Update urllib3 v1.26.4 -> v2.6.3, v2.8.0\n",
    )
    assert run([], fake, project) == 0
    out = capsys.readouterr().out
    assert out == (
        "warning: 22 findings wait on the exclude-newer cooldown: "
        "urllib3 1.26.4 (22 advisories, earliest fix 1.26.5). Nothing to do until it allows them.\n"
    )


def test_errors_are_detailed_and_cooldown_still_summarised(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = json.loads(audit_json("audit_virtualenv.json"))
    second = json.loads(json.dumps(doc["vulnerabilities"][0]))
    second["id"] = "GHSA-aaaa-bbbb-cccc"
    second["fix_versions"] = ["21.14.12"]
    doc["vulnerabilities"].append(second)
    doc["summary"]["vulnerabilities"] = 2
    fake = FakeUv(json.dumps(doc))
    assert run([], fake, project) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("error: virtualenv 21.14.11: GHSA-aaaa-bbbb-cccc ")
    assert lines[1].startswith("warning: 1 finding waits")
    assert len(lines) == 2


def test_passthrough_args_go_to_audit_only(project: Path) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    run(["--no-dev", "--ignore", "GHSA-xxxx-xxxx-xxxx"], fake, project)
    assert fake.calls[0][-3:] == ["--no-dev", "--ignore", "GHSA-xxxx-xxxx-xxxx"]
    assert all("--no-dev" not in c for c in fake.calls[1:])


def test_double_dash_separates_passthrough(project: Path) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    run(["--", "--unfixed", "x"], fake, project)
    assert fake.calls[0][-2:] == ["--unfixed", "x"]


def test_extra_args_single_flag(project: Path) -> None:
    # the Action passes `--extra-args="$INPUT_ARGS"`; one flag must not look like an option
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    run(["--extra-args=--no-dev"], fake, project)
    assert fake.calls[0][-1] == "--no-dev"


def test_config_options_go_to_both(project: Path) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    run(["--config-file", "uv.toml", "--no-config", "--no-dev"], fake, project)
    assert fake.calls[1][-3:] == ["--config-file", "uv.toml", "--no-config"]


def test_extra_args_string_is_shell_split(project: Path) -> None:
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    run(["--extra-args", "--no-dev  --ignore 'GHSA-a b'"], fake, project)
    assert fake.calls[0][-3:] == ["--no-dev", "--ignore", "GHSA-a b"]


def test_location_args_go_to_both(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "uv.lock").write_text("")
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    assert run(["--directory", "sub", "--no-dev"], fake, tmp_path) == 0
    assert fake.calls[0][-3:] == ["--directory", "sub", "--no-dev"]
    assert fake.calls[1][-2:] == ["--directory", "sub"]
    assert fake.calls[2][-2:] == ["--directory", "sub"]


def test_location_args_equals_form(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "uv.lock").write_text("")
    fake = FakeUv(audit_json("audit_virtualenv.json"))
    assert run(["--project=sub"], fake, tmp_path) == 0
    assert fake.calls[1][-1] == "--project=sub"


@pytest.mark.parametrize(
    "result",
    [
        RunResult(
            1, "", "error: Unable to find lockfile at `uv.lock`, but `--frozen` was provided.\n"
        ),
        RunResult(2, "", "error: No `pyproject.toml` found in current directory or any parent\n"),
    ],
)
def test_skips_without_a_lock_or_project(
    tmp_path: Path, result: RunResult, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeUv(result)
    assert run([], fake, tmp_path) == 0
    assert len(fake.calls) == 1
    assert "nothing to audit" in capsys.readouterr().out


def test_script_runs_without_uv_lock(tmp_path: Path) -> None:
    fake = FakeUv(RunResult(0, audit_json("audit_clean.json"), ""))
    assert run(["--script", "tool.py"], fake, tmp_path) == 0
    assert fake.calls[0][-2:] == ["--script", "tool.py"]


def test_unfixed_warning_option(project: Path) -> None:
    doc = json.loads(audit_json("audit_virtualenv.json"))
    doc["vulnerabilities"][0]["fix_versions"] = []
    text = json.dumps(doc)
    fake = FakeUv(text)
    assert run([], fake, project) == 1
    assert run(["--unfixed", "warning"], FakeUv(text), project) == 0
    assert len(fake.calls) == 1  # nothing to upgrade to, so no dry-run


def test_audit_failure_is_exit_2(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(RunResult(2, "", "error: failed to query OSV\n"))
    assert run([], fake, project) == 2
    assert "failed to query OSV" in capsys.readouterr().err


def test_unexpected_schema_is_exit_2(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(RunResult(1, '{"schema": {"version": "2"}}', ""))
    assert run([], fake, project) == 2
    assert "schema" in capsys.readouterr().err


def test_dry_run_failure_is_exit_2(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeUv(
        audit_json("audit_virtualenv.json"), lock=RunResult(1, "", "error: No solution found\n")
    )
    assert run([], fake, project) == 2
    assert "No solution found" in capsys.readouterr().err


def test_adverse_status_is_an_error(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    text = audit_json("audit_clean.json").replace(
        '"adverse_statuses": []', '"adverse_statuses": [{"name": "foo", "status": "quarantined"}]'
    )
    text = text.replace('"adverse_statuses": 0', '"adverse_statuses": 1')
    fake = FakeUv(RunResult(1, text, ""))
    assert run([], fake, project) == 1
    assert "quarantined" in capsys.readouterr().out


def test_uses_uv_from_env_and_drops_virtual_env(project: Path) -> None:
    fake = FakeUv(RunResult(0, audit_json("audit_clean.json"), ""))
    env = {"UV": "/opt/uv", "VIRTUAL_ENV": "/x/.venv", "UV_FROZEN": "1", "UV_LOCKED": "1"}
    run([], fake, project, {**env, "PATH": "/bin"})
    assert fake.calls[0][0] == "/opt/uv"
    for key in ("VIRTUAL_ENV", "UV_FROZEN", "UV_LOCKED"):
        assert key not in fake.envs[0]
    assert fake.envs[0]["PATH"] == "/bin"


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip().startswith("uv-audit-cooldown ")


def test_workflow_command_escapes() -> None:
    assert (
        workflow_command("warning", "50% a\nb") == "::warning title=uv-audit-cooldown::50%25 a%0Ab"
    )
