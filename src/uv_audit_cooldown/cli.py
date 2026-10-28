"""Run `uv audit`, then one `uv lock --dry-run` per vulnerable package.

Exit codes: 0 nothing to do now, 1 action needed, 2 uv failed or its output was not understood.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name

from . import __version__
from .core import (
    Finding,
    Kind,
    SchemaError,
    Severity,
    classify,
    cooldown_summary,
    parse_audit,
    reachable_versions,
    relevant_fixes,
)

TITLE = "uv-audit-cooldown"
AUDIT = ["audit", "--preview-features", "audit-command,json-output", "--frozen"]
AUDIT += ["--output-format", "json"]
# also passed to `uv lock`, so both commands see the same project
LOCATION_OPTIONS = ("--directory", "--project", "--script")


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], Mapping[str, str]], RunResult]


class UvFailed(Exception):
    pass


def _subprocess_runner(cwd: Path) -> Runner:
    def run(cmd: Sequence[str], env: Mapping[str, str]) -> RunResult:
        proc = subprocess.run(
            list(cmd), cwd=cwd, env=dict(env), capture_output=True, text=True, check=False
        )
        return RunResult(proc.returncode, proc.stdout, proc.stderr)

    return run


def workflow_command(level: str, message: str) -> str:
    """A GitHub Actions annotation, with the data escaped per the runner's rules."""
    data = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::{level} title={TITLE}::{data}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TITLE,
        allow_abbrev=False,
        description=(
            "Run `uv audit`, but warn instead of failing while an advisory's fix is still "
            "inside the project's exclude-newer cooldown. Any other argument (or anything "
            "after `--`) is passed to `uv audit`."
        ),
    )
    parser.add_argument(
        "--unfixed",
        choices=[s.value for s in Severity],
        default=Severity.ERROR.value,
        help="how to report an advisory with no fixed version at all (default: error)",
    )
    parser.add_argument(
        "--extra-args",
        default="",
        metavar="STRING",
        help="more `uv audit` arguments as one shell-quoted string (used by the GitHub Action)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="also print one line per advisory that waits on the cooldown",
    )
    parser.add_argument("--version", action="version", version=f"{TITLE} {__version__}")
    return parser


def _location_args(args: Sequence[str]) -> list[str]:
    out: list[str] = []
    it = iter(args)
    for arg in it:
        if arg in LOCATION_OPTIONS:
            out += [arg, next(it, "")]
        elif arg.startswith(tuple(f"{o}=" for o in LOCATION_OPTIONS)):
            out.append(arg)
    return out


def _lock_dir(location: Sequence[str], cwd: Path) -> Path | None:
    """Where uv.lock should be, or None when a --script is audited instead."""
    values: dict[str, str] = {}
    it = iter(location)
    for arg in it:
        key, eq, value = arg.partition("=")
        values[key] = value if eq else next(it, "")
    if "--script" in values:
        return None
    base = cwd / values.get("--directory", "")
    return base / values.get("--project", "")


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    environ = os.environ if environ is None else environ
    cwd = Path.cwd() if cwd is None else cwd

    after: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, after = argv[:split], argv[split + 1 :]
    opts, passthrough = _parser().parse_known_args(argv)
    passthrough += shlex.split(opts.extra_args) + after
    location = _location_args(passthrough)

    lock_dir = _lock_dir(location, cwd)
    if lock_dir is not None and not (lock_dir / "uv.lock").is_file():
        print(f"{TITLE}: no uv.lock in {lock_dir}; nothing to audit.")
        return 0

    uv = environ.get("UV") or "uv"
    # don't leak the Action's own `uv run` venv into the audited project
    env = {k: v for k, v in environ.items() if k != "VIRTUAL_ENV"}
    run = runner or _subprocess_runner(cwd)
    github = bool(environ.get("GITHUB_ACTIONS"))

    try:
        findings, adverse = _check(uv, passthrough, location, run, env, Severity(opts.unfixed))
    except FileNotFoundError:
        print(f"{TITLE}: `{uv}` not found; install uv or put it on PATH.", file=sys.stderr)
        return 2
    except (UvFailed, SchemaError) as exc:
        print(f"{TITLE}: {exc}", file=sys.stderr)
        return 2

    def emit(severity: Severity, message: str) -> None:
        level = severity.value
        print(workflow_command(level, message) if github else f"{level}: {message}")

    for status in adverse:
        emit(Severity.ERROR, f"adverse project status: {status}")
    for f in findings:
        if f.kind is not Kind.COOLDOWN or opts.verbose:
            emit(f.severity, f.message)
    summary = cooldown_summary(findings)
    if summary:
        emit(Severity.WARNING, summary)
    if not findings and not adverse:
        print(f"{TITLE}: no known vulnerabilities.")

    failed = adverse or any(f.severity is Severity.ERROR for f in findings)
    return 1 if failed else 0


def _check(
    uv: str,
    passthrough: Sequence[str],
    location: Sequence[str],
    run: Runner,
    env: Mapping[str, str],
    unfixed: Severity,
) -> tuple[list[Finding], tuple[object, ...]]:
    audit = run([uv, *AUDIT, *passthrough], env)
    # uv audit exits 1 when it finds something; the JSON says what
    if audit.returncode not in (0, 1):
        raise UvFailed(f"`uv audit` exited {audit.returncode}:\n{audit.stderr}".rstrip())
    try:
        report = parse_audit(audit.stdout)
    except SchemaError as exc:
        raise SchemaError(f"{exc}\n{audit.stderr}".rstrip()) from None

    def dry_run(name: str, *extra: str) -> str:
        result = run([uv, "lock", "--dry-run", "--upgrade-package", name, *extra, *location], env)
        if result.returncode != 0:
            raise UvFailed(
                f"`uv lock --dry-run --upgrade-package {name}` exited {result.returncode}:\n"
                f"{result.stderr}".rstrip()
            )
        # uv prints the changes on stderr; read both in case that moves
        return result.stdout + result.stderr

    # one dry-run per package, and one lifted probe per package, at most
    reachable_cache: dict[tuple[str, str], tuple[str, ...] | None] = {}
    lifted_cache: dict[tuple[str, str], tuple[str, ...] | None] = {}
    findings = []
    for v in report.vulnerabilities:
        key = (canonicalize_name(v.name), v.version)
        if not relevant_fixes(v):
            # nothing to upgrade to, so nothing to ask uv
            findings.append(classify(v, None, lambda: None, unfixed=unfixed))
            continue
        if key not in reachable_cache:
            reachable_cache[key] = reachable_versions(dry_run(v.name), v.name, v.version)

        def lifted(name: str = v.name, key: tuple[str, str] = key) -> tuple[str, ...] | None:
            if key not in lifted_cache:
                text = dry_run(
                    name, "--exclude-newer", "false", "--exclude-newer-package", f"{name}=false"
                )
                lifted_cache[key] = reachable_versions(text, name, key[1])
            return lifted_cache[key]

        findings.append(classify(v, reachable_cache[key], lifted, unfixed=unfixed))
    return findings, report.adverse_statuses
