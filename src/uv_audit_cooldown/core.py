"""Parse `uv audit` JSON and `uv lock --dry-run` output, and classify findings."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# the only `uv audit` JSON schema version understood; anything else fails
SCHEMA_VERSION = "preview"


class SchemaError(Exception):
    """uv printed something this tool does not understand. Never treated as a pass."""


class Severity(Enum):
    WARNING = "warning"
    ERROR = "error"


class Kind(Enum):
    COOLDOWN = "cooldown"  # a fix exists; only the cooldown keeps it out
    FIX_ALLOWED = "fix-allowed"  # a fix is allowed now: bump
    BLOCKED = "blocked"  # a fix exists, but something besides the cooldown holds it back
    UNFIXED = "unfixed"  # no fix published
    NO_APPLICABLE_FIX = "no-applicable-fix"  # every listed fix is at or below the locked version


@dataclass(frozen=True)
class Vulnerability:
    name: str
    version: str
    id: str
    fix_versions: tuple[str, ...]
    link: str | None


@dataclass(frozen=True)
class AuditReport:
    vulnerabilities: tuple[Vulnerability, ...]
    adverse_statuses: tuple[Any, ...]


@dataclass(frozen=True)
class Finding:
    vuln: Vulnerability
    kind: Kind
    severity: Severity
    message: str
    # newest versions the project's own cooldown allows now (None: no upgrade)
    reachable: tuple[str, ...] | None = None


# --- uv audit ------------------------------------------------------------------


def _require(obj: Any, key: str, kind: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise SchemaError(f"uv audit JSON: {where} has no {key!r}")
    value = obj[key]
    if not isinstance(value, kind):
        raise SchemaError(f"uv audit JSON: {where}.{key} is {type(value).__name__}: {value!r}")
    return value


def _version(text: str, where: str) -> Version:
    try:
        return Version(text)
    except InvalidVersion:
        raise SchemaError(f"uv audit JSON: {where} is not a PEP 440 version: {text!r}") from None


def parse_audit(text: str) -> AuditReport:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"uv audit did not print JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise SchemaError(f"uv audit JSON is {type(doc).__name__}, not an object")

    schema = _require(doc, "schema", dict, "document")
    version = schema.get("version")
    if version != SCHEMA_VERSION:
        raise SchemaError(
            f"uv audit JSON schema version {version!r} is not {SCHEMA_VERSION!r}; "
            "this uv is newer than uv-audit-cooldown understands"
        )

    vulns: list[Vulnerability] = []
    for i, raw in enumerate(_require(doc, "vulnerabilities", list, "document")):
        where = f"vulnerabilities[{i}]"
        dep = _require(raw, "dependency", dict, where)
        name = _require(dep, "name", str, f"{where}.dependency")
        ver = _require(dep, "version", str, f"{where}.dependency")
        _version(ver, f"{where}.dependency.version")
        fixes = _require(raw, "fix_versions", list, where)
        for j, fix in enumerate(fixes):
            if not isinstance(fix, str):
                raise SchemaError(f"uv audit JSON: {where}.fix_versions[{j}] is {fix!r}")
            _version(fix, f"{where}.fix_versions[{j}]")
        link = raw.get("link")
        if link is not None and not isinstance(link, str):
            raise SchemaError(f"uv audit JSON: {where}.link is {link!r}")
        vulns.append(
            Vulnerability(
                name=name,
                version=ver,
                id=_require(raw, "id", str, where),
                fix_versions=tuple(fixes),
                link=link,
            )
        )

    adverse = _require(doc, "adverse_statuses", list, "document")

    # cross-check the summary when uv gives one, so a truncated list can't pass
    summary = doc.get("summary")
    if isinstance(summary, dict):
        for key, items in (("vulnerabilities", vulns), ("adverse_statuses", adverse)):
            if key in summary and summary[key] != len(items):
                raise SchemaError(
                    f"uv audit JSON: summary.{key} is {summary[key]!r} "
                    f"but {len(items)} {key} are listed"
                )

    return AuditReport(vulnerabilities=tuple(vulns), adverse_statuses=tuple(adverse))


# --- uv lock --dry-run ---------------------------------------------------------

# `Update virtualenv v21.14.11 -> v21.14.12`; a forked resolution lists several
# versions on one side: `Update urllib3 v1.26.4 -> v2.6.3, v2.8.0`.
_VERSIONS = r"v\S+(?:, v\S+)*"
_CHANGE = re.compile(
    rf"^\s*(?P<verb>Update|Add|Remove) (?P<name>\S+) (?P<old>{_VERSIONS})(?: -> (?P<new>{_VERSIONS}))?\s*$",
    re.MULTILINE,
)


def _versions(group: str) -> tuple[str, ...]:
    return tuple(v.strip().removeprefix("v") for v in group.split(","))


def reachable_versions(text: str, name: str, version: str) -> tuple[str, ...] | None:
    """What the dry run would move <name> to; None if it is not named (already newest)."""
    want = canonicalize_name(name)
    lines = []
    for line in text.splitlines():
        match = _CHANGE.match(line.strip())
        if match and canonicalize_name(match["name"]) == want:
            lines.append(match)
    if not lines:
        if "No lockfile changes detected" in text or _CHANGE.search(text):
            return None
        raise SchemaError(f"uv lock --dry-run output not understood for {name}:\n{text}".rstrip())

    exact = [m for m in lines if version in _versions(m["old"])]
    if len(exact) == 1:
        chosen = exact[0]
    elif len(lines) == 1 and not exact:
        chosen = lines[0]
    else:
        raise SchemaError(
            f"uv lock --dry-run names {name} more than once and none is clearly "
            f"{version}: {[m.group(0) for m in lines]}"
        )
    if chosen["verb"] != "Update" or chosen["new"] is None:
        raise SchemaError(f"uv lock --dry-run: unexpected change for {name}: {chosen.group(0)!r}")
    return _versions(chosen["new"])


# --- classification ------------------------------------------------------------


def _subject(v: Vulnerability) -> str:
    return f"{v.name} {v.version}: {v.id}"


def _with_link(message: str, v: Vulnerability) -> str:
    return f"{message} {v.link}" if v.link else message


def _join(versions: Sequence[str]) -> str:
    return ", ".join(versions)


def relevant_fixes(v: Vulnerability) -> list[Version]:
    """Fix versions above the locked one, lowest first (lower ones fix older branches)."""
    current = Version(v.version)
    return sorted(f for f in map(Version, v.fix_versions) if f > current)


def is_fixed(version: Version, fixes: Sequence[Version]) -> bool:
    """At or past every fix, or past a fix on its own major.minor branch."""
    return version >= max(fixes) or any(
        f <= version and f.release[:2] == version.release[:2] for f in fixes
    )


def classify(
    v: Vulnerability,
    reachable: tuple[str, ...] | None,
    lifted: Callable[[], tuple[str, ...] | None],
    *,
    unfixed: Severity,
) -> Finding:
    """reachable: allowed now (None: no upgrade); lifted: reachable without the cooldown."""
    if not v.fix_versions:
        return Finding(
            v,
            Kind.UNFIXED,
            unfixed,
            _with_link(f"{_subject(v)} has no fixed version yet.", v),
        )
    fixes = relevant_fixes(v)
    if not fixes:
        return Finding(
            v,
            Kind.NO_APPLICABLE_FIX,
            Severity.ERROR,
            _with_link(
                f"{_subject(v)} lists fixes {_join(v.fix_versions)}, none above the locked "
                "version; check the advisory.",
                v,
            ),
        )
    fix_text = _join([str(f) for f in fixes])

    def reaches(versions: tuple[str, ...] | None) -> list[str]:
        return [r for r in versions or () if is_fixed(Version(r), fixes)]

    hit = reaches(reachable)
    if hit:
        return Finding(
            v,
            Kind.FIX_ALLOWED,
            Severity.ERROR,
            _with_link(
                f"{_subject(v)} is fixed in {fix_text}, and the cooldown allows {_join(hit)} "
                f"now: run `uv lock --upgrade-package {v.name}`.",
                v,
            ),
            reachable,
        )

    now = (
        f"the newest version allowed now is {_join(reachable)}"
        if reachable
        else f"{v.version} is already the newest version allowed now"
    )
    without_cooldown = lifted()
    if reaches(without_cooldown):
        return Finding(
            v,
            Kind.COOLDOWN,
            Severity.WARNING,
            _with_link(
                f"{_subject(v)} is fixed in {fix_text}, which is still inside the exclude-newer "
                f"cooldown; {now}.",
                v,
            ),
            reachable,
        )
    best = _join(without_cooldown) if without_cooldown else v.version
    return Finding(
        v,
        Kind.BLOCKED,
        Severity.ERROR,
        _with_link(
            f"{_subject(v)} is fixed in {fix_text}, but no fixed version is reachable even with "
            f"the cooldown lifted (best: {best}); a version constraint is holding {v.name} back.",
            v,
        ),
        reachable,
    )


def cooldown_summary(findings: Sequence[Finding]) -> str | None:
    """One line for every finding that only waits on the cooldown."""
    waiting = [f for f in findings if f.kind is Kind.COOLDOWN]
    if not waiting:
        return None
    by_package: dict[tuple[str, str], list[Finding]] = {}
    for f in waiting:
        by_package.setdefault((f.vuln.name, f.vuln.version), []).append(f)

    parts = []
    moves = []
    for (name, version), group in by_package.items():
        if len(group) == 1:
            (f,) = group
            parts.append(f"{name} {version} ({f.vuln.id}, fixed in {relevant_fixes(f.vuln)[0]})")
        else:
            earliest = min(relevant_fixes(f.vuln)[0] for f in group)
            parts.append(f"{name} {version} ({len(group)} advisories, earliest fix {earliest})")
        if group[0].reachable:
            moves.append(f"{name} can go to {_join(group[0].reachable)} now")

    count = len(waiting)
    head = (
        f"{count} finding waits" if count == 1 else f"{count} findings wait"
    ) + " on the exclude-newer cooldown: "
    them = "it" if count == 1 else "them"
    tail = (
        f"{'; '.join(moves)}, which does not fix {them} yet."
        if moves
        else f"Nothing to do until it allows {them}."
    )
    return f"{head}{'; '.join(parts)}. {tail}"
