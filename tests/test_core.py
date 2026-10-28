"""Decision logic, against recorded `uv audit` JSON and `uv lock --dry-run` output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from uv_audit_cooldown.core import (
    Kind,
    SchemaError,
    Severity,
    Vulnerability,
    classify,
    parse_audit,
    reachable_versions,
)

DATA = Path(__file__).parent / "data"

# Recorded 2026-10-28 with uv 0.13.0 against a lock holding virtualenv 21.14.11.
# 21.14.13 (the fix) was uploaded 2026-10-22, inside the 7-day cooldown, so the
# newest version the cooldown allowed was 21.14.12. uv prints this on stderr.
DRY_RUN_VIRTUALENV = """\
Using CPython 3.14.8 interpreter at: /opt/homebrew/opt/python@3.14/bin/python3.14
Resolved 56 packages in 136ms
Update virtualenv v21.14.11 -> v21.14.12
"""
# The same lock with the cooldown lifted (`--exclude-newer false`).
DRY_RUN_VIRTUALENV_LIFTED = """\
Using CPython 3.14.8 interpreter at: /opt/homebrew/opt/python@3.14/bin/python3.14
Resolving despite existing lockfile due to removal of exclude newer span
Resolved 56 packages in 132ms
Update virtualenv v21.14.11 -> v21.15.1
"""
# Already at the newest version the cooldown allows.
DRY_RUN_NO_CHANGES = """\
Resolved 2 packages in 133ms
No lockfile changes detected
"""
# A forked resolution (different versions per python marker split).
DRY_RUN_FORKED = """\
Resolved 2 packages in 140ms
Update urllib3 v1.26.4 -> v2.6.3, v2.8.0
"""


def load(name: str) -> str:
    return (DATA / name).read_text()


def vuln(fixes: tuple[str, ...] = ("21.14.13",), version: str = "21.14.11") -> Vulnerability:
    return Vulnerability(
        name="virtualenv",
        version=version,
        id="GHSA-cx6f-vjhg-g3cc",
        fix_versions=fixes,
        link="https://github.com/pypa/virtualenv/security/advisories/GHSA-cx6f-vjhg-g3cc",
    )


# --- parse_audit -----------------------------------------------------------


def test_parse_audit_virtualenv() -> None:
    report = parse_audit(load("audit_virtualenv.json"))
    assert report.adverse_statuses == ()
    (v,) = report.vulnerabilities
    assert v.name == "virtualenv"
    assert v.version == "21.14.11"
    assert v.id == "GHSA-cx6f-vjhg-g3cc"
    assert v.fix_versions == ("21.14.13",)
    assert v.link == "https://github.com/pypa/virtualenv/security/advisories/GHSA-cx6f-vjhg-g3cc"


def test_parse_audit_clean() -> None:
    report = parse_audit(load("audit_clean.json"))
    assert report.vulnerabilities == ()
    assert report.adverse_statuses == ()


def test_parse_audit_multi_branch_fixes() -> None:
    report = parse_audit(load("audit_urllib3.json"))
    by_id = {v.id: v for v in report.vulnerabilities}
    assert by_id["GHSA-v845-jxx5-vc9f"].fix_versions == ("2.0.6", "1.26.17")


def _mutate(path: str, change: object) -> str:
    doc = json.loads(load("audit_virtualenv.json"))
    keys = path.split(".")
    target = doc
    for k in keys[:-1]:
        target = target[int(k)] if isinstance(target, list) else target[k]
    if change is KeyError:
        del target[keys[-1]]
    else:
        target[keys[-1]] = change
    return json.dumps(doc)


@pytest.mark.parametrize(
    ("path", "change"),
    [
        ("schema.version", "1"),
        ("schema", KeyError),
        ("vulnerabilities", KeyError),
        ("vulnerabilities", {}),
        ("vulnerabilities.0.dependency", KeyError),
        ("vulnerabilities.0.dependency.name", 3),
        ("vulnerabilities.0.dependency.version", None),
        ("vulnerabilities.0.id", KeyError),
        ("vulnerabilities.0.fix_versions", KeyError),
        ("vulnerabilities.0.fix_versions", "21.14.13"),
        ("vulnerabilities.0.fix_versions", ["not a version!"]),
        ("vulnerabilities.0.link", 5),
        ("adverse_statuses", KeyError),
        ("summary.vulnerabilities", 2),
    ],
)
def test_parse_audit_rejects_unexpected_shape(path: str, change: object) -> None:
    with pytest.raises(SchemaError):
        parse_audit(_mutate(path, change))


@pytest.mark.parametrize("text", ["", "not json", "[]", "null"])
def test_parse_audit_rejects_non_object(text: str) -> None:
    with pytest.raises(SchemaError):
        parse_audit(text)


def test_parse_audit_allows_null_link() -> None:
    (v,) = parse_audit(_mutate("vulnerabilities.0.link", None)).vulnerabilities
    assert v.link is None


# --- reachable_versions ----------------------------------------------------


def test_reachable_versions_update_line() -> None:
    assert reachable_versions(DRY_RUN_VIRTUALENV, "virtualenv", "21.14.11") == ("21.14.12",)


def test_reachable_versions_not_named() -> None:
    assert reachable_versions(DRY_RUN_NO_CHANGES, "virtualenv", "21.14.11") is None


def test_reachable_versions_forked() -> None:
    assert reachable_versions(DRY_RUN_FORKED, "urllib3", "1.26.4") == ("2.6.3", "2.8.0")


def test_reachable_versions_normalises_names() -> None:
    text = "Update Zope.Interface v5.0 -> v5.1\n"
    assert reachable_versions(text, "zope-interface", "5.0") == ("5.1",)


def test_reachable_versions_ignores_other_packages() -> None:
    text = "Update typer v0.27.1 -> v0.27.3\nUpdate virtualenv v21.14.11 -> v21.14.12\n"
    assert reachable_versions(text, "virtualenv", "21.14.11") == ("21.14.12",)


def test_reachable_versions_picks_the_line_for_the_locked_version() -> None:
    text = "Update numpy v1.26.0 -> v1.26.4\nUpdate numpy v2.0.0 -> v2.1.0\n"
    assert reachable_versions(text, "numpy", "2.0.0") == ("2.1.0",)


def test_reachable_versions_ambiguous_is_an_error() -> None:
    text = "Update numpy v1.26.0 -> v1.26.4\nUpdate numpy v2.0.0 -> v2.1.0\n"
    with pytest.raises(SchemaError):
        reachable_versions(text, "numpy", "3.0.0")


def test_reachable_versions_unrecognised_output_is_an_error() -> None:
    # e.g. colour codes or new wording: never read as "already newest"
    with pytest.raises(SchemaError):
        reachable_versions(
            "\x1b[32mUpdate\x1b[0m virtualenv v21.14.11 -> v21.14.12\n", "virtualenv", "21.14.11"
        )


def test_reachable_versions_removed_package_is_an_error() -> None:
    # nothing to compare against; must not silently fall through to a warning
    with pytest.raises(SchemaError):
        reachable_versions("Remove virtualenv v21.14.11\n", "virtualenv", "21.14.11")


# --- classify ----------------------------------------------------------------


def never_lifted() -> tuple[str, ...] | None:
    raise AssertionError("the lifted-cooldown probe should not run here")


def test_virtualenv_fix_inside_cooldown_is_a_warning() -> None:
    finding = classify(
        vuln(),
        reachable_versions(DRY_RUN_VIRTUALENV, "virtualenv", "21.14.11"),
        lambda: reachable_versions(DRY_RUN_VIRTUALENV_LIFTED, "virtualenv", "21.14.11"),
        unfixed=Severity.ERROR,
    )
    assert finding.severity is Severity.WARNING
    assert finding.kind is Kind.COOLDOWN
    assert finding.reachable == ("21.14.12",)
    assert "GHSA-cx6f-vjhg-g3cc" in finding.message
    assert "21.14.13" in finding.message  # the fix
    assert "21.14.12" in finding.message  # what the cooldown allows now
    assert "cooldown" in finding.message


def test_fix_allowed_now_is_an_error() -> None:
    finding = classify(vuln(), ("21.14.13",), never_lifted, unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR
    assert finding.kind is Kind.FIX_ALLOWED
    assert "uv lock --upgrade-package virtualenv" in finding.message


def test_newer_than_fix_allowed_is_an_error() -> None:
    finding = classify(vuln(), ("21.15.1",), never_lifted, unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR


def test_no_fix_is_an_error_by_default() -> None:
    finding = classify(vuln(fixes=()), ("21.14.12",), never_lifted, unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR
    assert "no fixed version" in finding.message


def test_no_fix_can_be_a_warning() -> None:
    finding = classify(vuln(fixes=()), ("21.14.12",), never_lifted, unfixed=Severity.WARNING)
    assert finding.severity is Severity.WARNING
    assert finding.kind is Kind.UNFIXED


def test_already_newest_allowed_and_cooldown_blocks_is_a_warning() -> None:
    finding = classify(vuln(), None, lambda: ("21.15.1",), unfixed=Severity.ERROR)
    assert finding.severity is Severity.WARNING
    assert "already the newest version" in finding.message


def test_blocked_by_something_other_than_the_cooldown_is_an_error() -> None:
    # e.g. `virtualenv<21.14.12` in pyproject.toml: lifting the cooldown changes nothing
    finding = classify(vuln(), None, lambda: None, unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR
    assert finding.kind is Kind.BLOCKED
    assert "even with the cooldown lifted" in finding.message


def test_lifted_but_still_below_fix_is_an_error() -> None:
    finding = classify(vuln(), ("21.14.12",), lambda: ("21.14.12",), unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR
    assert "21.14.12" in finding.message


def test_fix_on_an_older_branch_does_not_count() -> None:
    # locked 2.0.0; fixes 1.26.17 (1.x branch) and 2.0.6 (2.x). Reaching 2.0.3 is
    # above 1.26.17 but still vulnerable: only fixes above the locked version count.
    v = vuln(fixes=("2.0.6", "1.26.17"), version="2.0.0")
    finding = classify(v, ("2.0.3",), lambda: ("2.0.6",), unfixed=Severity.ERROR)
    assert finding.severity is Severity.WARNING


def test_a_later_still_vulnerable_branch_is_not_a_fix() -> None:
    # locked 1.26.4; fixed in 1.26.17 and 2.0.6. 2.0.0 is above 1.26.17 but still vulnerable.
    v = vuln(fixes=("2.0.6", "1.26.17"), version="1.26.4")
    finding = classify(v, ("2.0.0",), lambda: ("2.0.0",), unfixed=Severity.ERROR)
    assert finding.kind is Kind.BLOCKED


def test_a_fix_on_the_same_branch_counts() -> None:
    v = vuln(fixes=("2.0.6", "1.26.17"), version="1.26.4")
    finding = classify(v, ("1.26.18",), never_lifted, unfixed=Severity.ERROR)
    assert finding.kind is Kind.FIX_ALLOWED


def test_forked_resolution_reaching_fix_anywhere_is_an_error() -> None:
    v = vuln(fixes=("2.8.0",), version="1.26.4")
    finding = classify(v, ("2.6.3", "2.8.0"), never_lifted, unfixed=Severity.ERROR)
    assert finding.severity is Severity.ERROR


def test_every_fix_at_or_below_the_locked_version_is_an_error() -> None:
    finding = classify(vuln(fixes=("21.0.0",)), None, never_lifted, unfixed=Severity.WARNING)
    assert finding.severity is Severity.ERROR


def test_message_carries_the_link() -> None:
    finding = classify(vuln(), ("21.14.13",), never_lifted, unfixed=Severity.ERROR)
    assert "https://github.com/pypa/virtualenv/security/advisories/" in finding.message
