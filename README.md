# uv-audit-cooldown

Cooldown-aware `uv audit`: it warns while a fix is inside your `exclude-newer` window, and fails once it isn't.

**Unofficial, and not affiliated with Astral.** It relies on `uv audit`'s preview JSON output.

```yaml
# GitHub Action
on:
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # advisories appear without code changes
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: jgstew/uv-audit-cooldown@0b808b7239fced579e4bb19f3d3ab3a918472abe # v1.0.0
```

```yaml
# pre-commit
repos:
  - repo: https://github.com/jgstew/uv-audit-cooldown
    rev: v1.0.0
    hooks:
      - id: uv-audit-cooldown
        verbose: true # pre-commit hides output of passing hooks
        stages: [manual] # needs the network
```

```sh
uvx uv-audit-cooldown@1.0.0
```

## What it does

It runs `uv audit`. For each vulnerable package it then runs
`uv lock --dry-run --upgrade-package <name>`, which shows the newest version
your own cooldown allows and leaves `uv.lock` untouched. If no audit
finding is reported, no other network call is made.

| Situation | Result |
| --- | --- |
| Every fix is still inside the cooldown | pass, with a one-line summary |
| An upgrade is allowed, but it doesn't reach the fix yet | pass, and the summary says so |
| A fixed version is allowed now | fail |
| A fix is blocked by something other than the cooldown (a pin) | fail |
| No fix has been published | fail (`--unfixed warning` to soften) |
| No project or no `uv.lock` (as uv finds them) | pass with a warning (`--no-lockfile error` to fail) |

To tell whether a fix is held back only by the cooldown, it runs a second
dry run with the cooldown lifted. That one uses `--no-build`, so it never
runs build code from a release that is still inside the cooldown; if it would
need a build, the tool exits `2`.

In GitHub Actions, messages are printed as `::warning`/`::error` annotations.
`--verbose` prints one line per advisory. Other arguments go to `uv audit`,
e.g. `--no-dev` or `--ignore GHSA-…`. Location, config, index, cache, build
and resolver options (`--project`, `--index`, `--prerelease`, `--exclude-newer`, …)
also go to the dry runs, so both see the same settings; `UV_*` environment
variables reach both too. `--offline` isn't used: on a cold
CI cache it fails, and with a stale cache it could hide a fix that is already allowed.

Exit codes: `0` nothing to do now, `1` action needed, `2` uv failed or its
output wasn't understood.

## Action inputs

`working-directory` (default `.`), `args` (extra `uv audit` arguments),
`unfixed` (`error`/`warning`), `no-lockfile` (`warning`/`error`),
`setup-uv` (`auto`/`true`/`false`), `uv-version`.

## Pinning

- **Action:** pin `uses:` to a commit SHA. The Action runs its own checkout
  (`uv run --frozen --project "$GITHUB_ACTION_PATH"`) and never installs from PyPI.
- **pre-commit:** pin `rev:` to a tag, or to a SHA with `pre-commit autoupdate --freeze`.
- **uvx:** pin a version: `uvx uv-audit-cooldown@1.0.0`.

### pre-commit limitation

pre-commit installs the hook with pip (`language: python`), which ignores this
repo's `uv.lock` and `exclude-newer`. The hook's dependency (`packaging`) and
its build backend (`uv_build`) therefore come from PyPI at their newest allowed
versions, with no cooldown. `rev:` pins only this repo's code. If that matters,
use the Action (it runs `uv run --frozen` from its own lockfile), or a `local`
hook with `language: system` and
`entry: uvx --exclude-newer "7 days" uv-audit-cooldown@1.0.0`.

## Related uv issues

[astral-sh/uv#18995](https://github.com/astral-sh/uv/issues/18995),
[astral-sh/uv#22944](https://github.com/astral-sh/uv/issues/22944),
[astral-sh/uv#19265](https://github.com/astral-sh/uv/issues/19265),
[astral-sh/uv#18506](https://github.com/astral-sh/uv/issues/18506)
