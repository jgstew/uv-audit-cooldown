# uv-audit-cooldown

Cooldown-aware `uv audit`: it warns while a fix is inside your `exclude-newer` window, and fails once it isn't.

**Unofficial, and not affiliated with Astral.** It relies on `uv audit`'s preview JSON output.

```yaml
# GitHub Action
- uses: jgstew/uv-audit-cooldown@<full-commit-sha> # v1.0.0
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
| No project or no `uv.lock` (as uv finds them) | skip |

In GitHub Actions, messages are printed as `::warning`/`::error` annotations.
`--verbose` prints one line per advisory. Other arguments go to `uv audit`,
e.g. `--no-dev` or `--ignore GHSA-…`. `--offline` isn't used: on a cold
CI cache it fails, and with a stale cache it could hide a fix that is already allowed.

Exit codes: `0` nothing to do now, `1` action needed, `2` uv failed or its
output wasn't understood.

## Action inputs

`working-directory` (default `.`), `args` (extra `uv audit` arguments),
`unfixed` (`error`/`warning`), `setup-uv` (`auto`/`true`/`false`), `uv-version`.

## Pinning

- **Action:** pin `uses:` to a commit SHA. The Action runs its own checkout
  (`uv run --frozen --project "$GITHUB_ACTION_PATH"`) and never installs from PyPI.
- **pre-commit:** pin `rev:` to a tag, or to a SHA with `pre-commit autoupdate --freeze`.
- **uvx:** pin a version: `uvx uv-audit-cooldown@1.0.0`.

## Related uv issues

[astral-sh/uv#18995](https://github.com/astral-sh/uv/issues/18995),
[astral-sh/uv#22944](https://github.com/astral-sh/uv/issues/22944),
[astral-sh/uv#19265](https://github.com/astral-sh/uv/issues/19265),
[astral-sh/uv#18506](https://github.com/astral-sh/uv/issues/18506)
