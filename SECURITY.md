# Security

Report a vulnerability privately through
[GitHub's private vulnerability reporting](https://github.com/jgstew/uv-audit-cooldown/security/advisories/new),
not in a public issue.

Only the latest release gets fixes.

## Practices

- Third-party actions are pinned to full commit SHAs; actionlint and zizmor
  check every workflow.
- Workflows default to read-only. Only the release jobs can write repository
  contents, and only the signing and PyPI jobs get an OIDC token; the build job
  has neither.
- PyPI uses Trusted Publishing (no API token), from a `pypi` environment
  that only `main` can deploy to.
- Release files carry Sigstore build provenance (`gh attestation verify
  <file> --repo jgstew/uv-audit-cooldown`), and PyPI files carry PEP 740
  attestations.
- Releases are immutable and carry SHA-256 checksums. `v*` tags can't be
  moved or deleted, and `main` needs a pull request and can't be force-pushed.
- Dependencies wait 7 days (`exclude-newer`, and a Dependabot cooldown).
- The Action runs from its own lockfile (`uv run --frozen`) and never installs
  from PyPI. Inputs reach scripts through environment variables, not `${{ }}`.
- gitleaks scans for secrets in pre-commit.
