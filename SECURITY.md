# Security policy

mcp-cross-exam sends traffic only to targets the operator names. The production guard is on by default: the runner refuses a target that is not an allowlisted fixture unless the operator overrides that refusal. Writes happen only against allowlisted targets.

Credentials are read from the environment. They are redacted from every artifact the tool writes.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub security advisories](https://github.com/smusali/mcp-cross-exam/security/advisories/new). Do not open a public issue for a security report.

## Supported versions

Only the latest release published on PyPI receives security fixes. This tree is still pre-release.
