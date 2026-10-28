# Security policy

The production guard allows a stdio command, a loopback host, and a host that matches `[target] allow`. `--target-is-not-production` still requires that allow-list match.

Credentials are read from the environment and redacted from the run directory.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub security advisories](https://github.com/smusali/mcp-cross-exam/security/advisories/new). Do not open a public issue for a security report.

## Supported versions

Only the latest release published on PyPI receives security fixes.
