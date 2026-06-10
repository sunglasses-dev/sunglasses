# Security Policy

Sunglasses is a security tool for AI-agent inputs. We take the security of the
project — and of the agents that rely on it — seriously.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of:

- **GitHub Security Advisories** — use the "Report a vulnerability" button under
  the repository's **Security** tab (preferred — coordinated disclosure built in).
- **Email** — `security@sunglasses.dev`

Please include: a description of the issue, steps to reproduce (a minimal scan
input is ideal), the affected version (`sunglasses --version`), and the impact
you observed (e.g. a bypass that lets a known attack pattern through, or a
false-positive class that breaks benign content).

## What to Expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity rating within 7 days.
- Coordinated disclosure: we'll agree on a timeline before any public detail,
  and credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope: detection bypasses (an attack pattern that should be caught but is
not), false-positive classes that block benign content, and any issue in the
scanner, CLI, or MCP server that affects trust decisions.

Out of scope: vulnerabilities in your own agent or in third-party services
Sunglasses scans for — though we're happy to help you understand a finding.

## Supported Versions

The latest published version on PyPI receives security fixes. Older versions
are not patched — please upgrade (`pip install -U sunglasses`).
