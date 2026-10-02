# AutoRelay

Authorized Active Directory assessment tool for identifying NTLM relay exposure, performing controlled relay testing, and generating remediation reports.

## Features

- NTLM relay preflight assessment
- SMB and LDAP security checks
- Coercion vector detection
- Controlled NTLM relay orchestration
- Structured logging
- Remediation reporting
- CLI-based operation

## Project Structure

```text
autorelay.py    # CLI entry point and orchestrator
preflight/      # Vulnerability and configuration checks
coercion/       # Coercion modules
relay/          # NTLM relay management
post/           # Opt-in post-exploitation actions
report/         # Findings and remediation reports
util/           # Shared utilities
tests/          # Tests and fixtures
