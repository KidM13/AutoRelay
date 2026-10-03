# AutoRelay

Authorized Active Directory assessment tool for identifying NTLM relay exposure, performing controlled relay testing, and generating remediation reports.

## Description

AutoRelay helps security teams assess NTLM relay exposure in Active Directory environments before performing controlled security tests.

The tool performs preflight checks, identifies relevant security weaknesses and coercion vectors, orchestrates controlled relay testing, records activity, and generates remediation guidance.

AutoRelay is designed for authorized security assessments and controlled laboratory environments.

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
```
## Authorization

AutoRelay is intended only for authorized security assessments and controlled laboratory environments.

Do not use this tool against systems without explicit authorization.

