# AutoRelay

Authorized Active Directory assessment tool for identifying NTLM relay exposure, simulating relay-session lifecycles in-process, and generating remediation reports.

## Description

AutoRelay helps security teams assess NTLM relay exposure in Active Directory environments before performing controlled security tests.

The tool performs preflight checks, identifies relevant security weaknesses and coercion vectors, simulates relay-session lifecycle behavior without network or authentication activity, records assessment results, and generates remediation guidance.

AutoRelay is designed for authorized security assessments and controlled laboratory environments.

## Features

- NTLM relay preflight assessment
- SMB and LDAP security checks
- Coercion vector detection
- Simulation-only relay lifecycle orchestration (no network or credential handling)
- Structured logging
- Remediation reporting
- CLI-based operation

## Relay assessment

Simulation and active assessment are separate modes. Simulation performs no network activity. Active assessment is limited to explicitly supplied authorized private/lab IPs and reports service reachability, SMB signing negotiation, LDAP signing/channel-binding evidence requirements, and LDAPS TLS/certificate validation. It does not authenticate or test relay susceptibility.

Install the SMB negotiation dependency:

python -m pip install -r requirements.txt

Example authorized lab assessment (certificate validation uses the system trust store by default):

python autorelay.py relay --mode assessment --authorized-lab --target 10.20.30.40 --timeout 1

To add an authorized lab CA bundle while retaining certificate verification:

python autorelay.py relay --mode assessment --authorized-lab --target 10.20.30.40 --timeout 1 --tls-ca-file C:\lab\root-ca.pem

See [Module Interfaces](docs/MODULE_INTERFACES.md#relay) for supported checks, finding interpretation, limits, and LDAP policy evidence requirements.

## Project Structure

autorelay.py    # CLI entry point and orchestrator
preflight/      # Vulnerability and configuration checks
coercion/       # Coercion modules
relay/          # Simulation-only relay session lifecycle
post/           # Opt-in post-exploitation actions
report/         # Findings and remediation reports
util/           # Shared utilities
tests/          # Tests and fixtures


## Documentation

- [Software Requirements Specification](docs/SRS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Module Interfaces](docs/MODULE_INTERFACES.md)
- [Contributing Guidelines](CONTRIBUTING.md)

Review the module interfaces before implementing or integrating a component.
## Authorization

AutoRelay is intended only for authorized security assessments and controlled laboratory environments.

Do not use this tool against systems without explicit authorization.
