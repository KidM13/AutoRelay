# Software Requirements Specification (SRS)

## 1. Purpose

AutoRelay is a command-line tool for assessing and validating NTLM relay exposure in authorized Active Directory environments. It identifies configuration weaknesses and provides actionable remediation guidance.

## 2. Scope

The initial release focuses on preflight assessment, findings, and remediation reporting. Controlled relay validation will be introduced incrementally.

### In Scope
- Check target reachability and relevant SMB/LDAP security configurations.
- Identify potential NTLM relay exposure.
- Produce structured findings and remediation recommendations.
- Support explicit target configuration and clear command-line output.
- Log assessment activities and errors.

### Out of Scope
- Assessing systems without explicit authorization.
- Targeting systems outside the configured scope.
- Automatic Golden Ticket creation.
- Stealth, persistence, or evasion mechanisms.

## 3. Functional Requirements

- **FR-01:** The CLI must accept explicit assessment targets.
- **FR-02:** Preflight checks must run before any coercion or relay activity.
- **FR-03:** The tool must assess relevant SMB signing and LDAP signing/channel-binding configurations where supported.
- **FR-04:** Findings must include a status, explanation, and remediation guidance.
- **FR-05:** The tool must distinguish confirmed findings from unknown or inconclusive results.
- **FR-06:** Assessment activity and errors must be logged.
- **FR-07:** Coercion must be restricted to explicitly configured targets.
- **FR-08:** Relay operations must be restricted to explicitly configured relay targets.
- **FR-09:** Post-assessment or post-exploitation actions must require an explicit opt-in flag.
- **FR-10:** The tool must handle connection failures, invalid configuration, and unsupported checks without silently reporting success.

## 4. Non-Functional Requirements

- **Security:** Enforce target scope and safe defaults.
- **Reliability:** Report failures and inconclusive results accurately.
- **Maintainability:** Keep CLI, assessment, relay, reporting, and utility logic modular.
- **Testability:** Support unit tests using mocks and controlled fixtures.
- **Usability:** Provide clear CLI help, readable findings, and actionable errors.

## 5. Constraints

- Python 3.11 or newer.
- Impacket may be used for supported protocol operations.
- Assessments must be performed only in authorized environments.
- Unsupported checks must return an unknown or inconclusive result rather than a false pass.

## 6. Acceptance Criteria

The initial milestone is complete when:

- The CLI accepts and validates assessment arguments.
- Preflight checks produce structured findings.
- Errors and inconclusive results are handled correctly.
- Findings include appropriate remediation guidance.
- Unit tests cover normal, failure, and unknown-result cases.
- Documentation describes usage, limitations, and authorization requirements.

## 7. Testing Strategy

Use unit tests and mocked protocol responses first. Validate integrations only in an isolated, authorized lab. Do not treat a successful connection alone as proof that a security control is correctly configured.