# Module Interfaces

## 1. Purpose

All modules must follow consistent input, output, and error-handling conventions so the orchestrator can integrate them without depending on implementation details.

## 2. Shared Finding Structure

Each assessment finding should contain:

- `check_id`: Stable identifier for the check.
- `title`: Short finding name.
- `status`: `PASS`, `FAIL`, `UNKNOWN`, or `ERROR`.
- `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, where applicable.
- `details`: Explanation of the result.
- `evidence`: Supporting observations, excluding unnecessary secrets.
- `remediation`: Recommended corrective action.

A `PASS` means the specific check passed; it does not mean the entire environment is secure.

## 3. Module Contracts

### Preflight

Each check accepts validated target and configuration data and returns one or more structured findings.

Checks must distinguish a confirmed failure from an inconclusive result. Network errors must not be reported as successful security checks.

### Coercion

Coercion methods must accept an explicitly scoped target and validated options. They must not select additional targets independently.

### Relay

Relay operations must accept the configured relay targets and validated options. They must not infer or expand the target list.

The relay simulation and active assessment are distinct operations. A simulation exercises only the in-process session lifecycle and is not evidence of a real-world vulnerability.

Active assessment accepts explicitly configured private/lab IP addresses only. For each target it returns separate findings for:

- TCP reachability of SMB (445), LDAP (389), and LDAPS (636). A reachable port is service exposure from the assessment host, not a protocol-security result. Refused connections are `PASS`; timeouts are `UNKNOWN`; other socket failures are `ERROR`.
- SMB signing, determined from an unauthenticated SMB2/3 negotiate response. A required flag is `PASS`; supported but non-required signing, or signing not advertised, is `FAIL`; unsupported or inconclusive responses are `UNKNOWN`. Connection and protocol failures are reported as `ERROR`, except timeouts, which are `UNKNOWN`.
- LDAP signing and channel-binding policy. These server settings are not reliably established by this remote check and are returned as `UNKNOWN`. Confirm them using the specified domain-controller policy/registry state or administrator evidence.
- LDAPS TLS negotiation and certificate validation. Certificate verification is always enabled against the system trust store. An optional CA bundle adds authorized lab trust anchors; it does not disable verification. A successfully validated TLS handshake is `PASS`, an invalid certificate or failed TLS handshake is `FAIL`, a timeout is `UNKNOWN`, and connection or trust-store errors are `ERROR`.

The SMB check requires `smbprotocol>=1.15.0,<2.0`; install it with `python -m pip install -r requirements.txt`. TLS uses Python's standard `ssl` library. Neither these checks nor a `PASS`/`FAIL` finding prove that a host is exploitable or immune to relay attacks. No credentials are used, and no authentication, credential forwarding, coercion, live relay, or target discovery is performed.

Active assessment must be explicitly selected and authorized by the operator, both in the CLI and in the assessment configuration. It must not resolve hostnames, expand target ranges, or access public targets. Only RFC 1918 IPv4, loopback, link-local IPv4, and IPv6 unique-local/loopback/link-local addresses are accepted. Each network check has a validated timeout of at most three seconds and assessments are limited to 16 targets.

Example authorized lab assessment:

```powershell
python autorelay.py relay --mode assessment --authorized-lab --target 10.20.30.40 --timeout 1
```

For an authorized lab CA that is not in the system trust store, add its PEM bundle; hostname/IP certificate validation remains enabled:

```powershell
python autorelay.py relay --mode assessment --authorized-lab --target 10.20.30.40 --timeout 1 --tls-ca-file C:\lab\root-ca.pem
```

Simulation remains network-free and is selected separately:

```powershell
python autorelay.py relay --mode simulation --target lab-session
```

### Reporting

The reporting layer accepts findings and produces a readable report. It must not rerun checks or modify the original evidence.

### Utilities

Shared utilities should have narrow responsibilities, documented arguments, predictable return values, and clear error behavior.

## 4. Error Handling

- Use documented exceptions for unrecoverable module failures.
- Return `UNKNOWN` when a check cannot reach a reliable conclusion.
- Use `ERROR` for an operation that failed unexpectedly.
- Never convert exceptions or missing evidence into a successful result.
- Avoid logging credentials, tokens, or other sensitive values.

## 5. Integration Rules

- Agree on function signatures before implementing cross-module calls.
- Use shared data structures rather than module-specific dictionaries with inconsistent fields.
- Keep CLI argument parsing inside the CLI layer.
- Keep terminal formatting inside the reporting or presentation layer.
- Add unit tests for each public module interface.

## 6. Interface Changes

Changes to shared structures or public function signatures must be discussed with the project lead and documented before dependent modules are updated.