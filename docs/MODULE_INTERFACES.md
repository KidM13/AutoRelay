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