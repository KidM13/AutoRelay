# AutoRelay Architecture

## 1. Overview

AutoRelay uses a modular Python CLI architecture. The CLI validates arguments and coordinates assessment modules. Modules return structured findings that the reporting layer formats for the user.

## 2. Components

- **CLI and orchestrator (`autorelay.py`):** Parses arguments, loads configuration, enforces execution order, invokes modules, and handles application-level errors.
- **Preflight (`preflight/`):** Checks reachability and supported SMB/LDAP security settings before further activity.
- **Coercion (`coercion/`):** Contains separately implemented, explicitly scoped coercion methods.
- **Relay (`relay/`):** Coordinates authorized relay operations and manages session state.
- **Reporting (`report/`):** Stores findings, maps them to remediation guidance, and generates reports.
- **Utilities (`util/`):** Provides shared logging and networking helpers.
- **Post actions (`post/`):** Contains optional modules that must remain disabled unless explicitly requested.
- **Tests (`tests/`):** Covers module behavior, error handling, and integration contracts.

## 3. Execution Flow

1. Parse and validate CLI arguments.
2. Load and validate configuration.
3. Display the authorization notice and verify the requested scope.
4. Run preflight checks.
5. Record findings and determine whether subsequent operations are permitted.
6. Run only explicitly requested and authorized operations.
7. Generate the final report and exit with an appropriate status.

The initial release should prioritize steps 1–4 and 7, with structured findings and remediation reporting.

## 4. Safety Boundaries

- Preflight checks must precede coercion and relay operations.
- Coercion targets and relay targets must be configured separately.
- No operation may expand beyond the explicitly supplied scope.
- Post actions require an explicit opt-in flag.
- Unknown results must never be silently treated as successful checks.

## 5. Design Principles

- Keep protocol operations separate from presentation.
- Use shared result structures between modules.
- Prefer deterministic remediation mappings over unnecessary AI dependencies.
- Make components independently testable.
- Avoid duplicate reporting and hidden side effects.