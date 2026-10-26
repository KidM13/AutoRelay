# AutoRelay

**AutoRelay** is an authorized Active Directory assessment tool designed to automate the NTLM relay assessment workflow.

It coordinates preflight checks, relay server management, coercion modules, and report generation to help security teams assess NTLM relay exposure in authorized environments.

## Features

- **Preflight Assessment:** Checks target reachability, SMB signing, LDAP signing, and coercion availability.
- **Relay Orchestration:** Manages the relay process and monitors output for intercepted authentication sessions.
- **Coercion Dispatcher:** Supports multiple coercion techniques, including PetitPotam, DFSCoerce, and PrinterBug, where implemented and available.
- **Safety Guardrails:** Enforces scope restrictions in live mode to help prevent out-of-scope activity.
- **Reporting:** Generates assessment reports in Markdown, HTML, and JSON formats, depending on the configured features.

## Requirements

- **Operating system:** Linux (Kali Linux, Ubuntu, or Debian) or WSL.
- **Python:** 3.10 or higher.
- **Privileges:** `sudo` may be required for operations that bind to privileged ports, such as TCP port 445.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/KidM13/AutoRelay.git
cd AutoRelay
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Verify the installation

```bash
python autorelay.py --help
```

## Usage

AutoRelay provides two execution profiles.

| Profile | Purpose |
|---|---|
| `goad` | Intended for controlled lab environments, such as GOAD. |
| `live` | Intended for authorized engagements and requires an explicit scope file. |

Use the profile and commands supported by your installed version of AutoRelay. Run assessments only against systems for which you have explicit authorization.

### 1. Preflight assessment (read-only)

Run preflight checks to evaluate the target environment without executing the full relay workflow.

```bash
python autorelay.py --profile goad preflight \
  --target 192.168.56.10 \
  --relay-targets 192.168.56.10 \
  --html report.html \
  --json report.json
```

### 2. Prepare the engagement scope

Before using the `live` profile, create a scope file from the provided template.

```bash
cp scope.example.yaml scope.yaml
nano scope.yaml
```

Add only the targets covered by your authorization. Keep the actual `scope.yaml` private and do not commit it to version control.

### 3. Run an authorized assessment

The following examples illustrate the intended command format. Replace the example addresses and account details with values from your authorized lab or engagement.

#### Automated coercion

```bash
sudo .venv/bin/python autorelay.py \
  --profile live \
  --scope scope.yaml \
  run \
  --target 10.10.10.5 \
  --relay-targets 10.10.10.5 \
  --listener-ip 10.10.10.100 \
  --timeout 60
```

Coercion behavior depends on the target configuration, available modules, permissions, and security patches.

#### Authenticated coercion

If the implementation supports authenticated coercion, provide authorized test credentials using the options documented by the CLI. Avoid putting real passwords directly into shell history.

Check the available options before running:

```bash
python autorelay.py run --help
```

#### Manual trigger mode

If supported by your installed version, `--no-coerce` can be used to disable automated coercion and allow a controlled manual demonstration.

```bash
sudo .venv/bin/python autorelay.py \
  --profile live \
  --scope scope.yaml \
  run \
  --target 10.10.10.5 \
  --relay-targets 10.10.10.5 \
  --listener-ip 10.10.10.100 \
  --no-coerce \
  --timeout 120
```

## Engagement Scope Configuration

Use `scope.example.yaml` as the starting point for your scope file. The following is an example of valid YAML structure; adjust the fields to match the schema expected by your implementation.

```yaml
engagement:
  client: "Acme Corp"
  authorized_by: "Jane Doe (CISO)"
  authorization_ref: "SOW-2026-001"
  start_date: "2026-01-01"
  end_date: "2026-12-31"

targets:
  # Systems that may be used as coercion targets
  coercion:
    - "10.10.10.10"
    - "10.10.10.11"

  # Systems explicitly authorized as relay targets
  relay:
    - "10.10.10.10"
    - "10.10.10.11"

# Systems or networks that must never be contacted
excluded:
  - "10.10.10.1"       # Firewall
  - "10.10.10.0/24"    # Example excluded subnet

# Operational restrictions
constraints:
  no_persistence: true
  no_data_exfil: true
  no_dos: true
  working_hours_only: false
```

**Important:** Confirm the exact scope schema in the project implementation before using this example. Never include real engagement credentials or confidential client information in a public repository.

## Project Structure

```text
AutoRelay/
├── autorelay.py              # CLI entry point
├── config.py                 # Configuration and scope enforcement
├── config.yaml               # Profile configuration, if used
├── scope.example.yaml        # Example engagement scope
├── requirements.txt          # Runtime dependencies
├── preflight/                # Read-only assessment checks
├── coercion/                 # Coercion module interfaces and implementations
├── relay/                    # Relay and assessment components
├── report/                   # Report generation
├── util/                     # Logging and networking utilities
├── tests/                    # Automated tests
└── docs/
    ├── SRS.md                # Software Requirements Specification
    ├── ARCHITECTURE.md       # System architecture
    └── MODULE_INTERFACES.md  # Component interface documentation
```

The tree above is representative. Refer to the repository for the current directory structure.

## Video of the project
``` video

   https://drive.google.com/file/d/1rT6l7aJuqatuGDTjSQI7VdZHKFE37g0F/view?usp=sharing

```
## Documentation

- [Software Requirements Specification](https://github.com/KidM13/AutoRelay/blob/main/docs/SRS.md)
- [Architecture](https://github.com/KidM13/AutoRelay/blob/main/docs/ARCHITECTURE.md)
- [Module Interfaces](https://github.com/KidM13/AutoRelay/blob/main/docs/MODULE_INTERFACES.md)
- [Contributing Guidelines](https://github.com/KidM13/AutoRelay/blob/main/CONTRIBUTING.md)

Review the module interface documentation before implementing or integrating a component.

## Authorization and Safety

AutoRelay is intended only for authorized security assessments and controlled laboratory environments.

- Obtain explicit authorization before testing any system.
- Keep all targets within the approved engagement scope.
- Do not commit real scope files, credentials, or confidential engagement data.
- Follow the project's safety controls and applicable rules of engagement.
