"""
AutoRelay — CLI entry point.

Stage 1 subcommand: `preflight`.

Usage:
    python autorelay.py preflight --profile goad \\
        --target 192.168.56.10 \\
        --relay-targets 192.168.56.10,192.168.56.11

    python autorelay.py preflight --profile live \\
        --scope scope.yaml \\
        --report out.md

Preflight is read-only. No coercion, no relay, no authentication.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def handle_preflight(args):
    print(f"running preflight assesment for {args.target}..")
    # module integration will be added when teammates does their function
    return 0
def handle_report(args):
    """report will be generated from existing assesment"""
    print(f"report input :{args.input}")
    # report module will be integrated here 
    return 0
def handle_relay(args):
    """Run either a local simulation or bounded protocol-security assessment."""
    if args.mode == "assessment":
        if not args.authorized_lab:
            raise ValueError(
                "active assessment requires --authorized-lab and private/lab IP targets"
            )
        from relay import RelayAssessmentConfig, assess_targets

        findings = assess_targets(
            RelayAssessmentConfig(
                tuple(args.target),
                timeout=args.timeout,
                authorized_lab=True,
                tls_ca_file=args.tls_ca_file,
            )
        )
        print(
            "Active assessment: service reachability, SMB signing, LDAP policy "
            "evidence, and LDAPS TLS validation; no relay was performed."
        )
        for finding in findings:
            evidence = finding["evidence"]
            location = evidence["target"]
            if "port" in evidence:
                location = f"{location}:{evidence['port']}"
            print(
                f"{finding['status']} [{finding['severity']}] {finding['check_id']} "
                f"({location}): "
                f"{finding['details']}"
            )
            print(f"  Remediation: {finding['remediation']}")
        return 0

    from relay import RelayConfig, RelayServer

    server = RelayServer(RelayConfig(relay_targets=tuple(args.target)))
    try:
        server.start()
        session = server.simulate_session()
        finding = session.results[0]
        print(f"Simulation session {session.session_id}: {session.state.value}")
        print("Simulation only: no network connections or real assessment were performed.")
        print(f"{finding['status']}: {finding['details']}")
        return 0
    finally:
        server.stop()


def build_parser():
    parser=argparse.ArgumentParser(
        prog="autorelay",#program name
        description="Authorized Active Directory security assessment tool.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- preflight ---
    pf = subparsers.add_parser(
        "preflight",
        help="Check whether an NTLM relay chain is viable against a target",
    )
    pf.add_argument(
        "--target", required=True,
        help="Primary coercion target (the host whose auth we would coerce)",
    )
    pf.add_argument(
        "--relay-targets", required=True,
        help="Comma-separated list of hosts we would relay to",
    )
    pf.add_argument(
        "--report", default=None,
        help="Write a Markdown report to this path",
    )
    pf.add_argument(
        "--json", default=None,
        help="Write a JSON report to this path",
    )
    pf.add_argument(
        "--quiet", action="store_true",
        help="Suppress console output of the report",
    )
        # --- modules ---
    subparsers.add_parser(
        "modules",
        help="List registered coercion modules",
    )
        # --- run-module ---
    run_module_parser = subparsers.add_parser(
        "run-module",
        help="Run a registered coercion module",
    )
    run_module_parser.add_argument(
        "--module",
        required=True,
        help="Name of the registered module",
    )
    report_parser.set_defaults(handler=handle_report)

    relay_parser = subparsers.add_parser(
        "relay",
        help="Simulate a session or assess authorized lab services and protocol security.",
    )
    relay_parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="Explicit target (simulation identifier or private/lab IP for assessment); repeatable.",
    )
    relay_parser.add_argument(
        "--mode",
        choices=("simulation", "assessment"),
        default="simulation",
        help=(
            "simulation uses no network; assessment checks TCP reachability, SMB signing, "
            "LDAP policy evidence, and LDAPS TLS."
        ),
    )
    relay_parser.add_argument(
        "--authorized-lab",
        action="store_true",
        help="Confirm these private/lab targets are explicitly authorized (required for assessment).",
    )
    relay_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-connection timeout in seconds for assessment (maximum 3).",
    )
    relay_parser.add_argument(
        "--tls-ca-file",
        help=(
            "Optional CA bundle added to the system trust store for LDAPS certificate "
            "validation; verification remains enabled."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Command: preflight
# ---------------------------------------------------------------------------

def cmd_preflight(args: argparse.Namespace, profile) -> int:
    # Parse the target list early so errors surface before any probing.
    try:
        relay_targets = parse_targets(args.relay_targets)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if not relay_targets:
        print("error: --relay-targets must not be empty", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    target = args.target.strip()
    if not target:
        print("error: --target must not be empty", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    log = log_setup.get_logger("autorelay.cli")
    log.info(f"command=preflight profile={profile.name} "
             f"target={target} relay_targets={relay_targets}")

    # Scope enforcement for the coercion target (live mode only).
    if profile.safety.hard_scope_enforcement:
        from config import enforce_scope
        try:
            enforce_scope(profile, target, "preflight")
            for rt in relay_targets:
                enforce_scope(profile, rt, "preflight")
        except ScopeViolation as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_SCOPE_VIOLATION

    # Run preflight. All timeouts come from the profile.
    try:
        report = run_preflight(
            target=target,
            relay_targets=relay_targets,
            profile_name=profile.name,
            timeout_override={
                "tcp": profile.timeouts.tcp_connect,
                "smb": profile.timeouts.smb_negotiate,
                "ldap": profile.timeouts.ldap_bind,
                "rpc": profile.timeouts.rpc_bind,
            },
        )
    except Exception as e:
        log.exception("preflight crashed")
        print(f"error: preflight failed: {e}", file=sys.stderr)
        return EXIT_UNEXPECTED

    # Console output
    if not args.quiet:
        print(report.render_console(color=profile.output.color))

    # Write reports if requested
    if args.report:
        from report import write_markdown_report
        path = write_markdown_report(report, args.report)
        log.info(f"markdown report written to {path}")
        if not args.quiet:
            print(f"\nMarkdown report: {path}")

    if args.json:
        from report import write_json_report
        path = write_json_report(report, args.json)
        log.info(f"json report written to {path}")
        if not args.quiet:
            print(f"JSON report:     {path}")

    # Exit code based on blockers
    if not report.ok_to_proceed():
        if not args.quiet:
            print(f"\n{len(report.blockers)} blocker(s) found — "
                  f"chain not viable as-is", file=sys.stderr)
        return EXIT_BLOCKERS

    return EXIT_OK

def cmd_modules() -> int:
    registry = build_registry()
    modules = registry.available()

    if not modules:
        print("No coercion modules registered.")
        return EXIT_OK

    print("Available coercion modules:")
    for name in modules:
        print(f"  - {name}")

    return EXIT_OK

def cmd_run_module(args: argparse.Namespace, profile) -> int:
    """Validate and run a registered coercion module."""

    # Check whether coercion is enabled in this profile.
    if not profile.capabilities.coercion:
        print(
            "Error: coercion is disabled for this profile.",
            file=sys.stderr,
        )
        return EXIT_CONFIG_ERROR

    # Build the registry and find the requested module.
    registry = build_registry()

    try:
        module = registry.create(args.module)
    except KeyError:
        available = ", ".join(registry.available()) or "(none)"
        print(
            f"Error: unknown module '{args.module}'. "
            f"Available modules: {available}",
            file=sys.stderr,
        )
        return EXIT_CONFIG_ERROR

    # Enforce target scope when the profile requires it.
    try:
        enforce_scope(profile, args.target, "coercion")
    except ScopeViolation as e:
        print(f"Scope violation: {e}", file=sys.stderr)
        return EXIT_SCOPE_VIOLATION

    # Dry-run validates the request but does not call module.run().
    if args.dry_run:
        print(
            f"Dry run successful: module={module.name}, "
            f"target={args.target}"
        )
        return EXIT_OK

    # Invoke the module and report its result.
    try:
        result = module.run(args.target)
    except Exception as e:
        print(f"Module error: {e}", file=sys.stderr)
        return EXIT_UNEXPECTED

    status = {
        True: "SUCCESS",
        False: "FAILURE",
        None: "UNKNOWN",
    }[result.success]

    print(f"Module:  {result.technique}")
    print(f"Target:  {result.target}")
    print(f"Status:  {status}")
    print(f"Detail:  {result.detail}")

    return EXIT_OK if result.success is not False else EXIT_UNEXPECTED


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load config + profile before anything else so errors are early.
    try:
        profile = build_profile_from_args(args)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # Set up logging according to the profile.
    level = "DEBUG" if args.debug else profile.logging.level
    log_path = log_setup.setup(
        log_dir=profile.logging.log_dir,
        level=level,
        console=profile.logging.console,
        file=profile.logging.file,
        color=profile.output.color,
    )
    log = log_setup.get_logger("autorelay.cli")
    log.info(f"profile={profile.name} mode={profile.mode} "
             f"log_file={log_path}")

    # Dispatch
    if args.command == "preflight":
        return cmd_preflight(args, profile)
    if args.command == "modules":
        return cmd_modules()
    if args.command == "run-module":
        return cmd_run_module(args, profile)

    parser.error(f"unknown command: {args.command}")
    return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
