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

from config import ConfigError, ScopeViolation, build_profile_from_args
from preflight import run as run_preflight
from util import log as log_setup
from util.net import parse_targets
from coercion.registry import ModuleRegistry
from coercion.loader import build_registry


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_SCOPE_VIOLATION = 3
EXIT_BLOCKERS = 4         # preflight ran, found blockers
EXIT_UNEXPECTED = 5


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autorelay",
        description=(
            "Authorized Active Directory assessment tool. "
            "Stage 1: preflight viability checks for an NTLM relay chain."
        ),
        epilog=(
            "Preflight is read-only. It performs no coercion, no relay, "
            "and no authentication. Use --profile goad for lab testing "
            "and --profile live --scope <file> for authorized engagements."
        ),
    )
    parser.add_argument(
        "--profile", default=None,
        help="Configuration profile: 'goad' (default) or 'live'",
    )
    parser.add_argument(
        "--scope", default=None,
        help="Path to scope file (required for 'live' profile)",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Non-interactive (rejected in 'live' profile)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Force DEBUG logging regardless of profile",
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
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.render_markdown(), encoding="utf-8")
        log.info(f"markdown report written to {path}")
        if not args.quiet:
            print(f"\nMarkdown report: {path}")

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json(), encoding="utf-8")
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

    parser.error(f"unknown command: {args.command}")
    return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
