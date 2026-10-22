import argparse
import sys


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

    # preflight command
    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Assess target security configuration.",
    )
    preflight_parser.add_argument(
        "--target",
        required=True,
        help="Explicitly authorized target hostname or IP.",
    )
    preflight_parser.set_defaults(handler=handle_preflight)

    # report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a report from assessment results.",
    )
    report_parser.add_argument(
        "--input",
        required=True,
        help="Path to an existing results file.",
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
    relay_parser.set_defaults(handler=handle_relay)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
