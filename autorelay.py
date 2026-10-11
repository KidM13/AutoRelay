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
    """"placeholder for future controlled relay functionality"""
    print("relay functionality is not implemented yet")
    return 0
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

    # relay placeholder
    relay_parser = subparsers.add_parser(
        "relay",
        help="Controlled relay testing (not yet implemented).",
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

