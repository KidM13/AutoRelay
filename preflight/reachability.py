"""
AutoRelay — preflight reachability check.

TCP-only. Determines which of the ports we care about are open, closed,
or filtered on each target. No protocol negotiation, no authentication,
no offensive traffic.

This is deliberately the first check because every other check depends
on it. If port 445 is closed, there is no point negotiating SMB. If port
135 is filtered, coercion vectors cannot fire.

Output: one Check per (target, port) pair, plus one summary Check per
target indicating overall reachability.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from util.log import get_logger
from util.net import (
    PortResult,
    tcp_ping,
    PORT_SMB,
    PORT_NETBIOS,
    PORT_LDAP,
    PORT_LDAPS,
    PORT_MSRPC,
    PORT_KERBEROS,
)
from .report import Check, PreflightReport

log = get_logger(__name__)


# Ports we probe, in order of importance for the NTLM relay chain.
# The order matters only for output readability.
PROBE_PORTS: list[tuple[int, str, str]] = [
    # (port, service_name, why_this_matters)
    (PORT_SMB,      "smb",      "relay target; SMB signing check"),
    (PORT_MSRPC,    "msrpc",    "coercion vectors (PetitPotam, DFScoerce)"),
    (PORT_LDAP,     "ldap",     "relay target; directory queries"),
    (PORT_LDAPS,    "ldaps",    "relay target; channel binding applies"),
    (PORT_NETBIOS,  "netbios",  "legacy SMB"),
    (PORT_KERBEROS, "kerberos", "indicates domain controller"),
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(
    targets: Iterable[str],
    report: PreflightReport,
    timeout: float = 3.0,
    max_workers: int = 8,
) -> dict[str, dict[int, PortResult]]:
    """
    Probe all (target, port) pairs, add Check objects to the report, and
    return a lookup dict {target: {port: PortResult}} for downstream use.

    Concurrent across (target, port) pairs, capped at max_workers.
    """
    targets = list(targets)
    if not targets:
        return {}

    jobs: list[tuple[str, int]] = []
    for t in targets:
        for port, _svc, _why in PROBE_PORTS:
            jobs.append((t, port))

    log.info(f"reachability: probing {len(jobs)} (target, port) pairs across "
             f"{len(targets)} target(s), timeout={timeout}s")

    results: dict[str, dict[int, PortResult]] = {t: {} for t in targets}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(tcp_ping, t, port, timeout): (t, port)
            for t, port in jobs
        }
        for fut in as_completed(futures):
            t, port = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                log.exception(f"reachability: tcp_ping crashed for {t}:{port}")
                result = PortResult(t, port, "error", str(e))
            results[t][port] = result

    # Build checks — one summary check per target, one detail check per
    # open/closed port. Filtered and error ports get detail checks too
    # because they are diagnostically important.

    for target in targets:
        port_results = results[target]
        _emit_target_checks(target, port_results, report)

    return results


# ---------------------------------------------------------------------------
# Check construction
# ---------------------------------------------------------------------------

def _emit_target_checks(
    target: str,
    port_results: dict[int, PortResult],
    report: PreflightReport,
) -> None:
    open_ports = [p for p, r in port_results.items() if r.state == "open"]
    closed_ports = [p for p, r in port_results.items() if r.state == "closed"]
    filtered_ports = [p for p, r in port_results.items() if r.state == "filtered"]
    error_ports = [p for p, r in port_results.items() if r.state == "error"]

    smb_open = port_results.get(PORT_SMB, PortResult(target, PORT_SMB, "error")).state == "open"
    rpc_open = port_results.get(PORT_MSRPC, PortResult(target, PORT_MSRPC, "error")).state == "open"
    ldap_open = port_results.get(PORT_LDAP, PortResult(target, PORT_LDAP, "error")).state == "open"
    kerb_open = port_results.get(PORT_KERBEROS, PortResult(target, PORT_KERBEROS, "error")).state == "open"

    # Overall reachability check
    if error_ports and not open_ports:
        # Completely unreachable
        report.add(Check(
            name=f"reachability.{target}.overall",
            category="reachability",
            target=target,
            passed=False,
            severity="blocker",
            detail=f"host not reachable ({error_ports[0].state} on all probed ports)",
            evidence={
                "errors": {p: port_results[p].detail for p in error_ports},
            },
        ))
        return

    if not open_ports:
        report.add(Check(
            name=f"reachability.{target}.overall",
            category="reachability",
            target=target,
            passed=False,
            severity="blocker",
            detail=f"no probed ports open ({len(filtered_ports)} filtered, {len(closed_ports)} closed)",
            evidence={
                "open": [],
                "closed": closed_ports,
                "filtered": filtered_ports,
            },
        ))
        return

    # Host is reachable — emit a positive summary
    roles: list[str] = []
    if kerb_open:
        roles.append("DC")
    if smb_open:
        roles.append("smb")
    if ldap_open:
        roles.append("ldap")

    report.add(Check(
        name=f"reachability.{target}.overall",
        category="reachability",
        target=target,
        passed=True,
        severity="info",
        detail=f"host reachable ({len(open_ports)} port(s) open; likely {'/'.join(roles) or 'unknown'})",
        evidence={
            "open": open_ports,
            "closed": closed_ports,
            "filtered": filtered_ports,
        },
    ))

    # Detail checks for the ports that matter to the chain
    for port, svc, why in PROBE_PORTS:
        r = port_results.get(port)
        if r is None:
            continue

        if r.state == "open":
            report.add(Check(
                name=f"reachability.{target}.{port}",
                category="reachability",
                target=target,
                passed=True,
                severity="info",
                detail=f"TCP {port} ({svc}) open — {why}",
                evidence={"port": port, "service": svc, "state": r.state},
            ))
        elif r.state == "filtered":
            report.add(Check(
                name=f"reachability.{target}.{port}",
                category="reachability",
                target=target,
                passed=False,
                severity="warning",
                detail=f"TCP {port} ({svc}) filtered — firewall may block {why}",
                evidence={"port": port, "service": svc, "state": r.state,
                          "detail": r.detail},
            ))
        elif r.state == "closed":
            report.add(Check(
                name=f"reachability.{target}.{port}",
                category="reachability",
                target=target,
                passed=True,   # closed is not a failure, just absence
                severity="info",
                detail=f"TCP {port} ({svc}) closed",
                evidence={"port": port, "service": svc, "state": r.state},
            ))
        else:  # error
            report.add(Check(
                name=f"reachability.{target}.{port}",
                category="reachability",
                target=target,
                passed=None,
                severity="warning",
                detail=f"TCP {port} ({svc}) error: {r.detail}",
                evidence={"port": port, "service": svc, "state": r.state,
                          "detail": r.detail},
            ))


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight.reachability
# ---------------------------------------------------------------------------

def _main() -> int:
    from util.log import setup

    setup(log_dir="logs/_selftest", level="INFO", color=True)

    report = PreflightReport(target="127.0.0.1", profile_name="goad")
    run(["127.0.0.1"], report, timeout=1.0)
    report.finalize()

    print(report.render_console(color=False))

    # Also test against an unreachable host to verify the failure path
    print("\n--- unreachable host test ---")
    report2 = PreflightReport(target="192.0.2.1", profile_name="goad")
    # 192.0.2.0/24 is TEST-NET-1, guaranteed not routable
    run(["192.0.2.1"], report2, timeout=1.0)
    report2.finalize()
    print(report2.render_console(color=False))

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
