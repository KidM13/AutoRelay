"""
AutoRelay — preflight orchestrator.

Runs the four preflight checks in the correct order and produces a single
PreflightReport:

  1. reachability   — TCP connects, determines which ports are open
  2. smb_signing    — SMB2 negotiate, on each relay target
  3. ldap_signing   — LDAP rootDSE read, on each DC found in step 1
  4. coercion_probe — RPC bind, on the coercion target(s)

Order matters:
  - reachability first, because every other check depends on port state
  - smb_signing second, because it is the primary blocker to determine
  - ldap_signing third, as a fallback path if SMB relay is not viable
  - coercion_probe last, because it is the most expensive (3 RPC binds
    per target)

Nothing in this module fires any offensive traffic. It only reads.
"""

from __future__ import annotations

from typing import Iterable

from util.log import get_logger
from util.net import PORT_KERBEROS, PORT_LDAP

from . import reachability, smb_signing, ldap_signing, coercion_probe
from .report import Check, PreflightReport

log = get_logger(__name__)

__all__ = [
    "run",
    "PreflightReport",
    "Check",
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(
    target: str,
    relay_targets: Iterable[str],
    profile_name: str,
    timeout_override: dict | None = None,
) -> PreflightReport:
    """
    Run all preflight checks and return a single consolidated report.

    Args:
        target:          the primary coercion target (the host we will
                         try to coerce authentication from in Stage 4)
        relay_targets:   hosts we would relay to (typically DCs and
                         member servers with interesting privileges)
        profile_name:    for the report header only ("goad" | "live")
        timeout_override: optional dict to override default timeouts,
                          e.g. {"tcp": 5, "smb": 8, "ldap": 8, "rpc": 8}

    Returns:
        PreflightReport with all checks appended and finalized.
    """
    timeouts = {
        "tcp": 3.0,
        "smb": 5.0,
        "ldap": 8.0,
        "rpc": 8.0,
    }
    if timeout_override:
        timeouts.update(timeout_override)

    relay_targets = list(relay_targets)
    # The coercion target is also probed for reachability, but is not a
    # relay target unless explicitly listed there too.
    all_targets = list(dict.fromkeys([target] + relay_targets))  # dedup, order-preserving

    report = PreflightReport(target=target, profile_name=profile_name)

    log.info(f"preflight: target={target} relay_targets={relay_targets} "
             f"profile={profile_name}")

    # ------------------------------------------------------------------
    # 1. Reachability
    # ------------------------------------------------------------------
    log.info("preflight: [1/4] reachability")
    reach_results = reachability.run(
        all_targets,
        report,
        timeout=timeouts["tcp"],
    )

    # Determine which hosts are actually DCs (Kerberos port open).
    dcs: list[str] = []
    for host, ports in reach_results.items():
        kerb = ports.get(PORT_KERBEROS)
        if kerb and kerb.state == "open":
            dcs.append(host)
    log.info(f"preflight: detected {len(dcs)} DC(s): {dcs}")

    # Determine which relay targets even have SMB open. Skip SMB check
    # on hosts where 445 is not open — it will just fail uninterestingly.
    smb_viable_relays: list[str] = []
    for host in relay_targets:
        ports = reach_results.get(host, {})
        smb = ports.get(445)
        if smb and smb.state == "open":
            smb_viable_relays.append(host)
        else:
            state = smb.state if smb else "unprobed"
            log.info(f"preflight: skipping SMB signing check on {host} "
                     f"(port 445 {state})")

    # ------------------------------------------------------------------
    # 2. SMB signing (relay targets only)
    # ------------------------------------------------------------------
    log.info(f"preflight: [2/4] smb_signing on {len(smb_viable_relays)} host(s)")
    smb_signing.run(
        smb_viable_relays,
        report,
        timeout=timeouts["smb"],
    )

    # ------------------------------------------------------------------
    # 3. LDAP signing (DCs only)
    # ------------------------------------------------------------------
    log.info(f"preflight: [3/4] ldap_signing on {len(dcs)} host(s)")
    ldap_signing.run(
        dcs,
        report,
        timeout=timeouts["ldap"],
    )

    # ------------------------------------------------------------------
    # 4. Coercion probe (target only)
    # ------------------------------------------------------------------
    log.info(f"preflight: [4/4] coercion_probe on {target}")
    coercion_probe.run(
        [target],
        report,
        timeout=timeouts["rpc"],
    )

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------
    report.finalize()

    log.info(f"preflight: complete — "
             f"{len(report.blockers)} blocker(s), "
             f"{len(report.warnings)} warning(s), "
             f"{len(report.unknowns)} unknown(s)")

    return report


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight
# ---------------------------------------------------------------------------

def _main() -> int:
    from util.log import setup

    setup(log_dir="logs/_selftest", level="INFO", color=True)

    print("=== localhost (expected: no useful ports) ===")
    report = run(
        target="127.0.0.1",
        relay_targets=["127.0.0.1"],
        profile_name="goad",
        timeout_override={"tcp": 1, "smb": 1, "ldap": 1, "rpc": 1},
    )
    print(report.render_console(color=False))

    print()
    print("=== unreachable host (expected: blocker) ===")
    report2 = run(
        target="192.0.2.1",
        relay_targets=["192.0.2.1"],
        profile_name="goad",
        timeout_override={"tcp": 1, "smb": 1, "ldap": 1, "rpc": 1},
    )
    print(report2.render_console(color=False))

    print()
    print("=== sample markdown (truncated) ===")
    md = report.render_markdown()
    print("\n".join(md.splitlines()[:40]))

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
