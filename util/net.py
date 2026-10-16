"""
AutoRelay — small networking helpers.

Deliberately minimal. No protocol logic here; just TCP reachability,
host resolution, and target-list parsing. Protocol-specific code lives
in the preflight modules.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from .log import get_logger

log = get_logger(__name__)


# Common ports we care about in this project.
PORT_SMB = 445
PORT_NETBIOS = 139
PORT_LDAP = 389
PORT_LDAPS = 636
PORT_MSRPC = 135
PORT_KERBEROS = 88

PORT_NAMES = {
    PORT_SMB: "smb",
    PORT_NETBIOS: "netbios",
    PORT_LDAP: "ldap",
    PORT_LDAPS: "ldaps",
    PORT_MSRPC: "msrpc",
    PORT_KERBEROS: "kerberos",
}


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    host: str
    port: int
    state: str          # "open" | "closed" | "filtered" | "error"
    detail: str = ""


def tcp_ping(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """
    Attempt a TCP connect. Returns a PortResult.

    - "open"     : connect succeeded
    - "closed"   : RST received (host reachable, port not listening)
    - "filtered" : no response within timeout (firewall dropping)
    - "error"    : resolution failure or other socket error
    """
    try:
        ip = resolve_host(host)
    except socket.gaierror as e:
        return PortResult(host, port, "error", f"resolve failed: {e}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return PortResult(host, port, "open")
    except socket.timeout:
        return PortResult(host, port, "filtered", "timeout")
    except ConnectionRefusedError:
        return PortResult(host, port, "closed", "connection refused")
    except OSError as e:
        return PortResult(host, port, "error", str(e))
    finally:
        sock.close()


def resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4 address. Pass-through if already IP."""
    try:
        ipaddress.IPv4Address(host)
        return host
    except ipaddress.AddressValueError:
        return socket.gethostbyname(host)


def is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


# ---------------------------------------------------------------------------
# Target list parsing
# ---------------------------------------------------------------------------

def parse_targets(spec: str | list[str] | None) -> list[str]:
    """
    Parse a target specification into a list of hosts.

    Accepts:
      - "host1,host2,host3"   (comma-separated string)
      - ["host1", "host2"]    (list of strings)
      - "host1"               (single host)
      - None / ""             (empty list)

    Does NOT expand CIDR ranges. Ranges come in a later stage, and only
    against a scope file. For now, explicit hosts only.
    """
    if spec is None:
        return []
    if isinstance(spec, list):
        items = spec
    else:
        items = spec.split(",")

    result: list[str] = []
    for raw in items:
        host = raw.strip()
        if not host:
            continue
        if "/" in host:
            # CIDR not yet supported — refuse rather than silently ignore.
            raise ValueError(
                f"CIDR ranges are not supported yet: '{host}'. "
                f"Pass explicit hosts."
            )
        if host not in result:
            result.append(host)
    return result


# ---------------------------------------------------------------------------
# Self-test — run with: python -m util.net
# ---------------------------------------------------------------------------

def _main() -> int:
    print("parse_targets tests:")
    print("  'a,b,c'         ->", parse_targets("a,b,c"))
    print("  'a, b , a'      ->", parse_targets("a, b , a"))
    print("  ['x','y']       ->", parse_targets(["x", "y"]))
    print("  None            ->", parse_targets(None))
    print("  ''              ->", parse_targets(""))
    try:
        parse_targets("10.0.0.0/24")
    except ValueError as e:
        print("  '10.0.0.0/24'   -> raises:", e)

    print("\nresolve_host tests:")
    for h in ["127.0.0.1", "localhost"]:
        try:
            print(f"  {h:<12} -> {resolve_host(h)}")
        except Exception as e:
            print(f"  {h:<12} -> error: {e}")

    print("\ntcp_ping tests (against localhost):")
    # Port 22 is usually open on Kali; port 9 is usually closed.
    for port, label in [(22, "ssh (likely open)"), (9, "discard (likely closed)")]:
        r = tcp_ping("127.0.0.1", port, timeout=1.0)
        print(f"  port {port:<5} ({label:<22}) -> {r.state}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
