"""
AutoRelay — preflight LDAP signing / channel binding check.

Determines whether the DC enforces:
  - LDAP server signing (LDAPServerIntegrity)
  - LDAP channel binding (LdapEnforceChannelBinding)

Why this matters:
  NTLM relay to LDAP only works if the DC does not require signing. If
  signing is enforced, the LDAP SASL bind with integrity fails and the
  relayed session cannot perform LDAP operations (create objects, modify
  ACLs, etc.).

How it works:
  - Impacket's LDAPConnection opens the socket inside __init__ (no
    explicit connect() call in v0.13+).
  - We issue an anonymous search against the rootDSE and read whatever
    attributes the DC exposes.
  - LDAPServerIntegrity is not exposed via rootDSE on most modern DCs;
    when absent, we report "unknown" and provide a remediation note
    explaining how to check manually.
  - Channel binding is not exposed via LDAP at all; it's a registry
    policy on the DC. Reported as unknown in v1.

Safety:
  - Anonymous bind only. No credentials, no NTLM.
  - Single rootDSE read. No writes. No session beyond the read.
  - Closes the connection immediately.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable

from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

from util.log import get_logger
from util.net import PORT_LDAP, PORT_LDAPS
from .report import Check, PreflightReport

log = get_logger(__name__)


# LDAPServerIntegrity values (from MS-ADTS):
LDAP_INTEGRITY_NONE     = 0
LDAP_INTEGRITY_REQUIRED = 1

# States
LDAP_SIGNING_NOT_REQUIRED = "not_required"
LDAP_SIGNING_REQUIRED     = "required"
LDAP_SIGNING_UNKNOWN      = "unknown"


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class LdapSigningResult:
    host: str
    port: int
    state: str
    ldap_server_integrity: int | None
    channel_binding: int | None
    dns_hostname: str = ""
    service_name: str = ""
    error: str = ""

    @property
    def is_blocker(self) -> bool:
        return self.state == LDAP_SIGNING_REQUIRED

    @property
    def is_viable(self) -> bool:
        return self.state == LDAP_SIGNING_NOT_REQUIRED


# ---------------------------------------------------------------------------
# LDAP probe
# ---------------------------------------------------------------------------

def _read_rootdse(host: str, port: int, timeout: float) -> dict:
    """
    Anonymous bind to the target DC, read rootDSE attributes.

    In Impacket 0.13.x, the socket is opened inside __init__. There is
    no explicit connect() method. We construct the connection, run the
    search, and close.

    Returns a dict of {attribute_name: value_or_list}. Raises on failure.
    """
    # LDAPConnection constructor signature (v0.13.x):
    #   __init__(self, url, baseDN='', dstIp=None, signing=True)
    #
    # The url parameter takes the form "ldap://host" or "ldaps://host".
    # The dstIp is what the socket connects to (allows DNS bypass).
    #
    # NOTE: signing=True tells Impacket to sign LDAP traffic if the
    # server requires it during an authenticated bind. For an anonymous
    # rootDSE read, this has no effect. We leave the default.
    conn = LDAPConnection(
        f"ldap://{host}:{port}",
        baseDN="",
        dstIp=host,
    )

    # Read the rootDSE. Base DN is empty, scope is base.
    try:
        resp = conn.search(
            searchBase="",
            searchFilter="(objectClass=*)",
            attributes=[
                "dnsHostName",
                "ldapServiceName",
                "supportedSASLMechanisms",
                "supportedLDAPPolicies",
                "supportedControl",
                "LDAPServerIntegrity",       # often not present
                "LdapEnforceChannelBinding", # often not present
            ],
            scope=0,          # base
            sizeLimit=0,
            timeLimit=0,
            searchControls=None,
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass

    attrs: dict = {}
    for entry in resp:
        for attr in entry["attributes"]:
            name = attr["type"]
            values = attr["vals"]
            if len(values) == 1:
                attrs[name] = values[0]
            else:
                attrs[name] = values

    return attrs


def _parse_integrity(attrs: dict) -> int | None:
    """
    Extract LDAPServerIntegrity from rootDSE attributes.

    The value is not exposed on most modern DCs. When absent, return
    None (unknown).
    """
    if "LDAPServerIntegrity" in attrs:
        raw = attrs["LDAPServerIntegrity"]
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    return None


# ---------------------------------------------------------------------------
# Public check
# ---------------------------------------------------------------------------

def check_host(
    host: str,
    port: int = PORT_LDAP,
    timeout: float = 8.0,
) -> LdapSigningResult:
    """
    Probe LDAP signing state on a single DC.
    """
    try:
        attrs = _read_rootdse(host, port, timeout)
    except socket.timeout:
        return LdapSigningResult(host, port, LDAP_SIGNING_UNKNOWN, None, None,
                                 error="connect timeout")
    except ConnectionRefusedError:
        return LdapSigningResult(host, port, LDAP_SIGNING_UNKNOWN, None, None,
                                 error="connection refused")
    except LDAPSessionError as e:
        return LdapSigningResult(host, port, LDAP_SIGNING_UNKNOWN, None, None,
                                 error=f"ldap session error: {e}")
    except OSError as e:
        return LdapSigningResult(host, port, LDAP_SIGNING_UNKNOWN, None, None,
                                 error=f"socket error: {e}")
    except Exception as e:
        return LdapSigningResult(host, port, LDAP_SIGNING_UNKNOWN, None, None,
                                 error=f"unexpected error: {e}")

    integrity = _parse_integrity(attrs)
    channel_binding = None   # never exposed via LDAP in v1

    dns_hostname = attrs.get("dnsHostName", "")
    service_name = attrs.get("ldapServiceName", "")

    if integrity is None:
        state = LDAP_SIGNING_UNKNOWN
    elif integrity == LDAP_INTEGRITY_NONE:
        state = LDAP_SIGNING_NOT_REQUIRED
    else:
        state = LDAP_SIGNING_REQUIRED

    return LdapSigningResult(
        host=host,
        port=port,
        state=state,
        ldap_server_integrity=integrity,
        channel_binding=channel_binding,
        dns_hostname=dns_hostname,
        service_name=service_name,
    )


# ---------------------------------------------------------------------------
# Report integration
# ---------------------------------------------------------------------------

def run(
    dc_targets: Iterable[str],
    report: PreflightReport,
    port: int = PORT_LDAP,
    timeout: float = 8.0,
) -> dict[str, LdapSigningResult]:
    """
    Check LDAP signing on each DC target, add Check objects, return results.
    """
    dc_targets = list(dc_targets)
    if not dc_targets:
        return {}

    log.info(f"ldap_signing: checking {len(dc_targets)} DC target(s)")

    results: dict[str, LdapSigningResult] = {}
    for host in dc_targets:
        result = check_host(host, port=port, timeout=timeout)
        results[host] = result
        _emit_check(host, port, result, report)

    return results


def _emit_check(
    host: str,
    port: int,
    result: LdapSigningResult,
    report: PreflightReport,
) -> None:
    if result.state == LDAP_SIGNING_REQUIRED:
        report.add(Check(
            name=f"ldap_signing.{host}",
            category="ldap_signing",
            target=host,
            passed=False,
            severity="blocker",
            detail=f"LDAP signing REQUIRED on {host}:{port} — relay-to-LDAP not viable",
            evidence={
                "ldap_server_integrity": result.ldap_server_integrity,
                "channel_binding": result.channel_binding,
                "dns_hostname": result.dns_hostname,
                "service_name": result.service_name,
            },
            remediation=(
                "This is the secure configuration. No action needed. "
                "Consider relay-to-SMB if SMB signing is not enforced, "
                "or another coercion vector / relay target."
            ),
        ))

    elif result.state == LDAP_SIGNING_NOT_REQUIRED:
        report.add(Check(
            name=f"ldap_signing.{host}",
            category="ldap_signing",
            target=host,
            passed=True,
            severity="info",
            detail=f"LDAP signing NOT enforced on {host}:{port} — relay-to-LDAP viable",
            evidence={
                "ldap_server_integrity": result.ldap_server_integrity,
                "channel_binding": result.channel_binding,
                "dns_hostname": result.dns_hostname,
                "service_name": result.service_name,
            },
            remediation=(
                "Enforce LDAP signing via GPO: "
                "Computer Configuration > Policies > Windows Settings > "
                "Security Settings > Local Policies > Security Options > "
                "'Domain controller: LDAP server signing requirements' = Require signing. "
                "Also enable LDAP channel binding: "
                "'Domain controller: LDAP server channel binding token requirements' = Always. "
                "Note: enforcement should be rolled out carefully — legacy clients "
                "that do not support signing will break."
            ),
        ))

    else:  # unknown
        report.add(Check(
            name=f"ldap_signing.{host}",
            category="ldap_signing",
            target=host,
            passed=None,
            severity="warning",
            detail=(
                f"LDAP signing state could not be determined on "
                f"{host}:{port}: {result.error or 'attribute not present in rootDSE'}"
            ),
            evidence={
                "error": result.error,
                "ldap_server_integrity": result.ldap_server_integrity,
                "channel_binding": result.channel_binding,
                "dns_hostname": result.dns_hostname,
                "service_name": result.service_name,
            },
            remediation=(
                "LDAPServerIntegrity is not exposed via the rootDSE on "
                "most modern DCs. Verify manually on the DC: "
                "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters "
                "/v LDAPServerIntegrity. "
                "Value 1 = signing required; 0 = not required. "
                "Also check LdapEnforceChannelBinding on the same key."
            ),
        ))


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight.ldap_signing
# ---------------------------------------------------------------------------

def _main() -> int:
    from util.log import setup
    setup(log_dir="logs/_selftest", level="INFO", color=True)

    report = PreflightReport(target="127.0.0.1", profile_name="goad")
    run(["127.0.0.1"], report, timeout=2.0)
    report.finalize()
    print(report.render_console(color=False))

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
