"""
AutoRelay — preflight coercion vector probe.

Determines which coercion interfaces are present and bindable on a
target Windows host.

Interfaces probed:
  - MS-EFSRPC (PetitPotam)  : \\pipe\\efsrpc
  - MS-DFSNM  (DFScoerce)   : \\pipe\\netdfs
  - MS-RPRN   (PrinterBug)  : \\pipe\\spoolss

How it works:
  For each interface, we bind via DCE/RPC over SMB (TCP 445). Binding
  is an idempotent, read-only operation. It does NOT invoke any method.

What "available" means:
  - bind OK                 : interface present and bindable
  - interface not registered: pipe exists, RPC UUID not supported
  - pipe not found          : pipe missing on the target
  - access denied           : SMB pipe open denied (see below)
  - transport error         : could not reach the target at all

Important nuance about "access denied":
  Windows Server DCs (and modern Windows generally) require an
  authenticated SMB session to open most named pipes. An anonymous
  probe — which is what preflight does — will be denied with
  STATUS_ACCESS_DENIED before the RPC bind even happens.

  This is NOT evidence the interface is missing. It means we cannot
  determine the interface state without credentials. The correct
  report is "unknown" (passed=None), not "not available."

  Firing the actual coercion (Stage 4) uses an authenticated session
  or a relayed identity, which is why it can reach the pipe even when
  preflight cannot.

Safety:
  - Bind only. No method invocation.
  - No authentication coercion.
  - No traffic to our own listener.
  - Sockets closed immediately after bind.
"""

from __future__ import annotations

import socket
import uuid as _uuid
from dataclasses import dataclass
from typing import Iterable

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError as SmbSessionError

from util.log import get_logger
from util.net import PORT_SMB
from .report import Check, PreflightReport

log = get_logger(__name__)


# SMB status codes we care about
STATUS_ACCESS_DENIED     = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_INVALID   = 0xC0000033
STATUS_BAD_NETWORK_NAME      = 0xC00000CC


# ---------------------------------------------------------------------------
# Interface definitions
# ---------------------------------------------------------------------------

@dataclass
class CoercionVector:
    name: str
    display_name: str
    pipe: str
    interface_uuid: str
    major_version: int
    minor_version: int
    description: str
    remediation: str


VECTORS: list[CoercionVector] = [
    CoercionVector(
        name="petitpotam",
        display_name="PetitPotam (MS-EFSRPC)",
        pipe="efsrpc",
        interface_uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        major_version=1,
        minor_version=0,
        description=(
            "MS-EFSRPC exposed; can coerce machine account auth via "
            "EfsRpcOpenFileRaw"
        ),
        remediation=(
            "Apply the November 2021 patches (KB5005413 and related). "
            "Disable NTLM on Domain Controllers where feasible. "
            "Enable Extended Protection for Authentication (EPA) on "
            "AD CS endpoints. Enforce SMB signing and LDAP signing "
            "across the domain."
        ),
    ),
    CoercionVector(
        name="dfscoerce",
        display_name="DFScoerce (MS-DFSNM)",
        pipe="netdfs",
        interface_uuid="12345778-1234-abcd-ef00-0123456789ab",
        major_version=4,
        minor_version=0,
        description=(
            "MS-DFSNM exposed; can coerce machine account auth via "
            "NetrDfsRemoveStdRoot / NetrDfsAddStdRoot"
        ),
        remediation=(
            "No vendor patch as of writing; MS-DFSNM is exposed by "
            "design on DCs. Mitigate by disabling NTLM on DCs, "
            "enforcing SMB signing, and monitoring for unexpected "
            "machine-account authentications to attacker-controlled "
            "hosts."
        ),
    ),
    CoercionVector(
        name="printerbug",
        display_name="PrinterBug (MS-RPRN)",
        pipe="spoolss",
        interface_uuid="12345678-1234-abcd-ef00-0123456789ab",
        major_version=1,
        minor_version=0,
        description=(
            "MS-RPRN exposed; can coerce machine account auth via "
            "RpcRemoteFindFirstPrinterChangeNotificationEx"
        ),
        remediation=(
            "Disable the Print Spooler service on Domain Controllers "
            "and other non-print-server hosts: "
            "Stop-Service -Name Spooler -Force; "
            "Set-Service -Name Spooler -StartupType Disabled. "
            "Apply MS guidance for restricting spooler exposure."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

# Result states
STATE_AVAILABLE   = "available"       # bind succeeded
STATE_UNAVAILABLE = "unavailable"     # pipe or interface genuinely missing
STATE_DENIED      = "denied"          # SMB pipe open denied (anonymous)
STATE_ERROR       = "error"           # transport or protocol error


@dataclass
class CoercionProbeResult:
    host: str
    vector: str
    state: str                    # one of STATE_* above
    error: str = ""
    detail: str = ""

    @property
    def available(self) -> bool:
        return self.state == STATE_AVAILABLE

    @property
    def determined(self) -> bool:
        """True if we have a definite answer (available or unavailable)."""
        return self.state in (STATE_AVAILABLE, STATE_UNAVAILABLE)


# ---------------------------------------------------------------------------
# RPC bind
# ---------------------------------------------------------------------------

def _probe_vector(
    host: str,
    vector: CoercionVector,
    timeout: float,
) -> CoercionProbeResult:
    """
    Attempt to bind to a single coercion interface.

    Does NOT invoke any method on the bound interface.
    """
    string_binding = f"ncacn_np:{host}[\\pipe\\{vector.pipe}]"

    try:
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
    except SmbSessionError as e:
        # The most important case: Windows DCs deny anonymous access
        # to named pipes. This tells us nothing about whether the
        # interface exists — only that we couldn't reach it without
        # credentials.
        code = None
        try:
            code = e.get_error_code()
        except Exception:
            pass
        if code == STATUS_ACCESS_DENIED or "STATUS_ACCESS_DENIED" in str(e):
            return CoercionProbeResult(
                host, vector.name, STATE_DENIED,
                error=(
                    "SMB pipe open denied (anonymous session rejected). "
                    "Interface state cannot be determined without credentials."
                ),
                detail="access_denied_at_smb_tree_connect",
            )
        if code in (STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_NAME_INVALID,
                    STATUS_BAD_NETWORK_NAME) or "OBJECT_NAME_NOT_FOUND" in str(e):
            return CoercionProbeResult(
                host, vector.name, STATE_UNAVAILABLE,
                error=f"named pipe \\\\pipe\\\\{vector.pipe} not found on target",
                detail="pipe_missing",
            )
        return CoercionProbeResult(
            host, vector.name, STATE_ERROR,
            error=f"SMB session error: {e}",
        )
    except socket.timeout:
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error="connect timeout")
    except ConnectionRefusedError:
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error="connection refused")
    except OSError as e:
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error=f"socket error: {e}")
    except Exception as e:
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error=f"transport error: {e}")

    # SMB pipe open succeeded. Now try the RPC bind.
    try:
        dce.bind(_uuid.UUID(vector.interface_uuid).bytes_le)
    except DCERPCException as e:
        try:
            dce.disconnect()
        except Exception:
            pass
        err_str = str(e)
        # The specific DCE/RPC error for "no such interface on this endpoint"
        if "abstract_syntax_not_supported" in err_str or "provider_rejection" in err_str:
            return CoercionProbeResult(
                host, vector.name, STATE_UNAVAILABLE,
                error=f"interface UUID not registered on \\pipe\\{vector.pipe}",
                detail="abstract_syntax_not_supported",
            )
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error=f"bind rejected: {e}")
    except Exception as e:
        try:
            dce.disconnect()
        except Exception:
            pass
        return CoercionProbeResult(host, vector.name, STATE_ERROR,
                                   error=f"bind error: {e}")

    try:
        dce.disconnect()
    except Exception:
        pass

    return CoercionProbeResult(host, vector.name, STATE_AVAILABLE,
                               detail=f"interface {vector.pipe} bindable")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(
    targets: Iterable[str],
    report: PreflightReport,
    timeout: float = 8.0,
) -> dict[str, dict[str, CoercionProbeResult]]:
    """
    Probe all coercion vectors against all targets.

    Returns {host: {vector_name: CoercionProbeResult}}.
    Adds Check objects to the report: one per (host, vector) pair.
    """
    targets = list(targets)
    if not targets:
        return {}

    log.info(
        f"coercion_probe: probing {len(VECTORS)} vectors across "
        f"{len(targets)} target(s)"
    )

    results: dict[str, dict[str, CoercionProbeResult]] = {}

    for host in targets:
        results[host] = {}
        for vector in VECTORS:
            log.debug(f"coercion_probe: {host} vector={vector.name}")
            result = _probe_vector(host, vector, timeout)
            results[host][vector.name] = result
            _emit_check(host, vector, result, report)

    return results


def _emit_check(
    host: str,
    vector: CoercionVector,
    result: CoercionProbeResult,
    report: PreflightReport,
) -> None:
    if result.state == STATE_AVAILABLE:
        report.add(Check(
            name=f"coercion_probe.{host}.{vector.name}",
            category="coercion_probe",
            target=host,
            passed=True,
            severity="info",
            detail=f"{vector.display_name} interface bindable — {vector.description}",
            evidence={
                "vector": vector.name,
                "pipe": f"\\pipe\\{vector.pipe}",
                "interface_uuid": vector.interface_uuid,
                "state": result.state,
            },
            remediation=vector.remediation,
        ))

    elif result.state == STATE_UNAVAILABLE:
        report.add(Check(
            name=f"coercion_probe.{host}.{vector.name}",
            category="coercion_probe",
            target=host,
            passed=True,
            severity="info",
            detail=f"{vector.display_name} not available: {result.error}",
            evidence={
                "vector": vector.name,
                "pipe": f"\\pipe\\{vector.pipe}",
                "state": result.state,
                "error": result.error,
            },
            remediation="",
        ))

    elif result.state == STATE_DENIED:
        # Access denied — this is not "available" and not "unavailable".
        # The interface may well be present; we just can't probe it
        # anonymously. Report as unknown.
        report.add(Check(
            name=f"coercion_probe.{host}.{vector.name}",
            category="coercion_probe",
            target=host,
            passed=None,
            severity="warning",
            detail=(
                f"{vector.display_name} probe inconclusive — "
                f"{result.error}"
            ),
            evidence={
                "vector": vector.name,
                "pipe": f"\\pipe\\{vector.pipe}",
                "state": result.state,
                "error": result.error,
            },
            remediation=(
                "Verify manually from an authenticated session, or "
                "confirm during Stage 4 (authenticated coercion). "
                "Windows DCs deny anonymous named-pipe access by "
                "default, so this is expected behavior and does not "
                "indicate the interface is missing."
            ),
        ))

    else:  # STATE_ERROR
        report.add(Check(
            name=f"coercion_probe.{host}.{vector.name}",
            category="coercion_probe",
            target=host,
            passed=None,
            severity="warning",
            detail=(
                f"{vector.display_name} probe failed: {result.error}"
            ),
            evidence={
                "vector": vector.name,
                "pipe": f"\\pipe\\{vector.pipe}",
                "state": result.state,
                "error": result.error,
            },
            remediation=(
                "Investigate the transport error. Verify port 445 "
                "is reachable and SMB negotiation succeeds."
            ),
        ))


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight.coercion_probe
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
