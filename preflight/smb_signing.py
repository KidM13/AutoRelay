"""
AutoRelay — preflight SMB signing check.

Determines whether SMB signing is required, enabled-but-optional, or
disabled on a target's SMB service.

How it works:
  - Opens a TCP connection to port 445.
  - Sends an SMB2 NEGOTIATE request with signing enabled in our
    SecurityMode (we advertise that we support it).
  - Reads the SMB2 NEGOTIATE response and inspects the SecurityMode
    field the server returned.

  The server's SecurityMode has two bits we care about:
    - 0x01 SIGNING_ENABLED : the server supports signing
    - 0x02 SIGNING_REQUIRED: the server requires signing

Why this matters:
  NTLM relay to SMB only works if the relay target does NOT require
  signing. If SIGNING_REQUIRED is set, the relayed session will fail
  at the signing step and no useful session is established.

  This check runs against the RELAY TARGETS, not the coercion target.
  The coercion target's signing state is irrelevant; the relay target's
  is everything.

Dialect handling:
  We advertise SMB 3.0.2, 3.0, 2.1, and 2.0.2 — in strictly descending
  order (the SMB2 spec requires this; some servers reject otherwise).

  We deliberately omit 0x0311 (SMB 3.1.1) because SMB 3.1.1 requires
  negotiate contexts (pre-auth integrity, encryption caps, signing
  algorithms) that we don't send. Windows tolerates a bare 3.1.1
  negotiate and downgrades; Samba and some appliances reject the whole
  request with STATUS_INVALID_PARAMETER. Signing state is identical
  across 2.1 through 3.0.2, so we stop at 3.0.2 and get maximum
  compatibility.

Safety:
  - No authentication attempt.
  - No credentials sent.
  - No session established past NEGOTIATE.
  - Sockets closed in a finally block; no leaks on error paths.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Iterable

from util.log import get_logger
from util.net import PORT_SMB
from .report import Check, PreflightReport

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# SMB2 constants
# ---------------------------------------------------------------------------

SMB2_PROTOCOL_ID = b"\xfeSMB"
SMB2_NEGOTIATE = 0x0000

# SMB2 SecurityMode bits
SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

# SMB2 dialect constants
SMB2_DIALECT_0202 = 0x0202
SMB2_DIALECT_0210 = 0x0210
SMB2_DIALECT_0300 = 0x0300
SMB2_DIALECT_0302 = 0x0302
SMB2_DIALECT_0311 = 0x0311  # defined for reference; not advertised

# States our parser can return
SIGNING_REQUIRED = "required"
SIGNING_ENABLED  = "enabled"     # supported but not required
SIGNING_DISABLED = "disabled"
SIGNING_UNKNOWN  = "unknown"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class _Smb2ErrorResponse(Exception):
    """Raised when the server returns an SMB2 error instead of a
    NEGOTIATE response."""
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"SMB2 error 0x{status:08x}")


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class SmbSigningResult:
    host: str
    state: str                    # one of the SIGNING_* constants
    security_mode: int | None     # raw value from the server, if we got one
    dialect: int | None           # negotiated dialect
    error: str = ""

    @property
    def is_blocker(self) -> bool:
        return self.state == SIGNING_REQUIRED

    @property
    def is_viable(self) -> bool:
        """True if relay-to-SMB is possible (signing not required)."""
        return self.state in (SIGNING_ENABLED, SIGNING_DISABLED)


# ---------------------------------------------------------------------------
# Wire-level SMB2 negotiate
# ---------------------------------------------------------------------------

def _build_smb2_negotiate() -> bytes:
    """
    Build a minimal SMB2 NEGOTIATE request.

    Layout (little-endian unless noted):
      NetBIOS session header (4 bytes): 0x00 + 3-byte length
      SMB2 header (64 bytes):
        ProtocolId (4):      b'\\xfeSMB'
        StructureSize (2):   0x0040 (64)
        CreditCharge (2):    0x0000
        Status (4):          0x00000000
        Command (2):         0x0000 (NEGOTIATE)
        CreditRequest (2):   0x001f
        Flags (4):           0x00000000
        NextCommand (4):     0x00000000
        MessageId (8):       0x0000000000000000
        Reserved (4):        0x00000000
        TreeId (4):          0x00000000
        SessionId (8):       0x0000000000000000
        Signature (16):      zeros
      SMB2 NEGOTIATE request body (36 + 2*N bytes):
        StructureSize (2):   0x0024 (36)
        DialectCount (2):    N
        SecurityMode (2):    SIGNING_ENABLED
        Reserved (2):        0x0000
        Capabilities (4):    0x00000000
        ClientGuid (16):     zeros
        ClientStartTime (8): 0x0000000000000000
        Dialects (2*N):      one u16 per dialect, descending order
    """
    # Descending order. No 0x0311 (SMB 3.1.1) — see module docstring.
    dialects = [
        SMB2_DIALECT_0302,   # 3.0.2
        SMB2_DIALECT_0300,   # 3.0
        SMB2_DIALECT_0210,   # 2.1
        SMB2_DIALECT_0202,   # 2.0.2
    ]

    # SMB2 header
    header = b"".join([
        SMB2_PROTOCOL_ID,                        # ProtocolId
        struct.pack("<H", 64),                   # StructureSize
        struct.pack("<H", 0),                    # CreditCharge
        struct.pack("<I", 0),                    # Status
        struct.pack("<H", SMB2_NEGOTIATE),       # Command
        struct.pack("<H", 0x001f),               # CreditRequest
        struct.pack("<I", 0),                    # Flags
        struct.pack("<I", 0),                    # NextCommand
        struct.pack("<Q", 0),                    # MessageId
        struct.pack("<I", 0),                    # Reserved
        struct.pack("<I", 0),                    # TreeId
        struct.pack("<Q", 0),                    # SessionId
        b"\x00" * 16,                            # Signature
    ])
    assert len(header) == 64, f"SMB2 header must be 64 bytes, got {len(header)}"

    # Negotiate body, before dialects
    dialects_blob = b"".join(struct.pack("<H", d) for d in dialects)
    body = b"".join([
        struct.pack("<H", 36),                   # StructureSize
        struct.pack("<H", len(dialects)),        # DialectCount
        struct.pack("<H", SMB2_NEGOTIATE_SIGNING_ENABLED),  # SecurityMode
        struct.pack("<H", 0),                    # Reserved
        struct.pack("<I", 0),                    # Capabilities
        b"\x00" * 16,                            # ClientGuid
        struct.pack("<Q", 0),                    # ClientStartTime
        dialects_blob,
    ])

    smb2_packet = header + body

    # NetBIOS session service header: 1 byte type (0x00) + 3 bytes length
    length = len(smb2_packet)
    netbios = b"\x00" + length.to_bytes(3, "big")

    return netbios + smb2_packet


def _parse_smb2_negotiate_response(data: bytes) -> tuple[int, int] | None:
    """
    Parse an SMB2 NEGOTIATE response.

    Returns (security_mode, dialect) on success.

    Raises _Smb2ErrorResponse if the server returned an error status.

    Returns None if the response is not a NEGOTIATE response at all.
    """
    if len(data) < 4 + 64 + 6:
        return None

    # Skip NetBIOS header (4 bytes)
    payload = data[4:]

    # Verify protocol ID
    if payload[:4] != SMB2_PROTOCOL_ID:
        return None

    # SMB2 header fields we need
    header = payload[:64]
    status  = int.from_bytes(header[8:12], "little")
    command = int.from_bytes(header[12:14], "little")

    if status != 0:
        raise _Smb2ErrorResponse(status)

    if command != SMB2_NEGOTIATE:
        return None

    # Negotiate response body follows the 64-byte header
    body = payload[64:]
    if len(body) < 6:
        return None

    structure_size, security_mode, dialect = struct.unpack("<HHH", body[:6])
    if structure_size != 0x41:
        # Not a NEGOTIATE response body
        return None

    return security_mode, dialect


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes or return None on premature close."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Public check
# ---------------------------------------------------------------------------

def check_host(host: str, timeout: float = 5.0) -> SmbSigningResult:
    """
    Probe SMB signing state on a single host.

    Opens TCP to 445, sends SMB2 NEGOTIATE, reads response, closes.
    Never authenticates. Never sends a session setup.
    """
    request = _build_smb2_negotiate()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, PORT_SMB))
    except socket.timeout:
        sock.close()
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                "connect timeout")
    except ConnectionRefusedError:
        sock.close()
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                "connection refused")
    except OSError as e:
        sock.close()
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                f"connect error: {e}")

    try:
        sock.sendall(request)

        header = _recv_exact(sock, 4)
        if header is None:
            return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                    "no response")

        msg_len = int.from_bytes(header[1:4], "big")
        if msg_len < 64 or msg_len > 65536:
            return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                    f"implausible message length {msg_len}")

        body = _recv_exact(sock, msg_len)
        if body is None:
            return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                    "short response")

        full = header + body

    except socket.timeout:
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                "read timeout")
    except OSError as e:
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                f"read error: {e}")
    finally:
        sock.close()

    try:
        parsed = _parse_smb2_negotiate_response(full)
    except _Smb2ErrorResponse as e:
        status_name = {
            0xC000000D: "STATUS_INVALID_PARAMETER",
            0xC00000BB: "STATUS_NOT_SUPPORTED",
            0xC00000A5: "STATUS_ACCESS_DENIED",
            0xC000006D: "STATUS_LOGON_FAILURE",
        }.get(e.status, "unknown")
        return SmbSigningResult(
            host, SIGNING_UNKNOWN, None, None,
            error=f"server rejected negotiate: {status_name} ({e})",
        )

    if parsed is None:
        return SmbSigningResult(host, SIGNING_UNKNOWN, None, None,
                                "not an SMB2 negotiate response")

    security_mode, dialect = parsed

    if security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED:
        state = SIGNING_REQUIRED
    elif security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED:
        state = SIGNING_ENABLED
    else:
        state = SIGNING_DISABLED

    return SmbSigningResult(host, state, security_mode, dialect)


# ---------------------------------------------------------------------------
# Report integration
# ---------------------------------------------------------------------------

def run(
    relay_targets: Iterable[str],
    report: PreflightReport,
    timeout: float = 5.0,
) -> dict[str, SmbSigningResult]:
    """
    Check SMB signing on each relay target, add Check objects, and return
    the raw results for downstream use.
    """
    relay_targets = list(relay_targets)
    if not relay_targets:
        return {}

    log.info(f"smb_signing: checking {len(relay_targets)} relay target(s)")

    results: dict[str, SmbSigningResult] = {}
    for host in relay_targets:
        result = check_host(host, timeout=timeout)
        results[host] = result
        _emit_check(host, result, report)

    return results


def _emit_check(
    host: str,
    result: SmbSigningResult,
    report: PreflightReport,
) -> None:
    if result.state == SIGNING_REQUIRED:
        report.add(Check(
            name=f"smb_signing.{host}",
            category="smb_signing",
            target=host,
            passed=False,
            severity="blocker",
            detail="SMB signing REQUIRED — relay-to-SMB will fail on this host",
            evidence={
                "security_mode": hex(result.security_mode) if result.security_mode is not None else None,
                "dialect": hex(result.dialect) if result.dialect is not None else None,
                "signing_enabled": True,
                "signing_required": True,
            },
            remediation=(
                "This is the secure configuration; no action needed. "
                "Consider other relay targets, or pivot to LDAP relay "
                "if LDAP signing is not enforced."
            ),
        ))

    elif result.state == SIGNING_ENABLED:
        report.add(Check(
            name=f"smb_signing.{host}",
            category="smb_signing",
            target=host,
            passed=True,
            severity="info",
            detail="SMB signing enabled but NOT required — relay-to-SMB viable",
            evidence={
                "security_mode": hex(result.security_mode) if result.security_mode is not None else None,
                "dialect": hex(result.dialect) if result.dialect is not None else None,
                "signing_enabled": True,
                "signing_required": False,
            },
            remediation=(
                "Enforce SMB signing via GPO: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                "Also apply to member servers, not just DCs."
            ),
        ))

    elif result.state == SIGNING_DISABLED:
        report.add(Check(
            name=f"smb_signing.{host}",
            category="smb_signing",
            target=host,
            passed=True,
            severity="warning",
            detail="SMB signing DISABLED — relay-to-SMB fully viable",
            evidence={
                "security_mode": hex(result.security_mode) if result.security_mode is not None else None,
                "dialect": hex(result.dialect) if result.dialect is not None else None,
                "signing_enabled": False,
                "signing_required": False,
            },
            remediation=(
                "Enable SMB signing via GPO: "
                "'Microsoft network server: Digitally sign communications (always)' = Enabled, "
                "and 'Microsoft network client: Digitally sign communications (always)' = Enabled. "
                "Signing disabled is a finding on its own, independent of this assessment."
            ),
        ))

    else:  # unknown / error
        report.add(Check(
            name=f"smb_signing.{host}",
            category="smb_signing",
            target=host,
            passed=None,
            severity="warning",
            detail=f"SMB signing state could not be determined: {result.error}",
            evidence={
                "error": result.error,
            },
            remediation=(
                "Verify manually: run `nmap --script smb2-security-mode -p 445 <host>` "
                "or check the host's GPO settings. This check could not complete."
            ),
        ))


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight.smb_signing
# ---------------------------------------------------------------------------

def _main() -> int:
    from util.log import setup
    setup(log_dir="logs/_selftest", level="INFO", color=True)

    report = PreflightReport(target="127.0.0.1", profile_name="goad")
    run(["127.0.0.1"], report, timeout=2.0)
    report.finalize()
    print(report.render_console(color=False))

    print("\n--- unreachable host ---")
    report2 = PreflightReport(target="192.0.2.1", profile_name="goad")
    run(["192.0.2.1"], report2, timeout=1.0)
    report2.finalize()
    print(report2.render_console(color=False))

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
