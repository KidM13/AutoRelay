"""
AutoRelay — Relay session representation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

@dataclass
class RelaySession:
    timestamp: str
    target: str
    protocol: str
    identity: str
    status: str
    raw_line: str

# Pattern 1: The final authentication result
RELAY_AUTH_PATTERN = re.compile(
    r"\[\*\] Authenticating against (?P<protocol>\w+)://(?P<target>[^\s]+) "
    r"as (?P<identity>[^\s]+) (?P<status>SUCCEED|FAILED)"
)

# Pattern 2: The interception event (happens before auth result)
# This regex matches the exact line:
# [*] (SMB): Connection from LAB/WIN-DC01$@192.168.122.1 controlled, attacking target smb://192.168.122.38
RELAY_INTERCEPT_PATTERN = re.compile(
    r"\[\*\] \((?P<protocol>\w+)\): Connection from (?P<identity>[^@]+)@[^\s]+ controlled, "
    r"attacking target (?P<target>[^\s]+)"
)


def parse_relay_success(line: str) -> RelaySession | None:
    # Try matching the interception first
    match = RELAY_INTERCEPT_PATTERN.search(line)
    if match:
        return RelaySession(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            protocol=match.group("protocol").lower(),
            target=match.group("target"),
            identity=match.group("identity"),
            status="INTERCEPTED",
            raw_line=line.strip()
        )

    # Try matching the auth result
    match = RELAY_AUTH_PATTERN.search(line)
    if match:
        return RelaySession(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            protocol=match.group("protocol"),
            target=match.group("target"),
            identity=match.group("identity"),
            status=match.group("status"),
            raw_line=line.strip()
        )

    return None
