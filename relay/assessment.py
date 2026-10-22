"""Bounded, non-authenticating checks for relay-relevant service exposure."""

from __future__ import annotations

import errno
import ipaddress
import math
import socket
import ssl
from dataclasses import dataclass
from typing import Sequence
from uuid import uuid4


class RelayAssessmentError(Exception):
    """Base exception for relay assessment failures."""


class RelayAssessmentConfigurationError(RelayAssessmentError, ValueError):
    """Raised when assessment targets or options are invalid."""


class _SMBProtocolAssessmentError(Exception):
    """Raised when SMB negotiation fails at the protocol layer."""


_ASSESSMENT_PORTS = (
    ("SMB", 445),
    ("LDAP", 389),
    ("LDAPS", 636),
)
_ALLOWED_LAB_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "::1/128",
        "fe80::/10",
    )
)
_MAX_TARGETS = 16
_MAX_TIMEOUT = 3.0


def _validated_assessment_targets(targets: Sequence[str]) -> tuple[str, ...]:
    if isinstance(targets, (str, bytes)):
        raise RelayAssessmentConfigurationError(
            "targets must be an iterable of explicit private or lab IP addresses"
        )
    try:
        normalized = tuple(targets)
    except TypeError as exc:
        raise RelayAssessmentConfigurationError(
            "targets must be an iterable of explicit private or lab IP addresses"
        ) from exc

    if not normalized:
        raise RelayAssessmentConfigurationError("at least one explicit target is required")
    if len(normalized) > _MAX_TARGETS:
        raise RelayAssessmentConfigurationError(
            f"at most {_MAX_TARGETS} explicit targets may be assessed at once"
        )
    for target in normalized:
        if not isinstance(target, str) or not target or target != target.strip():
            raise RelayAssessmentConfigurationError(
                "each target must be an explicit private or lab IP address"
            )

    validated: list[str] = []
    for target in normalized:
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise RelayAssessmentConfigurationError(
                f"target {target!r} must be an IP address, not a hostname or URL"
            ) from exc
        if not any(address in network for network in _ALLOWED_LAB_NETWORKS):
            raise RelayAssessmentConfigurationError(
                f"target {target!r} is not a permitted private or lab address"
            )
        validated.append(str(address))
    if len(set(validated)) != len(validated):
        raise RelayAssessmentConfigurationError("duplicate targets are not allowed")
    return tuple(validated)


@dataclass(frozen=True)
class RelayAssessmentConfig:
    """Explicit private/lab IP targets and bounded assessment options."""

    targets: Sequence[str]
    timeout: float = 1.0
    authorized_lab: bool = False
    tls_ca_file: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "targets", _validated_assessment_targets(self.targets))
        if self.authorized_lab is not True:
            raise RelayAssessmentConfigurationError(
                "active assessment requires explicit authorized-lab confirmation"
            )
        try:
            valid_timeout = (
                not isinstance(self.timeout, bool)
                and isinstance(self.timeout, (int, float))
                and math.isfinite(self.timeout)
                and 0 < self.timeout <= _MAX_TIMEOUT
            )
        except OverflowError:
            valid_timeout = False
        if not valid_timeout:
            raise RelayAssessmentConfigurationError(
                f"timeout must be a positive finite number no greater than {_MAX_TIMEOUT:g} seconds"
            )
        if self.tls_ca_file is not None and (
            not isinstance(self.tls_ca_file, str) or not self.tls_ca_file.strip()
        ):
            raise RelayAssessmentConfigurationError(
                "tls_ca_file must be a non-empty path when provided"
            )


def assess_targets(config: RelayAssessmentConfig) -> list[dict[str, object]]:
    """Check fixed service reachability and protocol-security observations.

    The three exposure findings describe TCP reachability only. SMB signing
    uses an unauthenticated SMB2/3 negotiate request. LDAP security settings
    that are not remotely verifiable are reported as UNKNOWN. LDAPS always
    validates its certificate against the system trust store, optionally
    augmented by ``tls_ca_file``.
    """
    if not isinstance(config, RelayAssessmentConfig):
        raise TypeError("config must be a RelayAssessmentConfig")

    findings: list[dict[str, object]] = []
    for target in config.targets:
        for service, port in _ASSESSMENT_PORTS:
            findings.append(_check_endpoint(target, service, port, config.timeout))
        findings.append(_check_smb_signing(target, config.timeout))
        findings.append(_unknown_ldap_setting(target, "signing"))
        findings.append(_unknown_ldap_setting(target, "channel_binding"))
        findings.append(_check_ldaps_tls(target, config.timeout, config.tls_ca_file))
    return findings


def _check_endpoint(
    target: str,
    service: str,
    port: int,
    timeout: float,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "mode": "active_assessment",
        "target": target,
        "service": service,
        "port": port,
    }
    try:
        with socket.create_connection((target, port), timeout=timeout):
            status = "FAIL"
            details = (
                f"TCP port {port} ({service}) accepted a connection from this "
                "assessment host. This confirms service reachability only; it "
                "does not establish relay susceptibility."
            )
            severity = "MEDIUM"
            evidence["observation"] = "connection_accepted"
            remediation = (
                "Review whether this service must be reachable from the "
                "assessment network and enforce appropriate network segmentation "
                "and protocol protections."
            )
    except TimeoutError as exc:
        status = "UNKNOWN"
        severity = "INFO"
        details = (
            f"Connection to TCP port {port} ({service}) timed out; reachability "
            "could not be determined."
        )
        evidence["observation"] = "timeout"
        evidence["error_type"] = type(exc).__name__
        remediation = "Verify connectivity and repeat the check if appropriate."
    except OSError as exc:
        if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
            status = "PASS"
            severity = "INFO"
            details = (
                f"TCP port {port} ({service}) refused the connection from this "
                "assessment host; service reachability was not confirmed."
            )
            evidence["observation"] = "connection_refused"
            remediation = "No action is indicated by this reachability check."
        else:
            status = "ERROR"
            severity = "INFO"
            details = (
                f"Could not check TCP port {port} ({service}): "
                f"{type(exc).__name__}: {exc}"
            )
            evidence["observation"] = "connection_error"
            evidence["error_type"] = type(exc).__name__
            remediation = "Resolve the reported connection error before interpreting this check."
    return {
        "check_id": f"relay.exposure.{service.lower()}",
        "title": f"{service} service reachability",
        "status": status,
        "severity": severity,
        "details": details,
        "evidence": evidence,
        "remediation": remediation,
    }


def _query_smb_signing(
    target: str,
    timeout: float,
) -> tuple[object, int, int]:
    """Negotiate SMB2/3 without credentials and return the server security flags."""
    from smbprotocol.connection import Connection, SecurityMode
    from smbprotocol.exceptions import SMBException

    connection = Connection(str(uuid4()), target, port=445, require_signing=False)
    try:
        connection.connect(timeout=timeout)
        return (
            connection.server_security_mode,
            SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED,
        )
    except SMBException as exc:
        raise _SMBProtocolAssessmentError(str(exc)) from exc
    finally:
        if connection.transport is not None:
            connection.disconnect(close=False, timeout=timeout)


def _check_smb_signing(target: str, timeout: float) -> dict[str, object]:
    evidence: dict[str, object] = {
        "mode": "active_assessment",
        "target": target,
        "service": "SMB",
        "port": 445,
        "protocol": "SMB2/3 negotiate",
        "authentication": "none",
    }
    try:
        raw_mode, enabled_flag, required_flag = _query_smb_signing(target, timeout)
    except (TimeoutError, socket.timeout) as exc:
        status = "UNKNOWN"
        severity = "INFO"
        details = f"SMB negotiation timed out: {type(exc).__name__}."
        evidence.update({"observation": "timeout", "error_type": type(exc).__name__})
        remediation = "Verify connectivity and repeat the check if appropriate."
    except OSError as exc:
        status = "ERROR"
        severity = "INFO"
        details = f"Could not connect for SMB negotiation: {type(exc).__name__}: {exc}"
        evidence.update({"observation": "connection_error", "error_type": type(exc).__name__})
        remediation = "Resolve the reported connection error before interpreting this check."
    except ImportError as exc:
        status = "ERROR"
        severity = "INFO"
        details = f"The SMB protocol dependency is unavailable: {exc}"
        evidence.update({"observation": "dependency_error", "error_type": type(exc).__name__})
        remediation = "Install the project's SMB assessment dependency and repeat the check."
    except _SMBProtocolAssessmentError as exc:
        status = "ERROR"
        severity = "INFO"
        details = f"SMB negotiation failed at the protocol layer: {exc}"
        evidence.update({"observation": "protocol_error", "error_type": type(exc).__name__})
        remediation = "Verify that the target supports SMB2/3 negotiation and repeat the check."
    except Exception as exc:
        status = "ERROR"
        severity = "INFO"
        details = f"Unexpected SMB assessment failure: {type(exc).__name__}: {exc}"
        evidence.update({"observation": "assessment_error", "error_type": type(exc).__name__})
        remediation = "Resolve the reported assessment error before interpreting this check."
    else:
        if (
            isinstance(raw_mode, bool)
            or not isinstance(raw_mode, int)
            or not isinstance(enabled_flag, int)
            or not isinstance(required_flag, int)
            or raw_mode < 0
            or raw_mode & ~(enabled_flag | required_flag)
        ):
            status = "UNKNOWN"
            severity = "INFO"
            details = (
                "The SMB response did not provide a supported signing security mode; "
                "the requirement could not be determined."
            )
            evidence.update({"observation": "inconclusive_protocol_response"})
            remediation = (
                "Confirm the SMB dialect and signing policy using server-side "
                "configuration or administrator evidence."
            )
        else:
            signing_required = bool(raw_mode & required_flag)
            signing_enabled = bool(raw_mode & enabled_flag) or signing_required
            evidence.update(
                {
                    "observation": "negotiate_security_mode",
                    "server_security_mode": raw_mode,
                    "signing_enabled": signing_enabled,
                    "signing_required": signing_required,
                }
            )
            if signing_required:
                status = "PASS"
                severity = "INFO"
                details = "The SMB server advertised signing as required during negotiation."
                remediation = "No remediation is indicated by this SMB signing check."
            elif signing_enabled:
                status = "FAIL"
                severity = "HIGH"
                details = (
                    "The SMB server advertised signing support but did not require "
                    "signing during negotiation."
                )
                remediation = (
                    "Configure the SMB server to require message signing through "
                    "the applicable server policy, then verify the negotiated setting."
                )
            else:
                status = "FAIL"
                severity = "HIGH"
                details = "The SMB server did not advertise signing as enabled or required."
                remediation = (
                    "Enable and require SMB message signing through the applicable "
                    "server policy, then verify the negotiated setting."
                )

    return {
        "check_id": "relay.smb.signing",
        "title": "SMB signing requirement",
        "status": status,
        "severity": severity,
        "details": details,
        "evidence": evidence,
        "remediation": remediation,
    }


def _unknown_ldap_setting(target: str, setting: str) -> dict[str, object]:
    if setting == "signing":
        title = "LDAP signing requirement"
        required_evidence = (
            "Domain Controller: LDAP server signing requirements Group Policy, "
            "resultant policy, or LDAPServerIntegrity at "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters."
        )
        details = (
            "LDAP signing cannot be reliably determined by this remote assessment. "
            "Port reachability and anonymous LDAP responses do not establish the "
            "server's signing policy."
        )
    elif setting == "channel_binding":
        title = "LDAP channel binding policy"
        required_evidence = (
            "Resultant domain-controller policy or the LdapEnforceChannelBinding "
            "value at HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters."
        )
        details = (
            "LDAP channel-binding policy cannot be reliably determined by this "
            "remote assessment; it is local server policy, not a port-level property."
        )
    else:
        raise ValueError(f"unsupported LDAP setting: {setting}")

    return {
        "check_id": f"relay.ldap.{setting}",
        "title": title,
        "status": "UNKNOWN",
        "severity": "INFO",
        "details": details,
        "evidence": {
            "mode": "active_assessment",
            "target": target,
            "service": "LDAP",
            "remote_setting_query": "not_supported",
            "required_evidence": required_evidence,
        },
        "remediation": (
            "Obtain the specified local configuration or administrator evidence "
            "before recording this setting as confirmed."
        ),
    }


def _check_ldaps_tls(
    target: str,
    timeout: float,
    tls_ca_file: str | None,
) -> dict[str, object]:
    trust_source = "system trust store"
    if tls_ca_file is not None:
        trust_source = f"system trust store plus {tls_ca_file}"
    evidence: dict[str, object] = {
        "mode": "active_assessment",
        "target": target,
        "service": "LDAPS",
        "port": 636,
        "certificate_validation": "required",
        "trust_source": trust_source,
    }

    try:
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        if tls_ca_file is not None:
            context.load_verify_locations(cafile=tls_ca_file)
    except (OSError, ssl.SSLError) as exc:
        status = "ERROR"
        severity = "INFO"
        details = f"Could not load the configured TLS trust store: {type(exc).__name__}: {exc}"
        evidence.update({"observation": "trust_store_error", "error_type": type(exc).__name__})
        remediation = "Check the CA file path and format, then repeat the check."
    else:
        try:
            with socket.create_connection((target, 636), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=target) as tls_socket:
                    tls_version = tls_socket.version()
        except (TimeoutError, socket.timeout) as exc:
            status = "UNKNOWN"
            severity = "INFO"
            details = f"LDAPS connection timed out: {type(exc).__name__}."
            evidence.update({"observation": "timeout", "error_type": type(exc).__name__})
            remediation = "Verify connectivity and repeat the check if appropriate."
        except ssl.SSLCertVerificationError as exc:
            status = "FAIL"
            severity = "HIGH"
            details = (
                "The LDAPS TLS handshake was rejected because certificate validation "
                f"failed: {exc}"
            )
            evidence.update(
                {
                    "observation": "certificate_invalid",
                    "certificate_validation": "failed",
                    "error_type": type(exc).__name__,
                }
            )
            remediation = (
                "Install a certificate valid for the target address and chain it to "
                "the system trust store, or provide the authorized lab CA with --tls-ca-file."
            )
        except ssl.SSLError as exc:
            status = "FAIL"
            severity = "MEDIUM"
            details = f"An LDAPS TLS session could not be established: {type(exc).__name__}: {exc}"
            evidence.update({"observation": "tls_handshake_error", "error_type": type(exc).__name__})
            remediation = (
                "Configure the service with a supported TLS certificate and protocol, "
                "then repeat the check."
            )
        except OSError as exc:
            status = "ERROR"
            severity = "INFO"
            details = f"Could not connect to LDAPS: {type(exc).__name__}: {exc}"
            evidence.update({"observation": "connection_error", "error_type": type(exc).__name__})
            remediation = "Resolve the reported connection error before interpreting this check."
        except Exception as exc:
            status = "ERROR"
            severity = "INFO"
            details = f"Unexpected LDAPS assessment failure: {type(exc).__name__}: {exc}"
            evidence.update({"observation": "assessment_error", "error_type": type(exc).__name__})
            remediation = "Resolve the reported assessment error before interpreting this check."
        else:
            status = "PASS"
            severity = "INFO"
            details = (
                "LDAPS completed a TLS handshake and the server certificate validated "
                f"against the {trust_source}."
            )
            evidence.update(
                {
                    "observation": "tls_and_certificate_valid",
                    "certificate_validation": "passed",
                    "tls_version": tls_version,
                }
            )
            remediation = "No remediation is indicated by this LDAPS TLS check."

    return {
        "check_id": "relay.ldaps.tls",
        "title": "LDAPS TLS and certificate validation",
        "status": status,
        "severity": severity,
        "details": details,
        "evidence": evidence,
        "remediation": remediation,
    }
