"""
AutoRelay — Security Findings and Result Models.

Implements structured findings representing security observations, vulnerability
assessments, impact classifications, and defensive remediation guidance according
to the project architecture and module interfaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

from .remediation import RemediationGuidance, get_remediation_guidance


# ---------------------------------------------------------------------------
# Enums: Severity and Status
# ---------------------------------------------------------------------------

class FindingSeverity(str, Enum):
    """
    Standard severity ratings following industry security assessment conventions.
    Ordered from highest impact to informational.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, val: str) -> FindingSeverity:
        """Parse and normalize a severity string, handling aliases and case."""
        if not isinstance(val, str):
            raise ValueError(f"Severity must be a string, got {type(val).__name__}")

        norm = val.strip().upper()
        if norm in cls.__members__:
            return cls[norm]

        # Handle preflight aliases
        alias_map = {
            "BLOCKER": cls.HIGH,
            "WARNING": cls.MEDIUM,
            "INFORMATIONAL": cls.INFO,
        }
        if norm in alias_map:
            return alias_map[norm]

        raise ValueError(
            f"Invalid severity '{val}'. Must be one of: "
            f"{', '.join(cls.__members__.keys())}"
        )

    @property
    def rank(self) -> int:
        """Numeric rank for sorting findings by severity (5 = CRITICAL, 1 = INFO)."""
        ranks = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        return ranks.get(self, 0)


class FindingStatus(str, Enum):
    """
    Assessment finding status as defined in MODULE_INTERFACES.md.
    """
    PASS = "PASS"        # Security control verified active and effective
    FAIL = "FAIL"        # Security control missing, inactive, or weak
    UNKNOWN = "UNKNOWN"  # Inconclusive probe, lack of credentials, or unsupported check
    ERROR = "ERROR"      # Protocol, network, or transport error during check

    @classmethod
    def from_str(cls, val: str) -> FindingStatus:
        """Parse and normalize a status string."""
        if not isinstance(val, str):
            raise ValueError(f"Status must be a string, got {type(val).__name__}")

        norm = val.strip().upper()
        if norm in cls.__members__:
            return cls[norm]

        raise ValueError(
            f"Invalid status '{val}'. Must be one of: "
            f"{', '.join(cls.__members__.keys())}"
        )


# ---------------------------------------------------------------------------
# Sensitive Data Redaction
# ---------------------------------------------------------------------------

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"hash", re.IGNORECASE),
    re.compile(r"cred(ential)?", re.IGNORECASE),
    re.compile(r"auth_key", re.IGNORECASE),
    re.compile(r"private_key", re.IGNORECASE),
]

SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"(?:aad3b435b51404eeaad3b435b51404ee:)?[0-9a-fA-F]{32}"),  # NTLM hash
]


def redact_sensitive_value(value: Any) -> Any:
    """Recursively redact sensitive tokens, passwords, and hashes from data structures."""
    if isinstance(value, dict):
        redacted = {}
        for k, v in value.items():
            if any(p.search(str(k)) for p in SENSITIVE_KEY_PATTERNS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_value(v)
        return redacted
    elif isinstance(value, list):
        return [redact_sensitive_value(v) for v in value]
    elif isinstance(value, str):
        result = value
        for p in SENSITIVE_VALUE_PATTERNS:
            result = p.sub("[REDACTED_HASH]", result)
        return result
    return value


# ---------------------------------------------------------------------------
# Finding Model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Standardized security finding representing an assessment observation,
    its defensive status, severity, impact, and verified remediation guidance.
    """
    finding_id: str
    title: str
    target: str
    severity: FindingSeverity
    status: FindingStatus
    description: str
    category: str = "general"
    evidence: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    remediation: str = ""
    remediation_guidance: Optional[RemediationGuidance] = None
    references: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    check_id: Optional[str] = None

    def __post_init__(self) -> None:
        # Validate required fields
        if not self.finding_id or not isinstance(self.finding_id, str):
            raise ValueError("finding_id must be a non-empty string")
        if not self.title or not isinstance(self.title, str):
            raise ValueError("title must be a non-empty string")
        if not self.target or not isinstance(self.target, str):
            raise ValueError("target must be a non-empty string")

        # Normalize severity and status
        if isinstance(self.severity, str):
            self.severity = FindingSeverity.from_str(self.severity)
        if isinstance(self.status, str):
            self.status = FindingStatus.from_str(self.status)

        # check_id defaults to finding_id for MODULE_INTERFACES.md compatibility
        if not self.check_id:
            self.check_id = self.finding_id

        # Redact sensitive values from evidence
        if self.evidence:
            self.evidence = redact_sensitive_value(self.evidence)

    @property
    def details(self) -> str:
        """Alias for description per MODULE_INTERFACES.md."""
        return self.description

    @details.setter
    def details(self, val: str) -> None:
        self.description = val

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding into a clean serializable dictionary."""
        data: dict[str, Any] = {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "target": self.target,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp,
        }
        if self.remediation_guidance:
            data["remediation_guidance"] = self.remediation_guidance.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Reconstruct a Finding from a dictionary."""
        d = dict(data)
        guidance_data = d.pop("remediation_guidance", None)
        guidance = RemediationGuidance(**guidance_data) if guidance_data else None

        # Handle details alias if present
        if "details" in d and "description" not in d:
            d["description"] = d.pop("details")

        finding = cls(
            finding_id=d["finding_id"],
            title=d["title"],
            target=d["target"],
            severity=FindingSeverity.from_str(d["severity"]),
            status=FindingStatus.from_str(d["status"]),
            description=d.get("description", ""),
            category=d.get("category", "general"),
            evidence=d.get("evidence", {}),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            remediation_guidance=guidance,
            references=d.get("references", []),
            timestamp=d.get("timestamp", datetime.now().isoformat(timespec="seconds")),
            check_id=d.get("check_id"),
        )
        return finding


# ---------------------------------------------------------------------------
# Preflight Check Conversion
# ---------------------------------------------------------------------------

def finding_from_check(check: Any) -> Finding:
    """
    Convert a preflight Check object into a structured Finding.

    Distinguishes attacker viability from defensive security posture:
      - SMB Signing: Required = PASS (secure); Enabled/Disabled = FAIL (vulnerable to relay)
      - LDAP Signing: Enforced = PASS (secure); Not enforced = FAIL (vulnerable to relay)
      - Coercion: Interface exposed = FAIL (potential exposure); Unavailable = PASS; Denied = UNKNOWN
      - Reachability: Port open = PASS / INFO; Host unreachable = FAIL / LOW
    """
    name = getattr(check, "name", "")
    category = getattr(check, "category", "")
    target = getattr(check, "target", "")
    passed = getattr(check, "passed", None)
    detail = getattr(check, "detail", "")
    evidence = getattr(check, "evidence", {}) or {}
    existing_remediation = getattr(check, "remediation", "")

    # Look up defensive guidance from knowledge base
    guidance = get_remediation_guidance(name, check_category=category, detail=detail)

    title = name
    description = detail
    impact = ""
    references: list[str] = []
    if guidance:
        references = list(guidance.references)

    # 1. SMB Signing
    if category == "smb_signing":
        signing_req = evidence.get("signing_required")
        signing_enb = evidence.get("signing_enabled")

        if signing_req is True:
            status = FindingStatus.PASS
            severity = FindingSeverity.INFO
            title = f"SMB Signing Enforced on {target}"
            description = "SMB signing is strictly enforced. Relayed SMB authentication is rejected."
            impact = "No exposure. Replay and relay of NTLM sessions to SMB will fail during negotiation."
        elif signing_enb is True and signing_req is False:
            status = FindingStatus.FAIL
            severity = FindingSeverity.HIGH
            title = f"SMB Signing Not Required on {target}"
            description = (
                "SMB signing is supported but not required. Clients and servers negotiate "
                "unsigned communications by default."
            )
            impact = (
                "Permits NTLM authentication relay attacks. Attackers can intercept or coerce "
                "NTLM authentication and relay it to this SMB server to access shares or execute code."
            )
        elif signing_enb is False:
            status = FindingStatus.FAIL
            severity = FindingSeverity.HIGH
            title = f"SMB Signing Disabled on {target}"
            description = "SMB signing is completely disabled on this server."
            impact = "Critical exposure to NTLM relay and traffic modification across the local network."
        elif passed is None:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"SMB Signing Assessment Inconclusive on {target}"
            description = f"Could not determine SMB signing state: {detail}"
            impact = "SMB signing configuration could not be confirmed. Manual verification required."
        else:
            status = FindingStatus.ERROR
            severity = FindingSeverity.LOW
            title = f"SMB Check Error on {target}"
            description = detail

    # 2. LDAP Signing
    elif category == "ldap_signing":
        integrity = evidence.get("ldap_server_integrity")
        error = evidence.get("error")

        if integrity is not None and integrity >= 2:
            status = FindingStatus.PASS
            severity = FindingSeverity.INFO
            title = f"LDAP Signing Enforced on {target}"
            description = "LDAP server integrity is configured to require signing."
            impact = "Protects Domain Controller from unsigned LDAP binds and relayed NTLM authentication."
        elif integrity == 0:
            status = FindingStatus.FAIL
            severity = FindingSeverity.HIGH
            title = f"LDAP Server Signing Not Enforced on {target}"
            description = "The Domain Controller permits unsigned SASL/NTLM LDAP binds."
            impact = (
                "Enables NTLM relay directly to Active Directory. Attackers can abuse coerced "
                "computer accounts to manipulate directory objects, configure delegation, or extract data."
            )
        elif passed is None or error:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"LDAP Signing Inconclusive on {target}"
            description = f"LDAP signing state could not be verified: {error or detail}"
            impact = "RootDSE query did not expose LDAPServerIntegrity. Authenticated inspection required."
        else:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"LDAP Signing Status Unknown on {target}"

    # 3. Coercion Probe
    elif category == "coercion_probe":
        state = evidence.get("state", "")
        error = evidence.get("error", "")

        if state == "available" or (passed is True and "open" in detail.lower()):
            status = FindingStatus.FAIL
            severity = FindingSeverity.MEDIUM
            title = f"Coercion Interface Bound: {name}"
            description = f"Named pipe RPC interface is accessible without error: {detail}"
            impact = (
                "The RPC interface is exposed. If unpatched or unconstrained, adversaries "
                "can leverage this interface to coerce target machine authentication."
            )
        elif state == "denied" or passed is None:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"Coercion Probe Inconclusive (Access Denied): {name}"
            description = (
                "Anonymous access to the RPC named pipe was denied. Windows DCs restrict "
                "anonymous pipe access by default."
            )
            impact = (
                "The interface may still be callable from an authenticated domain session. "
                "Does not indicate the interface is disabled."
            )
        elif state == "unavailable":
            status = FindingStatus.PASS
            severity = FindingSeverity.INFO
            title = f"Coercion Interface Unavailable: {name}"
            description = f"Named pipe or RPC interface is not exposed on target: {detail}"
            impact = "Target host does not expose this coercion endpoint."
        else:
            status = FindingStatus.ERROR
            severity = FindingSeverity.LOW
            title = f"Coercion Probe Error: {name}"
            description = f"Probe encountered an error: {error or detail}"
            impact = "Could not communicate with the RPC endpoint."

    # 4. Reachability
    elif category == "reachability":
        if passed is False and "not reachable" in detail.lower():
            status = FindingStatus.FAIL
            severity = FindingSeverity.LOW
            title = f"Host Unreachable: {target}"
            description = detail
            impact = "Target host is unreachable or not responding on probed assessment ports."
        elif passed is False:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"Port Filtered or Unreachable: {name}"
            description = detail
            impact = "Network filtering or firewall may be obstructing traffic."
        elif passed is None:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"Port Status Inconclusive: {name}"
            description = detail
            impact = "Probing returned an ambiguous or error state."
        else:
            status = FindingStatus.PASS
            severity = FindingSeverity.INFO
            title = f"Service Reachable: {name}"
            description = detail
            impact = "Service port is reachable as expected for normal network operations."

    # 5. Generic Fallback
    else:
        if passed is True:
            status = FindingStatus.PASS
            severity = FindingSeverity.INFO
            title = f"Assessment Passed: {name}"
        elif passed is False:
            status = FindingStatus.FAIL
            severity = FindingSeverity.MEDIUM
            title = f"Assessment Weakness: {name}"
        else:
            status = FindingStatus.UNKNOWN
            severity = FindingSeverity.LOW
            title = f"Assessment Inconclusive: {name}"

        impact = "Potential configuration exposure or inconclusive observation."

    # Format remediation text
    remediation_text = existing_remediation
    if guidance and not remediation_text:
        remediation_text = guidance.format_remediation_summary()
    elif not remediation_text:
        remediation_text = "Review security configuration and enforce hardened Active Directory baselines."

    return Finding(
        finding_id=name,
        check_id=name,
        title=title,
        target=target,
        severity=severity,
        status=status,
        description=description,
        category=category,
        evidence=evidence,
        impact=impact,
        remediation=remediation_text,
        remediation_guidance=guidance,
        references=references,
    )


# ---------------------------------------------------------------------------
# Assessment Report Container
# ---------------------------------------------------------------------------

@dataclass
class AssessmentReport:
    """
    Consolidated assessment report containing metadata, structured findings,
    severity distributions, and executive summaries.
    """
    target: str
    profile_name: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)

    def findings_by_severity(self, severity: FindingSeverity) -> list[Finding]:
        """Filter findings by specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def findings_by_status(self, status: FindingStatus) -> list[Finding]:
        """Filter findings by specific status."""
        return [f for f in self.findings if f.status == status]

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity rank descending, then title."""
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.title))

    def summary(self) -> dict[str, Any]:
        """Produce numerical breakdown of findings by severity and status."""
        sev_counts = {s.value: 0 for s in FindingSeverity}
        stat_counts = {s.value: 0 for s in FindingStatus}

        for f in self.findings:
            sev_counts[f.severity.value] += 1
            stat_counts[f.status.value] += 1

        return {
            "total_findings": len(self.findings),
            "severity_counts": sev_counts,
            "status_counts": stat_counts,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert entire assessment report into a clean dictionary."""
        return {
            "report_title": "AutoRelay Assessment & Remediation Report",
            "metadata": {
                "target": self.target,
                "profile_name": self.profile_name,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "assessment_type": "authorized_active_directory_preflight",
                **self.metadata,
            },
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def from_preflight_report(preflight_rep: Any) -> AssessmentReport:
    """
    Construct an AssessmentReport from an existing PreflightReport instance.
    """
    target = getattr(preflight_rep, "target", "")
    profile_name = getattr(preflight_rep, "profile_name", "")
    started_at = getattr(preflight_rep, "started_at", "")
    finished_at = getattr(preflight_rep, "finished_at", "")
    checks = getattr(preflight_rep, "checks", []) or []

    report = AssessmentReport(
        target=target,
        profile_name=profile_name,
        started_at=started_at or datetime.now().isoformat(timespec="seconds"),
        finished_at=finished_at or datetime.now().isoformat(timespec="seconds"),
    )

    for check in checks:
        finding = finding_from_check(check)
        report.add_finding(finding)

    return report
