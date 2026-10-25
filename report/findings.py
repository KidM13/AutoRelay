"""
AutoRelay — structured document model for reporting.

Takes the raw PreflightReport and translates it into a structured
summary suitable for a client-facing document.

This separates the "what did the tool find" (checks) from the "what
does it mean for the client" (findings).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from preflight.report import PreflightReport, Check
from .remediation import get_remediation


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    check: Check
    remediation: str


@dataclass
class FindingsDocument:
    target: str
    profile_name: str
    generated_at: str
    is_viable: bool
    summary_text: str
    blockers: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    info: list[Finding] = field(default_factory=list)
    unknowns: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_document(report: PreflightReport) -> FindingsDocument:
    """
    Transform a flat PreflightReport into a structured FindingsDocument.
    """
    doc = FindingsDocument(
        target=report.target,
        profile_name=report.profile_name,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_viable=report.ok_to_proceed(),
        summary_text="",
    )

    for check in report.checks:
        # Determine state for remediation lookup
        if check.passed is True:
            state = "available" if check.category in ("coercion_probe", "reachability") else "success"
            # For smb/ldap, success means it was viable (e.g. not required)
            if check.category in ("smb_signing", "ldap_signing"):
                # Extract from detail string, e.g., "SMB signing enabled but NOT required"
                if "REQUIRED" in check.detail or "required" in check.detail.lower():
                    state = "required"
                elif "NOT required" in check.detail or "NOT enforced" in check.detail:
                    state = "not_required"
                else:
                    state = "unknown"
        elif check.passed is False:
            state = check.severity  # blocker/warning
            if check.category == "smb_signing":
                state = "required" # only blocker for smb is required
        else:
            state = "unknown"

        # Special handling for coercion probe states based on evidence
        if check.category == "coercion_probe":
            if "state" in check.evidence:
                state = check.evidence["state"]
            elif check.passed is None:
                state = "denied"

        # Get remediation text
        remediation = get_remediation(check.category, check.name, state)
        
        # If the check already had inline remediation (legacy), we could use it,
        # but we're transitioning to the central repo. Let's stick with central.
        finding = Finding(check=check, remediation=remediation)

        # Categorize
        if check.passed is None:
            doc.unknowns.append(finding)
        elif check.passed is False and check.severity == "blocker":
            doc.blockers.append(finding)
        elif check.passed is False and check.severity == "warning":
            doc.warnings.append(finding)
        else:
            doc.info.append(finding)

    # Build Executive Summary
    doc.summary_text = _generate_summary(doc)
    return doc


def _generate_summary(doc: FindingsDocument) -> str:
    """Generate a human-readable executive summary paragraph."""
    target = doc.target
    
    if doc.is_viable and not doc.unknowns and not doc.warnings:
        return (
            f"The preflight assessment against **{target}** indicates that the "
            f"target is vulnerable to an NTLM relay attack. All necessary "
            f"conditions (SMB/LDAP signing disabled, coercion vectors available) "
            f"are met. An authorized red team should proceed to Stage 3."
        )
    
    if not doc.is_viable:
        blockers_text = ", ".join([f.check.name.split('.')[-1] for f in doc.blockers])
        return (
            f"The preflight assessment against **{target}** indicates that the "
            f"NTLM relay chain **cannot** proceed in its current state. "
            f"Critical blockers were identified: {blockers_text}. "
            f"These configurations actively prevent the attack."
        )
    
    if doc.unknowns:
        return (
            f"The preflight assessment against **{target}** identified no "
            f"immediate blockers, but **{len(doc.unknowns)} condition(s) could "
            f"not be determined**. This is common on hardened systems where "
            f"anonymous probing is restricted. Manual verification may be required "
            f"to confirm viability."
        )

    return (
        f"The preflight assessment against **{target}** completed successfully. "
        f"Review the findings below for details."
    )
