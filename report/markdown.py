"""
AutoRelay — Markdown Report Generator.

Transforms security assessment results, structured findings, and remediation guidance
into a professional, readable Markdown report suitable for presentation, technical
review, and audit documentation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Optional, Union

from .findings import (
    AssessmentReport,
    Finding,
    FindingSeverity,
    FindingStatus,
    from_preflight_report,
)


def _resolve_report(report_or_findings: Any) -> AssessmentReport:
    """Normalize input into an AssessmentReport instance."""
    if isinstance(report_or_findings, AssessmentReport):
        return report_or_findings

    # PreflightReport duck-typing
    if hasattr(report_or_findings, "checks") and hasattr(report_or_findings, "target"):
        return from_preflight_report(report_or_findings)

    # Iterable of Finding objects
    if isinstance(report_or_findings, Iterable):
        rep = AssessmentReport(
            target="Target Scope",
            profile_name="standard",
        )
        for item in report_or_findings:
            if isinstance(item, Finding):
                rep.add_finding(item)
            elif hasattr(item, "passed"):  # Check instance
                from .findings import finding_from_check
                rep.add_finding(finding_from_check(item))
        return rep

    raise TypeError(f"Unsupported report input type: {type(report_or_findings).__name__}")


def generate_markdown_report(
    report_or_findings: Any,
    title: str = "AutoRelay Security Assessment & Remediation Report",
) -> str:
    """
    Generate a comprehensive Markdown report from assessment data.

    Args:
        report_or_findings: AssessmentReport, PreflightReport, or list of findings/checks.
        title: Report header title.

    Returns:
        Formatted Markdown document as a string.
    """
    report = _resolve_report(report_or_findings)
    lines: list[str] = []

    # 1. Header & Title
    lines.append(f"# {title}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Assessment Scope & Metadata
    lines.append("## 1. Assessment Scope & Metadata")
    lines.append("")
    lines.append(f"- **Primary Target:** `{report.target or 'N/A'}`")
    lines.append(f"- **Configuration Profile:** `{report.profile_name or 'default'}`")
    lines.append(f"- **Assessment Started:** {report.started_at or 'N/A'}")
    lines.append(f"- **Assessment Finished:** {report.finished_at or 'In Progress / Finalized'}")
    lines.append("- **Assessment Mode:** Read-Only Educational / Defensive Audit")
    lines.append("- **Scope Authorization:** Authorized Laboratory / Target Scope Only")
    lines.append("")

    # 3. Executive Summary
    lines.append("## 2. Executive Summary")
    lines.append("")
    summary = report.summary()
    total = summary["total_findings"]
    sev = summary["severity_counts"]
    stat = summary["status_counts"]

    critical_high = sev.get("CRITICAL", 0) + sev.get("HIGH", 0)
    fails = stat.get("FAIL", 0)
    unknowns = stat.get("UNKNOWN", 0)

    if total == 0:
        lines.append(
            "No assessment findings were recorded. The target scope returned no observations "
            "or the check list was empty."
        )
    elif critical_high > 0 or fails > 0:
        lines.append(
            f"**High-Risk Configuration Identified:** The assessment identified **{fails}** failed "
            f"security control check(s) and **{critical_high}** finding(s) with HIGH or CRITICAL severity. "
            "These weaknesses present viable exposure to NTLM relay attacks across the Active Directory environment. "
            "Immediate remediation of SMB and LDAP signing policies is strongly advised."
        )
    elif unknowns > 0:
        lines.append(
            f"**Assessment Completed with Inconclusive Checks:** No confirmed high-severity vulnerabilities "
            f"were verified; however, **{unknowns}** check(s) returned inconclusive results (e.g., anonymous access "
            "restrictions or network filtering). Manual or authenticated verification is required."
        )
    else:
        lines.append(
            "**All Evaluated Security Controls Passed:** Probed services demonstrated hardened configurations "
            "(e.g., enforced SMB/LDAP signing). The evaluated attack vectors do not appear viable against "
            "these endpoints under tested conditions."
        )
    lines.append("")

    # Severity metrics breakdown
    lines.append(
        f"**Findings Distribution:** "
        f"`Critical: {sev.get('CRITICAL', 0)}` | "
        f"`High: {sev.get('HIGH', 0)}` | "
        f"`Medium: {sev.get('MEDIUM', 0)}` | "
        f"`Low: {sev.get('LOW', 0)}` | "
        f"`Info: {sev.get('INFO', 0)}`"
    )
    lines.append("")

    # 4. Findings Summary Table
    lines.append("## 3. Findings Summary")
    lines.append("")
    if not report.findings:
        lines.append("*No findings present in assessment data.*")
        lines.append("")
    else:
        lines.append("| ID | Finding Title | Target | Severity | Status |")
        lines.append("|:---|:---|:---|:---:|:---:|")
        for f in report.sorted_findings():
            lines.append(
                f"| `{f.finding_id}` | {f.title} | `{f.target}` | **{f.severity.value}** | `{f.status.value}` |"
            )
        lines.append("")

    # 5. Detailed Findings by Severity
    lines.append("## 4. Detailed Findings & Remediation Guidance")
    lines.append("")

    if not report.findings:
        lines.append("*No detailed findings to display.*")
        lines.append("")
    else:
        for severity in [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]:
            group = [f for f in report.findings if f.severity == severity]
            if not group:
                continue

            lines.append(f"### {severity.value} Severity Findings")
            lines.append("")

            for f in group:
                status_icon = {
                    FindingStatus.PASS: "PASS",
                    FindingStatus.FAIL: "FAIL",
                    FindingStatus.UNKNOWN: "UNKNOWN",
                    FindingStatus.ERROR: "ERROR",
                }.get(f.status, f.status.value)

                lines.append(f"#### [{status_icon}] {f.title}")
                lines.append("")
                lines.append(f"- **Finding Identifier:** `{f.finding_id}`")
                lines.append(f"- **Affected Target:** `{f.target}`")
                lines.append(f"- **Category:** `{f.category}`")
                lines.append(f"- **Severity:** **{f.severity.value}**")
                lines.append(f"- **Defensive Status:** `{f.status.value}`")
                lines.append(f"- **Description:** {f.description}")
                lines.append("")

                # Evidence block
                if f.evidence:
                    lines.append("- **Observed Evidence:**")
                    for k, v in f.evidence.items():
                        lines.append(f"  - `{k}`: `{v}`")
                    lines.append("")

                # Potential Security Impact
                if f.impact:
                    lines.append("- **Potential Security Impact:**")
                    lines.append(f"  > {f.impact}")
                    lines.append("")

                # Remediation
                lines.append("- **Recommended Defensive Remediation:**")
                if f.remediation_guidance:
                    rg = f.remediation_guidance
                    lines.append(f"  - **Action:** {rg.recommended_action}")
                    if rg.gpo_path:
                        lines.append(f"  - **Group Policy Path:** `{rg.gpo_path}`")
                    if rg.registry_setting:
                        lines.append(f"  - **Registry Configuration:** `{rg.registry_setting}`")
                    if rg.validation_guidance:
                        lines.append(f"  - **Validation Command:** `{rg.validation_guidance}`")
                    if rg.requires_verification:
                        lines.append(
                            "  - *Verification Notice: Exact setting requires verification "
                            "against your specific Windows Server build and role.*"
                        )
                elif f.remediation:
                    lines.append(f"  - {f.remediation}")
                else:
                    lines.append("  - Review Active Directory security baselines.")
                lines.append("")

                # References
                refs = f.references
                if f.remediation_guidance and not refs:
                    refs = f.remediation_guidance.references
                if refs:
                    lines.append("- **References & Documentation:**")
                    for r in refs:
                        lines.append(f"  - <{r}>")
                    lines.append("")

                lines.append("---")
                lines.append("")

    # 6. Inconclusive Checks & Assessment Limitations
    lines.append("## 5. Inconclusive Checks & Assessment Limitations")
    lines.append("")
    unknown_findings = report.findings_by_status(FindingStatus.UNKNOWN)
    error_findings = report.findings_by_status(FindingStatus.ERROR)

    if not unknown_findings and not error_findings:
        lines.append(
            "All assessment probes reached conclusive results. No anonymous access blocks or "
            "transport errors hindered the evaluation."
        )
    else:
        lines.append(
            "The following checks could not reach a definitive conclusion. Inconclusive results "
            "must **not** be treated as verified passes nor as confirmed vulnerabilities:"
        )
        lines.append("")
        for f in unknown_findings + error_findings:
            lines.append(f"- **`{f.finding_id}` on `{f.target}`:** {f.description}")
            if f.evidence.get("error"):
                lines.append(f"  - *Diagnostic Error:* `{f.evidence['error']}`")
        lines.append("")
        lines.append(
            "> [!NOTE]\n"
            "> Windows Domain Controllers restrict anonymous RPC pipe binds by default. "
            "> Anonymous access denial is standard security behavior and indicates that "
            "> interface availability must be validated using authenticated tests."
        )
    lines.append("")

    # 7. Strategic Remediation Roadmap
    lines.append("## 6. Strategic Defensive Roadmap")
    lines.append("")
    lines.append("To mitigate NTLM relay attacks holistically in Active Directory:")
    lines.append("1. **Enforce SMB Signing Universally:** Deploy GPO requiring SMB signing on DCs, member servers, and workstations.")
    lines.append("2. **Require LDAP Signing & Channel Binding:** Set LDAPServerIntegrity to 2 and LdapEnforceChannelBinding to 2 on all Domain Controllers.")
    lines.append("3. **Disable Unnecessary Coercion Vectors:** Stop and disable the Print Spooler service on Domain Controllers; audit EFSRPC and FSRVP services.")
    lines.append("4. **Migrate Towards Kerberos:** Reduce NTLM usage across the enterprise with Protected Users and EPA.")
    lines.append("")

    return "\n".join(lines)


def write_markdown_report(
    report_or_findings: Any,
    output_path: Union[str, Path],
    title: str = "AutoRelay Security Assessment & Remediation Report",
) -> Path:
    """
    Generate Markdown report and write it to the specified file path.

    Args:
        report_or_findings: AssessmentReport, PreflightReport, or list of findings/checks.
        output_path: Destination file path.
        title: Optional custom report title.

    Returns:
        Path object of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_markdown_report(report_or_findings, title=title)
    path.write_text(content, encoding="utf-8")
    return path
