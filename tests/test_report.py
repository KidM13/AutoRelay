"""
AutoRelay — Unit Tests for Reporting & Remediation Module.

Covers:
1. Creation and validation of finding structures.
2. Valid and invalid severity values.
3. Handling of missing or unknown assessment results.
4. Correct mapping of supported findings to remediation guidance.
5. Handling of findings without a remediation mapping.
6. Markdown generation with multiple findings.
7. JSON generation and JSON parsing.
8. Empty assessment results.
9. Inconclusive or incomplete assessments.
10. Consistency between Markdown and JSON outputs.
11. Sensitive-data redaction.
12. Writing reports to output files.
13. Compatibility with existing preflight result models (PreflightReport, Check).
14. Regression tests for existing reporting behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from preflight.report import Check, PreflightReport
from report import (
    AssessmentReport,
    Finding,
    FindingSeverity,
    FindingStatus,
    RemediationGuidance,
    enrich_check_with_remediation,
    finding_from_check,
    from_preflight_report,
    generate_json_report,
    generate_markdown_report,
    get_remediation_guidance,
    redact_sensitive_value,
    register_remediation,
    write_json_report,
    write_markdown_report,
)


# ===========================================================================
# 1. Creation and Validation of Finding Structures
# ===========================================================================

def test_finding_creation_valid():
    finding = Finding(
        finding_id="TEST-001",
        title="Test Finding",
        target="10.0.0.1",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.FAIL,
        description="Test description",
        category="network",
        evidence={"port": 445},
        impact="Test impact",
        remediation="Test remediation",
        references=["https://example.com"],
    )

    assert finding.finding_id == "TEST-001"
    assert finding.check_id == "TEST-001"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.status == FindingStatus.FAIL
    assert finding.details == "Test description"
    assert finding.to_dict()["finding_id"] == "TEST-001"
    assert finding.to_dict()["severity"] == "HIGH"
    assert finding.to_dict()["status"] == "FAIL"


def test_finding_validation_missing_required_fields():
    with pytest.raises(ValueError, match="finding_id"):
        Finding(
            finding_id="",
            title="Title",
            target="10.0.0.1",
            severity=FindingSeverity.INFO,
            status=FindingStatus.PASS,
            description="desc",
        )

    with pytest.raises(ValueError, match="title"):
        Finding(
            finding_id="ID-1",
            title="",
            target="10.0.0.1",
            severity=FindingSeverity.INFO,
            status=FindingStatus.PASS,
            description="desc",
        )

    with pytest.raises(ValueError, match="target"):
        Finding(
            finding_id="ID-1",
            title="Title",
            target="",
            severity=FindingSeverity.INFO,
            status=FindingStatus.PASS,
            description="desc",
        )


def test_finding_from_dict():
    raw = {
        "finding_id": "DICT-01",
        "title": "Dict Title",
        "target": "10.0.0.2",
        "severity": "MEDIUM",
        "status": "FAIL",
        "description": "Dict description",
        "category": "smb",
        "evidence": {"key": "val"},
        "impact": "Dict impact",
        "remediation": "Dict remediation",
        "references": ["https://ref.com"],
    }
    f = Finding.from_dict(raw)
    assert f.finding_id == "DICT-01"
    assert f.severity == FindingSeverity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.evidence == {"key": "val"}


# ===========================================================================
# 2. Valid and Invalid Severity Values
# ===========================================================================

def test_severity_valid_conversions():
    assert FindingSeverity.from_str("critical") == FindingSeverity.CRITICAL
    assert FindingSeverity.from_str("HIGH") == FindingSeverity.HIGH
    assert FindingSeverity.from_str("medium") == FindingSeverity.MEDIUM
    assert FindingSeverity.from_str("Low") == FindingSeverity.LOW
    assert FindingSeverity.from_str("INFO") == FindingSeverity.INFO

    # Preflight severity aliases
    assert FindingSeverity.from_str("blocker") == FindingSeverity.HIGH
    assert FindingSeverity.from_str("warning") == FindingSeverity.MEDIUM
    assert FindingSeverity.from_str("informational") == FindingSeverity.INFO


def test_severity_invalid_values():
    with pytest.raises(ValueError, match="Invalid severity"):
        FindingSeverity.from_str("EXTREME")

    with pytest.raises(ValueError, match="Severity must be a string"):
        FindingSeverity.from_str(123)  # type: ignore


def test_status_valid_and_invalid():
    assert FindingStatus.from_str("pass") == FindingStatus.PASS
    assert FindingStatus.from_str("FAIL") == FindingStatus.FAIL
    assert FindingStatus.from_str("unknown") == FindingStatus.UNKNOWN
    assert FindingStatus.from_str("error") == FindingStatus.ERROR

    with pytest.raises(ValueError, match="Invalid status"):
        FindingStatus.from_str("NOT_SURE")


# ===========================================================================
# 3. Handling of Missing or Unknown Assessment Results
# ===========================================================================

def test_handling_inconclusive_checks():
    check = Check(
        name="smb_signing.unknown_host",
        category="smb_signing",
        target="192.168.1.100",
        passed=None,
        severity="warning",
        detail="SMB negotiate timed out",
        evidence={"error": "timeout"},
    )
    finding = finding_from_check(check)
    assert finding.status == FindingStatus.UNKNOWN
    assert finding.severity == FindingSeverity.LOW
    assert "Inconclusive" in finding.title
    assert "Manual verification required" in finding.impact


# ===========================================================================
# 4. Correct Mapping of Supported Findings to Remediation Guidance
# ===========================================================================

def test_remediation_mapping_smb_signing():
    # SMB signing enabled but not required (vulnerable)
    check_smb_enabled = Check(
        name="smb_signing.member01",
        category="smb_signing",
        target="192.168.56.20",
        passed=True,
        severity="info",
        detail="SMB signing enabled but NOT required — relay-to-SMB viable",
        evidence={"signing_enabled": True, "signing_required": False},
    )
    f_smb = finding_from_check(check_smb_enabled)
    assert f_smb.status == FindingStatus.FAIL
    assert f_smb.severity == FindingSeverity.HIGH
    assert f_smb.remediation_guidance is not None
    assert "Digitally sign communications (always)" in f_smb.remediation_guidance.gpo_path
    assert "RequireSecuritySignature" in f_smb.remediation_guidance.registry_setting

    # SMB signing required (secure)
    check_smb_req = Check(
        name="smb_signing.dc01",
        category="smb_signing",
        target="192.168.56.10",
        passed=False,
        severity="blocker",
        detail="SMB signing is REQUIRED — relay to SMB not viable",
        evidence={"signing_enabled": True, "signing_required": True},
    )
    f_smb_req = finding_from_check(check_smb_req)
    assert f_smb_req.status == FindingStatus.PASS
    assert f_smb_req.severity == FindingSeverity.INFO


def test_remediation_mapping_ldap_signing():
    check_ldap_none = Check(
        name="ldap_signing.dc01",
        category="ldap_signing",
        target="192.168.56.10",
        passed=True,
        severity="info",
        detail="LDAP signing not enforced — relay to LDAP viable",
        evidence={"ldap_server_integrity": 0},
    )
    f_ldap = finding_from_check(check_ldap_none)
    assert f_ldap.status == FindingStatus.FAIL
    assert f_ldap.severity == FindingSeverity.HIGH
    assert f_ldap.remediation_guidance is not None
    assert "LDAPServerIntegrity" in f_ldap.remediation_guidance.registry_setting
    assert "LDAP server signing requirements" in f_ldap.remediation_guidance.gpo_path


def test_remediation_mapping_coercion_vectors():
    # PetitPotam access denied
    check_efs_denied = Check(
        name="coercion_probe.dc01.petitpotam",
        category="coercion_probe",
        target="192.168.56.10",
        passed=None,
        severity="warning",
        detail="access denied",
        evidence={"state": "denied", "error": "access denied"},
    )
    f_efs = finding_from_check(check_efs_denied)
    assert f_efs.status == FindingStatus.UNKNOWN
    assert f_efs.severity == FindingSeverity.LOW

    # PrinterBug bound
    check_spooler = Check(
        name="coercion_probe.dc01.printerbug",
        category="coercion_probe",
        target="192.168.56.10",
        passed=True,
        severity="warning",
        detail="pipe spoolss bound",
        evidence={"state": "available"},
    )
    f_spool = finding_from_check(check_spooler)
    assert f_spool.status == FindingStatus.FAIL
    assert f_spool.severity == FindingSeverity.MEDIUM
    assert f_spool.remediation_guidance is not None
    assert "Print Spooler" in f_spool.remediation_guidance.recommended_action


# ===========================================================================
# 5. Handling of Findings Without a Remediation Mapping
# ===========================================================================

def test_unmapped_finding_fallback():
    check_custom = Check(
        name="custom_check.target",
        category="unregistered_category",
        target="10.10.10.10",
        passed=False,
        severity="warning",
        detail="Custom test observation",
        evidence={"custom_data": 42},
    )
    f_custom = finding_from_check(check_custom)
    assert f_custom.status == FindingStatus.FAIL
    assert f_custom.remediation_guidance is None
    assert "Review security configuration" in f_custom.remediation


# ===========================================================================
# 6. Markdown Generation With Multiple Findings
# ===========================================================================

def test_markdown_report_generation():
    f1 = Finding(
        finding_id="AR-SMB-001",
        title="SMB Signing Disabled",
        target="192.168.56.20",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.FAIL,
        description="SMB signing is disabled.",
        evidence={"security_mode": 0},
        impact="Enables NTLM relay.",
        remediation="Enable SMB signing via GPO.",
        references=["https://learn.microsoft.com/smb"],
    )
    f2 = Finding(
        finding_id="AR-LDAP-001",
        title="LDAP Signing Enforced",
        target="192.168.56.10",
        severity=FindingSeverity.INFO,
        status=FindingStatus.PASS,
        description="LDAP signing is enforced.",
        evidence={"ldap_server_integrity": 2},
        impact="Secure.",
        remediation="None required.",
    )

    report = AssessmentReport(
        target="192.168.56.10",
        profile_name="goad",
        started_at="2026-10-18T12:00:00",
        finished_at="2026-10-18T12:00:05",
        findings=[f1, f2],
    )

    md = generate_markdown_report(report)

    # Check key sections exist
    assert "# AutoRelay Security Assessment & Remediation Report" in md
    assert "## 1. Assessment Scope & Metadata" in md
    assert "## 2. Executive Summary" in md
    assert "## 3. Findings Summary" in md
    assert "## 4. Detailed Findings & Remediation Guidance" in md
    assert "## 5. Inconclusive Checks & Assessment Limitations" in md
    assert "## 6. Strategic Defensive Roadmap" in md

    # Check finding content in markdown
    assert "AR-SMB-001" in md
    assert "SMB Signing Disabled" in md
    assert "AR-LDAP-001" in md
    assert "LDAP Signing Enforced" in md


# ===========================================================================
# 7. JSON Generation and JSON Parsing
# ===========================================================================

def test_json_report_generation_and_parsing():
    f = Finding(
        finding_id="AR-TEST-01",
        title="Test JSON",
        target="192.168.56.10",
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.FAIL,
        description="Testing json output",
        evidence={"detail": "sample"},
    )
    report = AssessmentReport(
        target="192.168.56.10",
        profile_name="lab",
        findings=[f],
    )

    raw_json = generate_json_report(report)
    parsed = json.loads(raw_json)

    assert parsed["report_title"] == "AutoRelay Assessment & Remediation Report"
    assert parsed["metadata"]["target"] == "192.168.56.10"
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["summary"]["severity_counts"]["MEDIUM"] == 1
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["finding_id"] == "AR-TEST-01"


# ===========================================================================
# 8. Empty Assessment Results
# ===========================================================================

def test_empty_assessment_results():
    empty_report = AssessmentReport(
        target="10.0.0.99",
        profile_name="goad",
        findings=[],
    )

    # Markdown
    md = generate_markdown_report(empty_report)
    assert "No assessment findings were recorded." in md
    assert "*No findings present in assessment data.*" in md

    # JSON
    raw_json = generate_json_report(empty_report)
    parsed = json.loads(raw_json)
    assert parsed["summary"]["total_findings"] == 0
    assert parsed["findings"] == []


# ===========================================================================
# 9. Inconclusive or Incomplete Assessments
# ===========================================================================

def test_inconclusive_assessment_reporting():
    f_unk = Finding(
        finding_id="AR-COERCE-UNK",
        title="Coercion Probe Inconclusive",
        target="192.168.56.10",
        severity=FindingSeverity.LOW,
        status=FindingStatus.UNKNOWN,
        description="Anonymous named-pipe access denied.",
        evidence={"error": "STATUS_ACCESS_DENIED"},
    )
    report = AssessmentReport(
        target="192.168.56.10",
        profile_name="goad",
        findings=[f_unk],
    )

    md = generate_markdown_report(report)
    assert "Inconclusive Checks & Assessment Limitations" in md
    assert "`AR-COERCE-UNK` on `192.168.56.10`" in md
    assert "STATUS_ACCESS_DENIED" in md

    raw_json = generate_json_report(report)
    parsed = json.loads(raw_json)
    assert len(parsed["limitations"]) == 1
    assert "AR-COERCE-UNK" in parsed["limitations"][0]


# ===========================================================================
# 10. Consistency Between Markdown and JSON Outputs
# ===========================================================================

def test_consistency_markdown_and_json():
    f1 = Finding(
        finding_id="F-1",
        title="Check 1",
        target="host1",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.FAIL,
        description="desc1",
    )
    f2 = Finding(
        finding_id="F-2",
        title="Check 2",
        target="host2",
        severity=FindingSeverity.LOW,
        status=FindingStatus.PASS,
        description="desc2",
    )
    report = AssessmentReport(
        target="host1",
        profile_name="test",
        findings=[f1, f2],
    )

    md = generate_markdown_report(report)
    parsed_json = json.loads(generate_json_report(report))

    # Same number of findings
    assert len(parsed_json["findings"]) == 2
    assert "F-1" in md
    assert "F-2" in md
    assert parsed_json["findings"][0]["finding_id"] == "F-1"  # sorted by severity
    assert parsed_json["summary"]["severity_counts"]["HIGH"] == 1
    assert parsed_json["summary"]["severity_counts"]["LOW"] == 1


# ===========================================================================
# 11. Sensitive-Data Redaction
# ===========================================================================

def test_sensitive_data_redaction():
    evidence = {
        "user": "administrator",
        "password": "SuperSecretPassword123!",
        "auth_token": "abcdef1234567890",
        "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "challenge_response": "Server response containing aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 inside payload",
        "nested": {
            "secret_key": "private_data",
            "normal_data": "public_info",
        },
    }
    redacted = redact_sensitive_value(evidence)

    assert redacted["user"] == "administrator"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["auth_token"] == "[REDACTED]"
    assert redacted["ntlm_hash"] == "[REDACTED]"
    assert "[REDACTED_HASH]" in redacted["challenge_response"]
    assert redacted["nested"]["secret_key"] == "[REDACTED]"
    assert redacted["nested"]["normal_data"] == "public_info"


# ===========================================================================
# 12. Writing Reports to Output Files
# ===========================================================================

def test_writing_reports_to_files(tmp_path: Path):
    f = Finding(
        finding_id="F-FILE",
        title="File Test",
        target="127.0.0.1",
        severity=FindingSeverity.INFO,
        status=FindingStatus.PASS,
        description="File test description",
    )
    report = AssessmentReport(target="127.0.0.1", profile_name="test", findings=[f])

    md_path = tmp_path / "subdir" / "report.md"
    json_path = tmp_path / "subdir" / "report.json"

    res_md = write_markdown_report(report, md_path)
    res_json = write_json_report(report, json_path)

    assert res_md.exists()
    assert res_json.exists()
    assert "File Test" in res_md.read_text(encoding="utf-8")
    assert json.loads(res_json.read_text(encoding="utf-8"))["findings"][0]["finding_id"] == "F-FILE"


# ===========================================================================
# 13. Compatibility With Existing Preflight Result Models
# ===========================================================================

def test_compatibility_with_preflight_report():
    pf_report = PreflightReport(target="192.168.56.10", profile_name="goad")
    pf_report.add(Check(
        name="smb_signing.dc01",
        category="smb_signing",
        target="192.168.56.10",
        passed=False,
        severity="blocker",
        detail="SMB signing is REQUIRED — relay to SMB not viable",
        evidence={"signing_required": True, "signing_enabled": True},
    ))
    pf_report.add(Check(
        name="ldap_signing.dc01",
        category="ldap_signing",
        target="192.168.56.10",
        passed=True,
        severity="info",
        detail="LDAP signing not enforced — relay to LDAP viable",
        evidence={"ldap_server_integrity": 0},
    ))
    pf_report.finalize()

    # Convert to assessment report
    assessment = from_preflight_report(pf_report)
    assert assessment.target == "192.168.56.10"
    assert assessment.profile_name == "goad"
    assert len(assessment.findings) == 2

    # Direct markdown / json generation from PreflightReport
    md = generate_markdown_report(pf_report)
    assert "Preflight" in md or "AutoRelay" in md
    assert "smb_signing.dc01" in md
    assert "ldap_signing.dc01" in md

    j = generate_json_report(pf_report)
    parsed = json.loads(j)
    assert parsed["metadata"]["target"] == "192.168.56.10"
    assert len(parsed["findings"]) == 2


# ===========================================================================
# 14. Preflight Check Remediation Enrichment & Extension
# ===========================================================================

def test_enrich_check_with_remediation():
    check = Check(
        name="smb_signing.dc01",
        category="smb_signing",
        target="192.168.56.10",
        passed=True,
        severity="info",
        detail="SMB signing disabled",
        evidence={"signing_enabled": False},
        remediation="",
    )
    enrich_check_with_remediation(check)
    assert check.remediation != ""
    assert "Digitally sign communications" in check.remediation


def test_custom_remediation_registration():
    custom_guidance = RemediationGuidance(
        issue="Custom test issue",
        why_it_matters="Custom matter",
        potential_impact="Custom impact",
        recommended_action="Do custom action",
    )
    register_remediation("custom_key", custom_guidance)

    retrieved = get_remediation_guidance("custom_key")
    assert retrieved is not None
    assert retrieved.issue == "Custom test issue"
