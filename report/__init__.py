"""
AutoRelay — Reporting & Remediation Module.

Member 3 Responsibility:
Converts preflight assessment results and security observations into structured findings,
classifies findings by severity and impact, enriches them with verified defensive
remediation guidance, and exports reports in Markdown and JSON formats.
"""

from .findings import (
    AssessmentReport,
    Finding,
    FindingSeverity,
    FindingStatus,
    finding_from_check,
    from_preflight_report,
    redact_sensitive_value,
)
from .remediation import (
    RemediationGuidance,
    enrich_check_with_remediation,
    get_remediation_guidance,
    register_remediation,
)
from .markdown import (
    generate_markdown_report,
    write_markdown_report,
)
from .json_report import (
    generate_json_report,
    write_json_report,
)

__all__ = [
    # Findings and Models
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "AssessmentReport",
    "finding_from_check",
    "from_preflight_report",
    "redact_sensitive_value",

    # Remediation
    "RemediationGuidance",
    "get_remediation_guidance",
    "enrich_check_with_remediation",
    "register_remediation",

    # Markdown
    "generate_markdown_report",
    "write_markdown_report",

    # JSON
    "generate_json_report",
    "write_json_report",
]
