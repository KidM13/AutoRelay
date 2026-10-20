"""
AutoRelay — JSON Report Generator.

Serializes security assessment findings, metrics, and remediation guidance into
standardized, valid JSON matching the data model of the Markdown report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from .markdown import _resolve_report


def generate_json_report(
    report_or_findings: Any,
    indent: int = 2,
    sort_keys: bool = False,
) -> str:
    """
    Generate valid, deterministic JSON string from assessment data.

    Args:
        report_or_findings: AssessmentReport, PreflightReport, or list of findings/checks.
        indent: Indentation level for pretty-printing.
        sort_keys: Whether to sort keys deterministically.

    Returns:
        JSON string representation.
    """
    report = _resolve_report(report_or_findings)
    data = report.to_dict()

    # Append assessment limitations list to root JSON
    unknown_findings = report.findings_by_status("UNKNOWN")
    error_findings = report.findings_by_status("ERROR")
    limitations: list[str] = []

    for f in unknown_findings + error_findings:
        msg = f"{f.finding_id} on {f.target}: {f.description}"
        if f.evidence.get("error"):
            msg += f" (error: {f.evidence['error']})"
        limitations.append(msg)

    data["limitations"] = limitations

    return json.dumps(data, indent=indent, sort_keys=sort_keys, default=str)


def write_json_report(
    report_or_findings: Any,
    output_path: Union[str, Path],
    indent: int = 2,
) -> Path:
    """
    Generate JSON report and write it to the specified file path.

    Args:
        report_or_findings: AssessmentReport, PreflightReport, or list of findings/checks.
        output_path: Destination file path.
        indent: JSON indentation.

    Returns:
        Path object of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_json_report(report_or_findings, indent=indent)
    path.write_text(content, encoding="utf-8")
    return path
