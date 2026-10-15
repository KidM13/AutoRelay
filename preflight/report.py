"""
AutoRelay — preflight report data model and renderer.

A PreflightReport holds a list of Check objects. Each check is a single
observation about the target environment: what was tested, what was
found, and what it means for the attack chain.

Design rules:
  - A check that cannot be determined returns passed=None, not passed=True.
    "Unknown" is a real state, and it is not "pass."
  - Severity is "blocker" | "warning" | "info". Only blockers prevent
    the chain from proceeding.
  - The renderer produces Markdown suitable for the client report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Literal

Severity = Literal["blocker", "warning", "info"]


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

@dataclass
class Check:
    """A single preflight observation."""
    name: str                        # short identifier, e.g. "smb_signing.dc01"
    category: str                    # "reachability" | "smb_signing" | ...
    target: str                      # host this check was run against
    passed: bool | None              # True=ok, False=fail, None=unknown
    severity: Severity
    detail: str                      # one-line human-readable summary
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""            # populated by report/remediation.py (Stage 2)

    def status_symbol(self) -> str:
        return {True: "[+]", False: "[-]", None: "[?]"}[self.passed]

    def status_word(self) -> str:
        return {True: "pass", False: "fail", None: "unknown"}[self.passed]


# ---------------------------------------------------------------------------
# PreflightReport
# ---------------------------------------------------------------------------

@dataclass
class PreflightReport:
    target: str
    profile_name: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: str = ""
    checks: list[Check] = field(default_factory=list)

    # --- mutation ---

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def extend(self, checks: list[Check]) -> None:
        self.checks.extend(checks)

    def finalize(self) -> None:
        self.finished_at = datetime.now().isoformat(timespec="seconds")

    # --- queries ---

    @property
    def blockers(self) -> list[Check]:
        return [c for c in self.checks if c.severity == "blocker" and c.passed is False]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.severity == "warning" and c.passed is False]

    @property
    def unknowns(self) -> list[Check]:
        return [c for c in self.checks if c.passed is None]

    def ok_to_proceed(self) -> bool:
        """True only if there are no blocker failures."""
        return not self.blockers

    def by_category(self) -> dict[str, list[Check]]:
        result: dict[str, list[Check]] = {}
        for c in self.checks:
            result.setdefault(c.category, []).append(c)
        return result

    # --- serialization ---

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "profile_name": self.profile_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ok_to_proceed": self.ok_to_proceed(),
            "summary": {
                "total": len(self.checks),
                "blockers": len(self.blockers),
                "warnings": len(self.warnings),
                "unknowns": len(self.unknowns),
            },
            "checks": [asdict(c) for c in self.checks],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # --- rendering ---

    def render_console(self, color: bool = True) -> str:
        """Compact, human-readable summary for the terminal."""
        reset = "\033[0m" if color else ""
        dim = "\033[2m" if color else ""
        bold = "\033[1m" if color else ""
        red = "\033[31m" if color else ""
        green = "\033[32m" if color else ""
        yellow = "\033[33m" if color else ""

        def color_for(check: Check) -> str:
            if check.passed is True:
                return green
            if check.passed is False and check.severity == "blocker":
                return red
            if check.passed is False:
                return yellow
            return dim  # unknown

        lines: list[str] = []
        lines.append(f"{bold}Preflight report{reset}")
        lines.append(f"  target:  {self.target}")
        lines.append(f"  profile: {self.profile_name}")
        lines.append("")

        for category, checks in self.by_category().items():
            lines.append(f"{bold}{category}{reset}")
            for c in checks:
                sym = c.status_symbol()
                col = color_for(c)
                lines.append(f"  {col}{sym}{reset} {c.target:<20} {c.detail}")
            lines.append("")

        n_blockers = len(self.blockers)
        n_warnings = len(self.warnings)
        n_unknowns = len(self.unknowns)

        if n_blockers:
            lines.append(f"{red}{bold}{n_blockers} blocker(s) — do not proceed{reset}")
            for b in self.blockers:
                lines.append(f"  {red}[-]{reset} {b.name}: {b.detail}")
        elif n_unknowns:
            lines.append(f"{yellow}{bold}No blockers, but {n_unknowns} unknown check(s){reset}")
        else:
            lines.append(f"{green}{bold}All checks passed — chain appears viable{reset}")

        if n_warnings:
            lines.append(f"{yellow}{n_warnings} warning(s){reset}")

        return "\n".join(lines)

    def render_markdown(self) -> str:
        """Client-facing Markdown report."""
        lines: list[str] = []
        lines.append(f"# Preflight Report — {self.target}")
        lines.append("")
        lines.append(f"- **Profile:** `{self.profile_name}`")
        lines.append(f"- **Started:** {self.started_at}")
        lines.append(f"- **Finished:** {self.finished_at or '(not finalized)'}")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        if self.ok_to_proceed():
            if self.unknowns:
                lines.append(
                    f"No blockers identified. {len(self.unknowns)} check(s) "
                    f"could not be determined and should be verified manually."
                )
            else:
                lines.append(
                    "All preflight checks passed. The NTLM relay chain "
                    "appears viable against this target."
                )
        else:
            lines.append(
                f"**{len(self.blockers)} blocker(s) identified.** "
                f"The NTLM relay chain cannot proceed as-is against this "
                f"target."
            )
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Category | Checks | Pass | Fail | Unknown |")
        lines.append("|---|---|---|---|---|")
        for category, checks in self.by_category().items():
            n_pass = sum(1 for c in checks if c.passed is True)
            n_fail = sum(1 for c in checks if c.passed is False)
            n_unk = sum(1 for c in checks if c.passed is None)
            lines.append(
                f"| {category} | {len(checks)} | {n_pass} | {n_fail} | {n_unk} |"
            )
        lines.append("")

        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")
        for category, checks in self.by_category().items():
            lines.append(f"### {category}")
            lines.append("")
            for c in checks:
                sym = c.status_symbol()
                lines.append(f"#### `{sym}` {c.name}")
                lines.append("")
                lines.append(f"- **Target:** `{c.target}`")
                lines.append(f"- **Status:** {c.status_word()}")
                lines.append(f"- **Severity:** {c.severity}")
                lines.append(f"- **Detail:** {c.detail}")
                if c.evidence:
                    lines.append(f"- **Evidence:**")
                    for k, v in c.evidence.items():
                        lines.append(f"    - `{k}`: `{v}`")
                if c.remediation:
                    lines.append(f"- **Remediation:** {c.remediation}")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test — run with: python -m preflight.report
# ---------------------------------------------------------------------------

def _main() -> int:
    report = PreflightReport(target="192.168.56.10", profile_name="goad")

    report.add(Check(
        name="reachability.dc01.445",
        category="reachability",
        target="192.168.56.10",
        passed=True,
        severity="info",
        detail="TCP 445 (smb) open",
        evidence={"port": 445, "state": "open"},
    ))
    report.add(Check(
        name="smb_signing.dc01",
        category="smb_signing",
        target="192.168.56.10",
        passed=False,
        severity="blocker",
        detail="SMB signing is REQUIRED — relay to SMB not viable",
        evidence={"signing_required": True, "signing_enabled": True},
    ))
    report.add(Check(
        name="ldap_signing.dc01",
        category="ldap_signing",
        target="192.168.56.10",
        passed=True,
        severity="info",
        detail="LDAP signing not enforced — relay to LDAP viable",
        evidence={"ldap_server_integrity": 0},
    ))
    report.add(Check(
        name="coercion_probe.petitpotam",
        category="coercion_probe",
        target="192.168.56.10",
        passed=None,
        severity="warning",
        detail="EFSRPC interface present, method availability not confirmed",
        evidence={"interface_bound": True, "method": "EfsRpcOpenFileRaw"},
    ))

    report.finalize()

    print("=== Console rendering ===")
    print(report.render_console(color=False))
    print()
    print("=== Markdown rendering ===")
    print(report.render_markdown())
    print()
    print("=== JSON rendering (truncated) ===")
    j = report.to_json()
    print(j[:600] + "...\n")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
