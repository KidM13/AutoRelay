"""
AutoRelay — Unit and regression tests for preflight report data structures.
"""

from __future__ import annotations

import json
from preflight.report import Check, PreflightReport


def test_preflight_check_basics():
    c = Check(
        name="reachability.test.445",
        category="reachability",
        target="127.0.0.1",
        passed=True,
        severity="info",
        detail="Port 445 open",
        evidence={"port": 445},
    )
    assert c.status_symbol() == "[+]"
    assert c.status_word() == "pass"

    c_fail = Check(
        name="smb_signing.test",
        category="smb_signing",
        target="127.0.0.1",
        passed=False,
        severity="blocker",
        detail="Signing required",
    )
    assert c_fail.status_symbol() == "[-]"
    assert c_fail.status_word() == "fail"

    c_unk = Check(
        name="coercion.test",
        category="coercion_probe",
        target="127.0.0.1",
        passed=None,
        severity="warning",
        detail="Unknown",
    )
    assert c_unk.status_symbol() == "[?]"
    assert c_unk.status_word() == "unknown"


def test_preflight_report_consolidation():
    rep = PreflightReport(target="127.0.0.1", profile_name="goad")
    rep.add(Check(
        name="reachability.overall",
        category="reachability",
        target="127.0.0.1",
        passed=True,
        severity="info",
        detail="Host reachable",
    ))
    rep.add(Check(
        name="smb_signing.dc01",
        category="smb_signing",
        target="127.0.0.1",
        passed=False,
        severity="blocker",
        detail="Signing required",
    ))
    rep.finalize()

    assert not rep.ok_to_proceed()
    assert len(rep.blockers) == 1
    assert len(rep.warnings) == 0
    assert len(rep.unknowns) == 0

    # Test dictionary / json serialization
    d = rep.to_dict()
    assert d["target"] == "127.0.0.1"
    assert d["summary"]["blockers"] == 1

    j = rep.to_json()
    assert "smb_signing.dc01" in j

    # Test console and markdown rendering
    console = rep.render_console(color=False)
    assert "1 blocker(s) — do not proceed" in console

    md = rep.render_markdown()
    assert "# Preflight Report — 127.0.0.1" in md
