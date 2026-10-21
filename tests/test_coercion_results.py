"""Tests for CoercionResult outcome interpretation.

These tests verify that the three possible values of the `success` field
map correctly to the human-readable status labels used in reports and CLI output:

    True  → "SUCCESS"   (the coercion technique achieved its intended outcome)
    False → "FAILURE"   (the technique ran but the outcome was not achieved)
    None  → "UNKNOWN"   (the outcome could not be determined)

This is separate from test_coercion_base.py, which tests validation rules.
Here we only care about whether a stored result carries the right meaning.
"""

import pytest

from coercion.base import CoercionResult


# ---------------------------------------------------------------------------
# Helper: the status mapping used by the reporting layer.
#
# This dict translates the raw success value into a display label.
# Keeping it here (rather than inlining it in every test) means a single
# source of truth: if the labels ever change, you update one place.
# ---------------------------------------------------------------------------

STATUS_LABELS = {
    True: "SUCCESS",
    False: "FAILURE",
    None: "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Parametrized test: all three outcomes in one table.
#
# pytest runs this function three times — once per row in the table below.
# Each run gets its own line in the test output, labelled with the input values.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("success", "expected_label"),
    [
        (True,  "SUCCESS"),   # module confirmed its goal was achieved
        (False, "FAILURE"),   # module confirmed its goal was NOT achieved
        (None,  "UNKNOWN"),   # module could not determine the outcome
    ],
)
def test_result_status_label(success, expected_label):
    """Each success value maps to the correct human-readable status label."""
    result = CoercionResult(
        technique="example",
        target="127.0.0.1",
        success=success,
        detail="Test result",
    )
    assert STATUS_LABELS[result.success] == expected_label


# ---------------------------------------------------------------------------
# Individual tests: one per outcome, with a clear description.
#
# These repeat the parametrized coverage on purpose. They make it easier
# for a beginner to read and understand each case in isolation, and they
# give more specific failure messages if something breaks.
# ---------------------------------------------------------------------------

def test_success_true_maps_to_success_label():
    # When success=True, the technique confirmed it worked.
    # A report should display "SUCCESS" for this result.
    result = CoercionResult(
        technique="PrinterBug",
        target="192.168.1.10",
        success=True,
        detail="Authentication hash captured.",
    )
    assert result.success is True
    assert STATUS_LABELS[result.success] == "SUCCESS"


def test_success_false_maps_to_failure_label():
    # When success=False, the technique confirmed it did NOT work.
    # A report should display "FAILURE" for this result.
    # Note: this is still a valid, useful result — knowing something
    # is blocked is important information in a security assessment.
    result = CoercionResult(
        technique="PetitPotam",
        target="dc01",
        success=False,
        detail="SMB signing blocked the attempt.",
    )
    assert result.success is False
    assert STATUS_LABELS[result.success] == "FAILURE"


def test_success_none_maps_to_unknown_label():
    # When success=None, the outcome could not be determined.
    # A report should display "UNKNOWN" for this result.
    # This is the correct value for placeholder or inconclusive runs.
    result = CoercionResult(
        technique="example",
        target="127.0.0.1",
        success=None,
        detail="Placeholder only; no action performed.",
    )
    assert result.success is None
    assert STATUS_LABELS[result.success] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Field integrity: verify that all other fields are stored correctly
# alongside the success value, so nothing is lost when a result is created.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("technique", "target", "success", "detail"),
    [
        ("PrinterBug",  "192.168.1.10", True,  "Hash captured."),
        ("PetitPotam",  "dc01",         False, "Blocked by signing."),
        ("example",     "127.0.0.1",    None,  "Placeholder only; no action performed."),
    ],
)
def test_result_stores_all_fields_correctly(technique, target, success, detail):
    """All four fields on CoercionResult are stored exactly as provided."""
    result = CoercionResult(
        technique=technique,
        target=target,
        success=success,
        detail=detail,
    )
    assert result.technique == technique
    assert result.target == target
    assert result.success is success
    assert result.detail == detail
