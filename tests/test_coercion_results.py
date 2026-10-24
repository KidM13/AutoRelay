
import pytest

from coercion.base import CoercionResult


@pytest.mark.parametrize("success", [True, False, None])
def test_result_accepts_valid_statuses(success):
    result = CoercionResult(
        technique="example",
        target="127.0.0.1",
        success=success,
        detail="Test result",
    )

    assert result.success is success


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("technique", ""),
        ("technique", "   "),
        ("target", ""),
        ("target", "   "),
        ("success", 1),
        ("success", "unknown"),
        ("detail", None),
    ],
)
def test_result_rejects_invalid_values(field, value):
    values = {
        "technique": "example",
        "target": "127.0.0.1",
        "success": None,
        "detail": "Test result",
    }
    values[field] = value

    with pytest.raises(ValueError):
        CoercionResult(**values)


@pytest.mark.parametrize(
    ("success", "expected_label"),
    [
        (True, "SUCCESS"),
        (False, "FAILURE"),
        (None, "UNKNOWN"),
    ],
)
def test_result_outcome_labels(success, expected_label):
    """Document the intended human-readable meaning of each outcome."""
    labels = {
        True: "SUCCESS",
        False: "FAILURE",
        None: "UNKNOWN",
    }

    result = CoercionResult(
        technique="example",
        target="127.0.0.1",
        success=success,
        detail="Test result",
    )

    assert labels[result.success] == expected_label


@pytest.mark.parametrize(
    ("technique", "target", "success", "detail"),
    [
        ("PrinterBug", "192.168.1.10", True, "Outcome confirmed."),
        ("PetitPotam", "dc01", False, "Outcome not achieved."),
        ("example", "127.0.0.1", None, "Placeholder; no action performed."),
    ],
)
def test_result_stores_all_fields_correctly(
    technique, target, success, detail
):
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
