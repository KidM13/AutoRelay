
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
