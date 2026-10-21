import pytest

from coercion.base import CoercionModule, CoercionResult


# ---------------------------------------------------------------------------
# A minimal concrete module used only inside this test file.
# It lets us test CoercionModule behaviour without importing the real example.
# ---------------------------------------------------------------------------

class ExampleModule(CoercionModule):
    name = "example"
    description = "Example module for testing"

    def run(self, target: str) -> CoercionResult:
        return CoercionResult(
            technique=self.name,
            target=target,
            success=True,
            detail="Test completed",
        )


# ---------------------------------------------------------------------------
# Existing tests (kept exactly as they were)
# ---------------------------------------------------------------------------

def test_module_implements_run():
    module = ExampleModule()

    result = module.run("127.0.0.1")

    assert result.technique == "example"
    assert result.target == "127.0.0.1"
    assert result.success is True


def test_abstract_class_cannot_be_instantiated():
    with pytest.raises(TypeError):
        CoercionModule()


# ---------------------------------------------------------------------------
# CoercionResult — valid inputs
# ---------------------------------------------------------------------------

def test_result_accepts_success_true():
    # A completed, successful coercion should be storable without error.
    result = CoercionResult(
        technique="PrinterBug",
        target="192.168.1.10",
        success=True,
        detail="Hash captured.",
    )
    assert result.success is True


def test_result_accepts_success_false():
    # A completed but unsuccessful attempt should also be storable without error.
    result = CoercionResult(
        technique="PetitPotam",
        target="dc01",
        success=False,
        detail="Connection refused.",
    )
    assert result.success is False


def test_result_accepts_success_none():
    # success=None means UNKNOWN — the module ran but the outcome is not yet
    # determined. This is valid and must be accepted.
    result = CoercionResult(
        technique="example",
        target="127.0.0.1",
        success=None,
        detail="No action performed.",
    )
    assert result.success is None


def test_result_accepts_empty_detail():
    # The detail field is optional context. An empty string is allowed.
    result = CoercionResult(
        technique="DFSCoerce",
        target="fileserver",
        success=None,
        detail="",
    )
    assert result.detail == ""


# ---------------------------------------------------------------------------
# CoercionResult — technique validation
# ---------------------------------------------------------------------------

def test_result_rejects_empty_technique():
    # An empty technique name means we have no idea what ran.
    # The report would be meaningless, so this must be rejected.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="",
            target="127.0.0.1",
            success=None,
            detail="Test",
        )


def test_result_rejects_whitespace_technique():
    # A string of spaces looks non-empty but carries no information.
    # It should be treated the same as an empty string.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="   ",
            target="127.0.0.1",
            success=None,
            detail="Test",
        )


def test_result_rejects_none_technique():
    # technique must be a string. Passing None is a programming error
    # and should produce a clear ValueError, not a confusing AttributeError.
    with pytest.raises(ValueError):
        CoercionResult(
            technique=None,
            target="127.0.0.1",
            success=None,
            detail="Test",
        )


def test_result_rejects_integer_technique():
    # Same reasoning as None — an integer is not a valid technique name.
    with pytest.raises(ValueError):
        CoercionResult(
            technique=42,
            target="127.0.0.1",
            success=None,
            detail="Test",
        )


# ---------------------------------------------------------------------------
# CoercionResult — target validation
# ---------------------------------------------------------------------------

def test_result_rejects_empty_target():
    # A result with no target cannot be traced back to any machine.
    # That makes it useless in a report, so it must be rejected.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target="",
            success=None,
            detail="Test",
        )


def test_result_rejects_whitespace_target():
    # Whitespace-only is treated the same as empty.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target="   ",
            success=None,
            detail="Test",
        )


def test_result_rejects_none_target():
    # target must be a string. None should give a clear ValueError.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target=None,
            success=None,
            detail="Test",
        )


def test_result_rejects_integer_target():
    # An IP address stored as an integer is not a valid target string.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target=3232235530,
            success=None,
            detail="Test",
        )


# ---------------------------------------------------------------------------
# CoercionResult — success validation
# ---------------------------------------------------------------------------

def test_result_rejects_string_success():
    # "yes", "no", "maybe" are not valid. Only True, False, or None are.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target="192.168.1.1",
            success="yes",
            detail="Test",
        )


def test_result_rejects_integer_1_as_success():
    # In Python, 1 == True but 1 is not True. We require the real boolean,
    # not an integer that happens to compare equal to it.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target="192.168.1.1",
            success=1,
            detail="Test",
        )


def test_result_rejects_integer_0_as_success():
    # Same as above: 0 == False in Python, but 0 is not False.
    with pytest.raises(ValueError):
        CoercionResult(
            technique="PrinterBug",
            target="192.168.1.1",
            success=0,
            detail="Test",
        )
