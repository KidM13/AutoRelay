import pytest

from coercion.base import CoercionModule,CoercionResult


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


def test_module_implements_run():
    module = ExampleModule()

    result = module.run("127.0.0.1")

    assert result.technique == "example"
    assert result.target == "127.0.0.1"
    assert result.success is True


def test_abstract_class_cannot_be_instantiated():
    with pytest.raises(TypeError):
        CoercionModule()