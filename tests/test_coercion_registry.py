
import pytest

from coercion.base import CoercionModule, CoercionResult
from coercion.registry import ModuleRegistry


class ExampleModule(CoercionModule):
    name = "example"
    description = "Test module"

    def run(self, target: str) -> CoercionResult:
        return CoercionResult(
            technique=self.name,
            target=target,
            success=True,
            detail="Test only",
        )


def test_register_and_create_module():
    registry = ModuleRegistry()
    registry.register(ExampleModule)

    module = registry.create("example")

    assert isinstance(module, ExampleModule)


def test_list_available_modules():
    registry = ModuleRegistry()
    registry.register(ExampleModule)

    assert registry.available() == ["example"]


def test_duplicate_registration_fails():
    registry = ModuleRegistry()
    registry.register(ExampleModule)

    with pytest.raises(ValueError):
        registry.register(ExampleModule)


def test_unknown_module_fails():
    registry = ModuleRegistry()

    with pytest.raises(KeyError):
        registry.create("missing")
