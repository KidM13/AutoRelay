"""Build the registry of available coercion modules."""

from coercion.example import ExampleModule
from coercion.registry import ModuleRegistry


def build_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    registry.register(ExampleModule)
    return registry