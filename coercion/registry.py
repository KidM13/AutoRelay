
"""Registry for AutoRelay coercion modules."""

from coercion.base import CoercionModule


class ModuleRegistry:
    """Stores and provides access to coercion modules."""

    def __init__(self):
        self._modules: dict[str, type[CoercionModule]] = {}

    def register(self, module_class: type[CoercionModule]) -> None:
        """Register a coercion module class."""

        if not issubclass(module_class, CoercionModule):
            raise TypeError("Module must inherit from CoercionModule")

        if not module_class.name or module_class.name == "unknown":
            raise ValueError("Module must have a valid name")

        if module_class.name in self._modules:
            raise ValueError(f"Module already registered: {module_class.name}")

        self._modules[module_class.name] = module_class

    def create(self, name: str) -> CoercionModule:
        """Create an instance of a registered module."""

        if name not in self._modules:
            raise KeyError(f"Unknown coercion module: {name}")

        return self._modules[name]()

    def available(self) -> list[str]:
        """Return the names of registered modules."""

        return sorted(self._modules.keys())
