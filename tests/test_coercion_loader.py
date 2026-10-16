from coercion.loader import build_registry


def test_build_registry_registers_example_module():
    registry = build_registry()

    assert registry.available() == ["example"]