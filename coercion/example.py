"""Example module for testing the registry."""

from coercion.base import CoercionModule, CoercionResult


class ExampleModule(CoercionModule):
    name = "example"
    description = "Placeholder module for testing"

    def run(self, target: str) -> CoercionResult:
        return CoercionResult(
            technique=self.name,
            target=target,
            success=None,
            detail="Placeholder only; no action performed.",
        )