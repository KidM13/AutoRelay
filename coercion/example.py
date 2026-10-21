"""Example coercion module — for demonstration and testing only.

This module exists to show how a real coercion module is structured.
It does NOT perform any network activity, authentication attempts,
or real coercion of any kind.

Use it to:
- Understand the CoercionModule / CoercionResult interface.
- Test the module registry and reporting pipeline with safe, predictable output.
- Serve as a starting template when writing a new coercion module.
"""

from coercion.base import CoercionModule, CoercionResult


class ExampleModule(CoercionModule):
    """A non-operational placeholder that demonstrates the coercion module interface.

    Running this module against any target is completely safe — it performs
    no network calls and returns a fixed UNKNOWN result every time.
    """

    name = "example"
    description = "Non-operational placeholder for interface demonstration and testing"

    def run(self, target: str) -> CoercionResult:
        """Return a fixed placeholder result without taking any action.

        Args:
            target: The target hostname or IP address (must be a non-empty string).

        Returns:
            A CoercionResult with success=None (UNKNOWN) and a fixed detail message.

        Raises:
            ValueError: If target is not a non-empty string.
        """
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        return CoercionResult(
            technique=self.name,
            target=target,
            success=None,
            detail="Placeholder only; no action performed.",
        )
