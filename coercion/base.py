
"""Base interface for AutoRelay coercion modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CoercionResult:
    """Result returned by a coercion module."""

    technique: str
    target: str
    success: bool | None
    detail: str

    def __post_init__(self) -> None:
        """Validate fields after the dataclass is created."""
        if not isinstance(self.technique, str) or not self.technique.strip():
            raise ValueError("technique must be a non-empty string")
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be a non-empty string")
        if self.success is not True and self.success is not False and self.success is not None:
            raise ValueError("success must be True, False, or None")


class CoercionModule(ABC):
    """Common interface for all coercion modules."""

    name: str = "unknown"
    description: str = ""

    @abstractmethod
    def run(self, target: str) -> CoercionResult:
        """Run the module against the explicitly specified target."""
        raise NotImplementedError
