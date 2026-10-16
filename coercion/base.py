
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


class CoercionModule(ABC):
    """Common interface for all coercion modules."""

    name: str = "unknown"
    description: str = ""

    @abstractmethod
    def run(self, target: str) -> CoercionResult:
        """Run the module against the explicitly specified target."""
        raise NotImplementedError
