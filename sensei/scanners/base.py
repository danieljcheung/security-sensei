"""Base scanner abstract class."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from sensei.core.finding import Finding


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    name: str = "base"
    description: str = "Base scanner"

    @abstractmethod
    def scan(self, path: Path) -> List[Finding]:
        """Scan the given path for security vulnerabilities.

        Args:
            path: The path to scan.

        Returns:
            A list of findings.
        """
        pass

    def is_applicable(self, path: Path) -> bool:
        """Check if this scanner is applicable to the given path.

        Override this method to implement scanner-specific checks.

        Args:
            path: The path to check.

        Returns:
            True if the scanner should run on this path.
        """
        return True
