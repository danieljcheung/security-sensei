"""Core components for Security Sensei."""

from .finding import Finding, Severity, Confidence
from .scanner import SenseiScanner, ScanResult, Scanner
from .project import ProjectAnalyzer
from .baseline import BaselineManager

__all__ = [
    "Finding",
    "Severity",
    "Confidence",
    "SenseiScanner",
    "ScanResult",
    "Scanner",  # Backward compatibility alias
    "ProjectAnalyzer",
    "BaselineManager",
]
