"""Main scanner orchestrator for Security Sensei."""

from __future__ import annotations

import importlib
import pkgutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Type

from sensei.core.finding import Finding, Severity
from sensei.core.project import ProjectAnalyzer
from sensei.core.baseline import BaselineManager

if TYPE_CHECKING:
    from sensei.scanners.base import BaseScanner


@dataclass
class ScanResult:
    """Result of a security scan."""

    findings: List[Finding]
    project_info: Dict
    scan_time: float  # Time in seconds
    scanners_run: List[str]
    auto_fixes_applied: int = 0
    baselined_count: int = 0

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count of findings grouped by severity."""
        counts: Dict[str, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> Dict:
        """Convert scan result to dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "project_info": self.project_info,
            "scan_time": self.scan_time,
            "scanners_run": self.scanners_run,
            "auto_fixes_applied": self.auto_fixes_applied,
            "baselined_count": self.baselined_count,
            "summary": {
                "total": self.total_findings,
                "by_severity": self.findings_by_severity,
            },
        }


class SenseiScanner:
    """Main orchestrator for running security scans.

    Discovers and runs all applicable scanners, aggregates findings,
    handles deduplication, and manages baselines.
    """

    def __init__(self, project_path: str, config: Optional[Dict] = None):
        """Initialize the scanner.

        Args:
            project_path: Path to the project to scan.
            config: Optional configuration dictionary.
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or {}
        self.project_analyzer = ProjectAnalyzer(str(self.project_path))
        self.baseline_manager = BaselineManager(str(self.project_path))
        self._scanner_classes: List[Type[Any]] = []
        self._discover_scanners()

    def _discover_scanners(self) -> None:
        """Discover all scanner classes from the sensei.scanners package."""
        try:
            import sensei.scanners as scanners_pkg
            from sensei.scanners.base import BaseScanner

            for importer, modname, ispkg in pkgutil.iter_modules(scanners_pkg.__path__):
                if modname == "base":
                    continue  # Skip the base module

                try:
                    module = importlib.import_module(f"sensei.scanners.{modname}")

                    # Find all BaseScanner subclasses in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, BaseScanner)
                            and attr is not BaseScanner
                        ):
                            self._scanner_classes.append(attr)
                except ImportError as e:
                    # Log error but continue with other scanners
                    if self.config.get("verbose"):
                        print(f"Warning: Could not load scanner {modname}: {e}")
        except ImportError:
            pass

    def scan(
        self,
        categories: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
        include_baselined: bool = False,
    ) -> ScanResult:
        """Run a security scan on the project.

        Args:
            categories: List of scanner categories to run (e.g., ["secrets", "code"]).
                       If None, runs all applicable scanners.
            min_severity: Minimum severity level to include in results.
            include_baselined: Whether to include baselined findings.

        Returns:
            ScanResult containing all findings and metadata.
        """
        start_time = time.time()

        # Analyze the project
        project_info = self.project_analyzer.analyze()
        languages = project_info["languages"]
        frameworks = project_info["frameworks"]

        # Initialize scanners and filter by applicability
        applicable_scanners: List[Any] = []
        for scanner_class in self._scanner_classes:
            scanner = scanner_class(self.project_path, self.config)

            # Filter by category if specified
            if categories and scanner.name not in categories:
                continue

            # Check if scanner applies to this project
            if scanner.is_applicable(languages, frameworks):
                applicable_scanners.append(scanner)

        # Run all applicable scanners
        all_findings: List[Finding] = []
        scanners_run: List[str] = []

        for scanner in applicable_scanners:
            try:
                findings = scanner.scan()
                all_findings.extend(findings)
                scanners_run.append(scanner.name)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"Warning: Scanner {scanner.name} failed: {e}")

        # Deduplicate findings by ID
        seen_ids: Set[str] = set()
        unique_findings: List[Finding] = []
        for finding in all_findings:
            if finding.id not in seen_ids:
                seen_ids.add(finding.id)
                unique_findings.append(finding)

        # Track baselined count before filtering
        baselined_count = sum(
            1 for f in unique_findings if self.baseline_manager.is_baselined(f.id)
        )

        # Filter out baselined findings unless requested
        if not include_baselined:
            unique_findings = self.baseline_manager.filter_findings(unique_findings)

        # Filter by minimum severity
        if min_severity:
            unique_findings = [
                f
                for f in unique_findings
                if Severity.compare(f.severity, min_severity) >= 0
            ]

        # Sort findings by severity (critical first) then by file
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        unique_findings.sort(
            key=lambda f: (severity_order.get(f.severity, 5), f.file_path, f.line_number or 0)
        )

        scan_time = time.time() - start_time

        return ScanResult(
            findings=unique_findings,
            project_info=project_info,
            scan_time=scan_time,
            scanners_run=scanners_run,
            baselined_count=baselined_count,
        )

    def get_available_scanners(self) -> List[Dict]:
        """Get information about all available scanners.

        Returns:
            List of dicts with scanner name, description, and applies_to.
        """
        return [
            {
                "name": scanner.name,
                "description": scanner.description,
                "applies_to": scanner.applies_to,
            }
            for scanner in self._scanner_classes
        ]


# Keep backward compatibility alias
Scanner = SenseiScanner
