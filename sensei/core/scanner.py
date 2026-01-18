"""Scanner orchestrator for running all security scanners."""

from pathlib import Path
from typing import List

from sensei.core.finding import Finding
from sensei.core.project import ProjectAnalyzer
from sensei.core.baseline import BaselineManager
from sensei.scanners.base import BaseScanner


class Scanner:
    """Orchestrates all security scanners and aggregates findings."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.project_analyzer = ProjectAnalyzer(path)
        self.baseline_manager = BaselineManager(path)
        self.scanners: List[BaseScanner] = []

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a scanner to run during scans."""
        self.scanners.append(scanner)

    def scan(self) -> List[Finding]:
        """Run all registered scanners and aggregate findings."""
        findings: List[Finding] = []

        for scanner in self.scanners:
            scanner_findings = scanner.scan(self.path)
            findings.extend(scanner_findings)

        # Filter out baselined findings
        findings = self.baseline_manager.filter_findings(findings)

        return findings
