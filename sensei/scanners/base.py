"""Base scanner abstract class."""

from abc import ABC, abstractmethod
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Set

from sensei.core.finding import Finding


class BaseScanner(ABC):
    """Abstract base class for all security scanners.

    All scanner implementations should inherit from this class and implement
    the scan() method.
    """

    # Scanner metadata - override in subclasses
    name: str = "base"
    description: str = "Base scanner"
    applies_to: List[str] = []  # Empty means applies to all languages/platforms

    # Default exclude patterns
    DEFAULT_EXCLUDES = [
        "node_modules",
        ".git",
        "__pycache__",
        "*.pyc",
        ".venv",
        "venv",
        "env",
        ".env",
        "dist",
        "build",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "*.egg-info",
        ".eggs",
        "vendor",
        "Pods",
        ".build",
        "DerivedData",
    ]

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        """Initialize the scanner.

        Args:
            project_path: Path to the project root directory.
            config: Optional configuration dictionary for the scanner.
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or {}

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Scan the project for security vulnerabilities.

        Returns:
            A list of findings.
        """
        pass

    def is_applicable(self, languages: List[str], frameworks: List[str]) -> bool:
        """Check if this scanner is applicable to the given project.

        Args:
            languages: List of detected languages in the project.
            frameworks: List of detected frameworks in the project.

        Returns:
            True if the scanner should run on this project.
        """
        # If applies_to is empty, scanner applies to all projects
        if not self.applies_to:
            return True

        # Check if any detected language/framework matches
        all_detected = set(languages + frameworks)
        return bool(all_detected & set(self.applies_to))

    def _read_file(self, path: Path) -> Optional[str]:
        """Read a file, handling encoding errors gracefully.

        Args:
            path: Path to the file to read.

        Returns:
            File contents as string, or None if file cannot be read.
        """
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]

        for encoding in encodings:
            try:
                with open(path, "r", encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except (IOError, OSError):
                return None

        # Last resort: read with errors ignored
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except (IOError, OSError):
            return None

    def _find_files(
        self,
        patterns: List[str],
        exclude: Optional[List[str]] = None,
    ) -> List[Path]:
        """Find files matching the given patterns.

        Args:
            patterns: List of glob patterns to match (e.g., ["*.py", "*.js"]).
            exclude: Additional patterns to exclude. Combined with DEFAULT_EXCLUDES.

        Returns:
            List of matching file paths.
        """
        exclude_patterns = set(self.DEFAULT_EXCLUDES)
        if exclude:
            exclude_patterns.update(exclude)

        # Add config-based excludes
        if "exclude" in self.config:
            exclude_patterns.update(self.config["exclude"])

        matching_files: List[Path] = []

        for pattern in patterns:
            for path in self.project_path.rglob(pattern):
                if path.is_file() and not self._is_excluded(path, exclude_patterns):
                    matching_files.append(path)

        return sorted(set(matching_files))

    def _is_excluded(self, path: Path, exclude_patterns: Set[str]) -> bool:
        """Check if a path should be excluded.

        Args:
            path: Path to check.
            exclude_patterns: Set of patterns to exclude.

        Returns:
            True if the path should be excluded.
        """
        # Get path relative to project root
        try:
            rel_path = path.relative_to(self.project_path)
        except ValueError:
            rel_path = path

        # Check each part of the path
        parts = rel_path.parts
        for pattern in exclude_patterns:
            # Check if any part matches the pattern
            for part in parts:
                if fnmatch(part, pattern):
                    return True
            # Also check the full relative path
            if fnmatch(str(rel_path), pattern):
                return True

        return False

    def _create_finding(
        self,
        type: str,
        title: str,
        description: str,
        severity: str,
        confidence: str,
        file_path: Path,
        fix_recommendation: str,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        auto_fixable: bool = False,
        metadata: Optional[Dict] = None,
    ) -> Finding:
        """Create a finding with this scanner's context.

        Args:
            type: Type of vulnerability (e.g., "hardcoded_secret").
            title: Short title describing the finding.
            description: Detailed description of the vulnerability.
            severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO).
            confidence: Confidence level (HIGH/MEDIUM/LOW).
            file_path: Path to the affected file.
            fix_recommendation: How to fix the vulnerability.
            line_number: Line number where the issue was found.
            code_snippet: Relevant code snippet.
            cwe_id: CWE identifier (e.g., "CWE-798").
            owasp_category: OWASP category (e.g., "A01:2021").
            auto_fixable: Whether this can be automatically fixed.
            metadata: Additional scanner-specific data.

        Returns:
            A new Finding instance.
        """
        # Convert to relative path for cleaner output
        try:
            rel_path = file_path.relative_to(self.project_path)
        except ValueError:
            rel_path = file_path

        return Finding(
            type=type,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=str(rel_path),
            fix_recommendation=fix_recommendation,
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            auto_fixable=auto_fixable,
            metadata=metadata or {"scanner": self.name},
        )

    def _get_line_content(self, content: str, line_number: int) -> str:
        """Get the content of a specific line.

        Args:
            content: Full file content.
            line_number: 1-indexed line number.

        Returns:
            The line content, or empty string if line doesn't exist.
        """
        lines = content.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""

    def _get_context_lines(
        self, content: str, line_number: int, context: int = 2
    ) -> str:
        """Get a code snippet with context lines.

        Args:
            content: Full file content.
            line_number: 1-indexed line number of the main line.
            context: Number of lines before and after to include.

        Returns:
            Code snippet with context.
        """
        lines = content.splitlines()
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])
