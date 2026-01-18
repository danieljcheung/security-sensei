"""Code scanner for detecting security vulnerabilities in source code."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class CodeScanner(BaseScanner):
    """Scanner for detecting security vulnerabilities in source code.

    Detects patterns like SQL injection, command injection, XSS,
    path traversal, insecure deserialization, and weak cryptography.
    """

    name = "code"
    description = "Detects security vulnerabilities in source code"
    applies_to = []  # Applies to all supported languages

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)
        self._patterns_data = self._load_patterns()
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, Dict]]] = {}
        self._language_extensions = self._patterns_data.get("language_extensions", {})
        self._compile_patterns()

    def _load_patterns(self) -> Dict:
        """Load code patterns from JSON file."""
        rules_path = Path(__file__).parent.parent / "rules" / "code_patterns.json"
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            return {"patterns": {}, "language_extensions": {}}

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        patterns_by_lang = self._patterns_data.get("patterns", {})

        for language, patterns in patterns_by_lang.items():
            self._compiled_patterns[language] = []
            for pattern_def in patterns:
                try:
                    flags = 0
                    flag_str = pattern_def.get("flags", "")
                    if "IGNORECASE" in flag_str:
                        flags |= re.IGNORECASE
                    if "MULTILINE" in flag_str:
                        flags |= re.MULTILINE
                    if "DOTALL" in flag_str:
                        flags |= re.DOTALL

                    compiled = re.compile(pattern_def["pattern"], flags)
                    self._compiled_patterns[language].append((compiled, pattern_def))
                except re.error as e:
                    # Skip invalid patterns
                    pass

    def scan(self) -> List[Finding]:
        """Scan source code for security vulnerabilities."""
        findings: List[Finding] = []

        # Get files for each language
        for language, extensions in self._language_extensions.items():
            if language not in self._compiled_patterns:
                continue

            # Find files with matching extensions
            for ext in extensions:
                pattern = f"*{ext}"
                for file_path in self._find_files([pattern]):
                    content = self._read_file(file_path)
                    if content is None:
                        continue

                    # Scan this file with language-specific patterns
                    file_findings = self._scan_file(
                        file_path, content, language
                    )
                    findings.extend(file_findings)

        return findings

    def _scan_file(
        self, file_path: Path, content: str, language: str
    ) -> List[Finding]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file.
            content: File content.
            language: Programming language of the file.

        Returns:
            List of findings in this file.
        """
        findings: List[Finding] = []
        lines = content.splitlines()
        patterns = self._compiled_patterns.get(language, [])

        # Track findings to avoid duplicates on same line
        seen_findings: Set[str] = set()

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments (basic heuristic)
            stripped = line.strip()
            if not stripped:
                continue

            # Skip obvious comment lines
            if self._is_comment_line(stripped, language):
                continue

            # Check each pattern
            for compiled_pattern, pattern_def in patterns:
                if compiled_pattern.search(line):
                    # Apply additional context checks if needed
                    if not self._validate_context(
                        content, line_num, line, pattern_def, language
                    ):
                        continue

                    # Create unique key to avoid duplicate findings
                    finding_key = f"{file_path}:{line_num}:{pattern_def['id']}"
                    if finding_key in seen_findings:
                        continue
                    seen_findings.add(finding_key)

                    finding = self._create_code_finding(
                        pattern_def=pattern_def,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line,
                        language=language,
                    )
                    findings.append(finding)

        return findings

    def _is_comment_line(self, line: str, language: str) -> bool:
        """Check if a line is a comment.

        Args:
            line: The stripped line content.
            language: The programming language.

        Returns:
            True if the line is a comment.
        """
        # Single-line comment prefixes by language
        comment_prefixes = {
            "python": ("#",),
            "javascript": ("//",),
            "typescript": ("//",),
            "java": ("//", "*"),
            "go": ("//",),
            "php": ("//", "#", "*"),
            "ruby": ("#",),
        }

        prefixes = comment_prefixes.get(language, ("#", "//"))
        return any(line.startswith(prefix) for prefix in prefixes)

    def _validate_context(
        self,
        content: str,
        line_num: int,
        line: str,
        pattern_def: Dict,
        language: str,
    ) -> bool:
        """Validate that the pattern match is in a meaningful context.

        This helps reduce false positives by checking surrounding context.

        Args:
            content: Full file content.
            line_num: Line number of the match.
            line: The matched line.
            pattern_def: Pattern definition.
            language: Programming language.

        Returns:
            True if the context is valid for this vulnerability.
        """
        pattern_id = pattern_def.get("id", "")

        # Skip weak crypto findings if in test/mock context
        if "weak-crypto" in pattern_id:
            lower_line = line.lower()
            # Common false positive indicators
            if any(ind in lower_line for ind in ["test", "mock", "example", "demo"]):
                return False

        # For Math.random, check if it's used for security purposes
        if pattern_id == "weak-random":
            # Check context for security-related usage
            context = self._get_context_lines(content, line_num, 3).lower()
            security_indicators = ["token", "secret", "password", "key", "auth", "session"]
            if not any(ind in context for ind in security_indicators):
                return False

        # For innerHTML/document.write, check if content is static
        if pattern_id in ("xss-innerhtml", "xss-document-write", "xss-outerhtml"):
            # If the value is a static string literal, lower confidence
            if re.search(r'=\s*["\'][^"\']+["\']', line):
                # Still flag but could reduce confidence in metadata
                pass

        # For path traversal, ensure it's not just a config constant
        if "path-traversal" in pattern_id:
            lower_line = line.lower()
            if any(ind in lower_line for ind in ["config", "const", "constant", "__file__"]):
                return False

        # For message event listeners, only flag if no origin check nearby
        if pattern_id == "postmessage-origin":
            context = self._get_context_lines(content, line_num, 10).lower()
            if "origin" in context:
                return False

        return True

    def _create_code_finding(
        self,
        pattern_def: Dict,
        file_path: Path,
        line_number: int,
        line_content: str,
        language: str,
    ) -> Finding:
        """Create a finding for a detected code vulnerability.

        Args:
            pattern_def: The matching pattern definition.
            file_path: Path to the file.
            line_number: Line number of the finding.
            line_content: The line content.
            language: Programming language.

        Returns:
            A Finding object.
        """
        # Map string severity to enum
        severity_str = pattern_def.get("severity", "MEDIUM")
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        severity = severity_map.get(severity_str.upper(), Severity.MEDIUM)

        # Map string confidence to enum
        confidence_str = pattern_def.get("confidence", "MEDIUM")
        confidence_map = {
            "HIGH": Confidence.HIGH,
            "MEDIUM": Confidence.MEDIUM,
            "LOW": Confidence.LOW,
        }
        confidence = confidence_map.get(confidence_str.upper(), Confidence.MEDIUM)

        return self._create_finding(
            type=f"code_vulnerability.{pattern_def['id']}",
            title=pattern_def["name"],
            description=pattern_def.get(
                "description",
                f"Detected potential {pattern_def['name']} vulnerability."
            ),
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            code_snippet=line_content.strip(),
            fix_recommendation=pattern_def.get(
                "fix",
                "Review and fix the identified security issue."
            ),
            cwe_id=pattern_def.get("cwe"),
            owasp_category=pattern_def.get("owasp"),
            auto_fixable=False,
            metadata={
                "scanner": self.name,
                "pattern_id": pattern_def["id"],
                "language": language,
                "category": self._get_category(pattern_def["id"]),
            },
        )

    def _get_category(self, pattern_id: str) -> str:
        """Get the vulnerability category from pattern ID.

        Args:
            pattern_id: The pattern identifier.

        Returns:
            Category name.
        """
        categories = {
            "sql-injection": "SQL Injection",
            "command-injection": "Command Injection",
            "xss": "Cross-Site Scripting",
            "path-traversal": "Path Traversal",
            "insecure-deserialization": "Insecure Deserialization",
            "weak-crypto": "Weak Cryptography",
            "exec-eval": "Code Injection",
            "xxe": "XML External Entity",
            "ssrf": "Server-Side Request Forgery",
            "open-redirect": "Open Redirect",
            "prototype-pollution": "Prototype Pollution",
        }

        for key, category in categories.items():
            if key in pattern_id:
                return category

        return "Security Vulnerability"

    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages.

        Returns:
            List of supported language names.
        """
        return list(self._language_extensions.keys())

    def get_patterns_for_language(self, language: str) -> List[Dict]:
        """Get all patterns for a specific language.

        Args:
            language: The programming language.

        Returns:
            List of pattern definitions.
        """
        return self._patterns_data.get("patterns", {}).get(language, [])
