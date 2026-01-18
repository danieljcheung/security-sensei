"""Secrets scanner for detecting hardcoded credentials."""

import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Set

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class SecretsScanner(BaseScanner):
    """Scanner for detecting hardcoded secrets, API keys, and credentials."""

    name = "secrets"
    description = "Detects hardcoded secrets, API keys, tokens, and credentials"
    applies_to = []  # Applies to all languages

    # CWE and OWASP mappings
    CWE_ID = "CWE-798"
    OWASP_CATEGORY = "A07:2021"

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".swift",
        ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp",
        ".json", ".yaml", ".yml", ".toml", ".xml", ".properties", ".conf",
        ".config", ".ini", ".env", ".sh", ".bash", ".zsh", ".ps1",
        ".tf", ".hcl", ".gradle", ".sql", ".md", ".txt", ".cfg",
    }

    # Additional directories to exclude for secrets scanning
    SECRETS_EXCLUDES = [
        "rules",  # Exclude our own rules directory
        "*.json",  # Exclude JSON config files (may contain pattern definitions)
    ]

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)
        self._rules = self._load_rules()
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _load_rules(self) -> Dict:
        """Load secret detection rules from JSON file."""
        rules_path = Path(__file__).parent.parent / "rules" / "secrets.json"
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            # Return minimal default rules if file can't be loaded
            return {
                "patterns": [],
                "exclude_patterns": [],
                "exclude_content_patterns": [],
            }

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for rule in self._rules.get("patterns", []):
            try:
                self._compiled_patterns[rule["id"]] = re.compile(rule["pattern"])
            except re.error:
                # Skip invalid patterns
                pass

    def scan(self) -> List[Finding]:
        """Scan for hardcoded secrets."""
        findings: List[Finding] = []

        # Get all scannable files
        files = self._get_scannable_files()

        for file_path in files:
            # Skip excluded files
            if self._is_excluded_file(file_path):
                continue

            content = self._read_file(file_path)
            if content is None:
                continue

            # Scan each line
            lines = content.splitlines()
            for line_num, line in enumerate(lines, start=1):
                # Skip lines with placeholder content
                if self._is_placeholder_line(line):
                    continue

                # Check each pattern
                for rule in self._rules.get("patterns", []):
                    pattern = self._compiled_patterns.get(rule["id"])
                    if pattern is None:
                        continue

                    matches = pattern.finditer(line)
                    for match in matches:
                        # For context-sensitive patterns, check context
                        if "context_patterns" in rule:
                            if not self._has_context(content, line_num, rule["context_patterns"]):
                                continue

                        # Double-check it's not a placeholder
                        matched_text = match.group(0)
                        if self._is_placeholder_value(matched_text):
                            continue

                        finding = self._create_secret_finding(
                            rule=rule,
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line,
                            matched_text=matched_text,
                        )
                        findings.append(finding)

        return findings

    def _get_scannable_files(self) -> List[Path]:
        """Get all files that should be scanned for secrets."""
        all_files: List[Path] = []

        for ext in self.SCANNABLE_EXTENSIONS:
            pattern = f"*{ext}"
            all_files.extend(self._find_files([pattern], exclude=self.SECRETS_EXCLUDES))

        # Also check files without extensions that might contain secrets
        for file_path in self.project_path.rglob("*"):
            if file_path.is_file() and file_path.suffix == "":
                name = file_path.name.lower()
                if name in {".env", ".envrc", "credentials", "secrets"}:
                    all_files.append(file_path)

        return list(set(all_files))

    def _is_excluded_file(self, file_path: Path) -> bool:
        """Check if a file should be excluded from scanning."""
        filename = file_path.name

        # Check exclude patterns from rules
        for pattern in self._rules.get("exclude_patterns", []):
            if fnmatch(filename, pattern):
                return True

        return False

    def _is_placeholder_line(self, line: str) -> bool:
        """Check if a line contains placeholder content."""
        line_lower = line.lower()

        for pattern in self._rules.get("exclude_content_patterns", []):
            if pattern.lower() in line_lower:
                return True

        return False

    def _is_placeholder_value(self, value: str) -> bool:
        """Check if a matched value is likely a placeholder."""
        value_lower = value.lower()

        # Check for common placeholder patterns
        placeholder_indicators = [
            "example", "placeholder", "your_", "your-", "<your",
            "xxx", "changeme", "insert_", "todo", "fixme",
            "dummy", "fake", "test_key", "test-key", "sample_", "sample-",
        ]

        for indicator in placeholder_indicators:
            if indicator in value_lower:
                return True

        # Check for repeated characters (e.g., "aaaaaaa", "0000000")
        if len(set(value.replace("-", "").replace("_", ""))) <= 2:
            return True

        return False

    def _has_context(self, content: str, line_num: int, context_patterns: List[str]) -> bool:
        """Check if the surrounding context contains expected patterns."""
        lines = content.splitlines()

        # Check lines around the match (5 lines before and after)
        start = max(0, line_num - 6)
        end = min(len(lines), line_num + 5)
        context = "\n".join(lines[start:end]).lower()

        for pattern in context_patterns:
            if pattern.lower() in context:
                return True

        return False

    def _create_secret_finding(
        self,
        rule: Dict,
        file_path: Path,
        line_number: int,
        line_content: str,
        matched_text: str,
    ) -> Finding:
        """Create a finding for a detected secret."""
        # Mask the secret in the code snippet
        masked_snippet = self._mask_secret(line_content, matched_text)

        return self._create_finding(
            type=f"hardcoded_secret.{rule['id']}",
            title=rule["name"],
            description=rule.get("description", f"Detected {rule['name']} in source code."),
            severity=rule.get("severity", Severity.HIGH),
            confidence=rule.get("confidence", Confidence.MEDIUM),
            file_path=file_path,
            fix_recommendation=rule.get("fix", "Remove hardcoded secrets and use environment variables."),
            line_number=line_number,
            code_snippet=masked_snippet,
            cwe_id=self.CWE_ID,
            owasp_category=self.OWASP_CATEGORY,
            auto_fixable=False,
            metadata={
                "scanner": self.name,
                "rule_id": rule["id"],
                "secret_type": rule["name"],
                "masked_match": self._mask_secret(matched_text, matched_text),
            },
        )

    def _mask_secret(self, text: str, secret: str) -> str:
        """Mask a secret value in text, showing only first/last few characters."""
        if len(secret) <= 8:
            masked = "*" * len(secret)
        else:
            # Show first 4 and last 4 characters
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

        return text.replace(secret, masked)
