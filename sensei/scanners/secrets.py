"""Secrets scanner for detecting hardcoded credentials."""

import json
import re
import subprocess
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
        self._include_git_history = config.get("include_git_history", False) if config else False

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

        # Scan current files
        findings.extend(self._scan_current_files())

        # Optionally scan git history
        if self._include_git_history:
            findings.extend(self.scan_git_history())

        return findings

    def _scan_current_files(self) -> List[Finding]:
        """Scan current files for secrets."""
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

    def scan_git_history(self) -> List[Finding]:
        """Scan git history for secrets that may have been committed and deleted.

        Returns:
            List of findings from git history.
        """
        findings: List[Finding] = []

        # Check if this is a git repository
        if not (self.project_path / ".git").exists():
            return findings

        try:
            # Run git log to get full history with diffs
            # Use encoding='utf-8' and errors='replace' to handle binary content
            result = subprocess.run(
                [
                    "git", "log", "-p", "--all", "--full-history",
                    "--no-color",
                    "--"
                ],
                cwd=self.project_path,
                capture_output=True,
                timeout=300,  # 5 minute timeout
                encoding="utf-8",
                errors="replace",  # Replace undecodable bytes
            )

            if result.returncode != 0:
                return findings

            if not result.stdout:
                return findings

            # Parse the git log output
            findings.extend(self._parse_git_log(result.stdout))

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
            # Git not available or timed out
            pass

        return findings

    def _parse_git_log(self, log_output: str) -> List[Finding]:
        """Parse git log output and scan for secrets.

        Args:
            log_output: Output from git log -p command.

        Returns:
            List of findings from git history.
        """
        findings: List[Finding] = []
        seen_secrets: Set[str] = set()  # Track unique secrets to avoid duplicates

        current_commit = None
        current_file = None
        current_line_in_file = 0

        # Regex patterns for parsing git log
        commit_pattern = re.compile(r"^commit ([a-f0-9]{40})")
        file_pattern = re.compile(r"^\+\+\+ b/(.+)$")
        hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
        added_line_pattern = re.compile(r"^\+(.*)$")

        lines = log_output.splitlines()
        for line in lines:
            # Check for new commit
            commit_match = commit_pattern.match(line)
            if commit_match:
                current_commit = commit_match.group(1)[:8]  # Short hash
                continue

            # Check for file being modified
            file_match = file_pattern.match(line)
            if file_match:
                current_file = file_match.group(1)
                # Skip excluded directories/files
                if self._should_skip_historical_file(current_file):
                    current_file = None
                continue

            # Check for hunk header (line numbers)
            hunk_match = hunk_pattern.match(line)
            if hunk_match:
                current_line_in_file = int(hunk_match.group(1))
                continue

            # Check for added lines
            added_match = added_line_pattern.match(line)
            if added_match and current_commit and current_file:
                added_content = added_match.group(1)

                # Skip placeholder lines
                if self._is_placeholder_line(added_content):
                    current_line_in_file += 1
                    continue

                # Scan the added line for secrets
                for rule in self._rules.get("patterns", []):
                    pattern = self._compiled_patterns.get(rule["id"])
                    if pattern is None:
                        continue

                    matches = pattern.finditer(added_content)
                    for match in matches:
                        matched_text = match.group(0)

                        # Skip placeholders
                        if self._is_placeholder_value(matched_text):
                            continue

                        # Create unique key to avoid duplicates
                        secret_key = f"{current_file}:{rule['id']}:{matched_text}"
                        if secret_key in seen_secrets:
                            continue
                        seen_secrets.add(secret_key)

                        # Check if the secret still exists in the current file
                        still_present = self._is_secret_still_present(
                            current_file, matched_text
                        )

                        finding = self._create_historical_finding(
                            rule=rule,
                            file_path=current_file,
                            line_number=current_line_in_file,
                            line_content=added_content,
                            matched_text=matched_text,
                            commit_hash=current_commit,
                            deleted=not still_present,
                        )
                        findings.append(finding)

                current_line_in_file += 1

        return findings

    def _should_skip_historical_file(self, file_path: str) -> bool:
        """Check if a file from git history should be skipped.

        Args:
            file_path: Relative path to the file.

        Returns:
            True if the file should be skipped.
        """
        # Skip files in excluded directories
        skip_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv",
                     "rules", "dist", "build", ".tox", ".pytest_cache"}
        parts = file_path.replace("\\", "/").split("/")
        for part in parts:
            if part in skip_dirs:
                return True

        # Skip excluded file patterns
        filename = parts[-1] if parts else ""
        for pattern in self._rules.get("exclude_patterns", []):
            if fnmatch(filename, pattern):
                return True

        # Skip JSON files (may contain pattern definitions)
        if filename.endswith(".json"):
            return True

        return False

    def _is_secret_still_present(self, file_path: str, secret: str) -> bool:
        """Check if a secret is still present in the current version of a file.

        Args:
            file_path: Relative path to the file.
            secret: The secret value to look for.

        Returns:
            True if the secret is still in the file, False if deleted.
        """
        full_path = self.project_path / file_path
        if not full_path.exists():
            return False

        content = self._read_file(full_path)
        if content is None:
            return False

        return secret in content

    def _create_historical_finding(
        self,
        rule: Dict,
        file_path: str,
        line_number: int,
        line_content: str,
        matched_text: str,
        commit_hash: str,
        deleted: bool,
    ) -> Finding:
        """Create a finding for a secret found in git history.

        Args:
            rule: The matching rule from secrets.json.
            file_path: Path to the file (relative).
            line_number: Line number in the historical version.
            line_content: The line content.
            matched_text: The matched secret text.
            commit_hash: Short commit hash where secret was added.
            deleted: Whether the secret has been deleted from current version.

        Returns:
            A Finding object for the historical secret.
        """
        # Mask the secret in the code snippet
        masked_snippet = self._mask_secret(line_content, matched_text)

        status = "deleted from current files but" if deleted else "still"
        rule_name = rule["name"]
        default_desc = f"Detected {rule_name} in source code."
        description = (
            f"Historical: {rule.get('description', default_desc)} "
            f"This secret was {status} present in git history (commit {commit_hash}). "
            f"Even deleted secrets remain exploitable if an attacker gains access to the repository."
        )

        fix_recommendation = rule.get("fix", "Remove hardcoded secrets and use environment variables.")
        if deleted:
            fix_recommendation += (
                " Since this secret is in git history, you should also: "
                "1) Rotate/revoke the exposed credential immediately, "
                "2) Consider using git-filter-repo or BFG Repo-Cleaner to remove it from history, "
                "3) Force push the cleaned history (coordinate with your team)."
            )

        title = f"Historical: {rule_name}"
        if deleted:
            title += " (deleted but in git history)"

        return self._create_finding(
            type=f"hardcoded_secret.historical.{rule['id']}",
            title=title,
            description=description,
            severity=rule.get("severity", Severity.HIGH),  # Same severity - still exploitable
            confidence=rule.get("confidence", Confidence.MEDIUM),
            file_path=Path(file_path),
            fix_recommendation=fix_recommendation,
            line_number=line_number,
            code_snippet=masked_snippet,
            cwe_id=self.CWE_ID,
            owasp_category=self.OWASP_CATEGORY,
            auto_fixable=False,
            metadata={
                "scanner": self.name,
                "rule_id": rule["id"],
                "secret_type": rule_name,
                "masked_match": self._mask_secret(matched_text, matched_text),
                "commit": commit_hash,
                "deleted": deleted,
                "historical": True,
            },
        )

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
