"""Auto-fix functionality for Security Sensei.

Provides safe, reversible automatic fixes for common security issues.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from sensei.core.finding import Finding


@dataclass
class ProposedFix:
    """Represents a proposed fix that can be applied."""

    fix_type: str
    description: str
    file_path: str
    preview: str
    finding_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "fix_type": self.fix_type,
            "description": self.description,
            "file_path": self.file_path,
            "preview": self.preview,
            "finding_ids": self.finding_ids,
        }


@dataclass
class AppliedFix:
    """Represents a fix that has been applied."""

    fix_type: str
    description: str
    file_path: str
    changes_made: str
    backup_path: Optional[str] = None
    timestamp: Optional[str] = None
    finding_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "fix_type": self.fix_type,
            "description": self.description,
            "file_path": self.file_path,
            "changes_made": self.changes_made,
            "backup_path": self.backup_path,
            "timestamp": self.timestamp,
        }


class BaseFixer(ABC):
    """Base class for auto-fixers."""

    name: str = "base"
    description: str = "Base fixer"

    def __init__(self, project_path: Path):
        self.project_path = project_path

    @abstractmethod
    def analyze(self, findings: List[Finding]) -> List[ProposedFix]:
        """Analyze findings and return proposed fixes."""
        pass

    @abstractmethod
    def apply(self, proposed_fix: ProposedFix) -> AppliedFix:
        """Apply a proposed fix and return the applied fix."""
        pass

    def _create_backup(self, file_path: Path) -> Optional[str]:
        """Create a backup of a file before modifying it."""
        if not file_path.exists():
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = file_path.with_suffix(f"{file_path.suffix}.{timestamp}.bak")
        backup_path.write_text(file_path.read_text())
        return str(backup_path)


class GitignoreAutoFix(BaseFixer):
    """Auto-fixer for .gitignore issues.

    Safe operations:
    - Add missing .env pattern
    - Add missing *.pem, *.key patterns
    - Never removes lines, only appends
    """

    name = "gitignore"
    description = "Add missing security patterns to .gitignore"

    def analyze(self, findings: List[Finding]) -> List[ProposedFix]:
        """Analyze findings for gitignore issues."""
        proposed_fixes = []

        # Get current .gitignore content
        gitignore_path = self.project_path / ".gitignore"
        current_content = ""
        if gitignore_path.exists():
            current_content = gitignore_path.read_text()

        current_lines = set(line.strip() for line in current_content.splitlines())

        # Find patterns to add based on findings
        patterns_to_add = []
        related_finding_ids = []

        for finding in findings:
            file_path = finding.file_path.lower()

            # Check for .env files
            if ".env" in file_path and "example" not in file_path:
                if ".env" not in current_lines:
                    if ".env" not in patterns_to_add:
                        patterns_to_add.append(".env")
                    related_finding_ids.append(finding.id)
                if ".env.*" not in current_lines:
                    if ".env.*" not in patterns_to_add:
                        patterns_to_add.append(".env.*")
                if "!.env.example" not in current_lines:
                    if "!.env.example" not in patterns_to_add:
                        patterns_to_add.append("!.env.example")

            # Check for key/certificate files
            for ext in [".pem", ".key", ".p12", ".pfx", ".jks"]:
                if file_path.endswith(ext):
                    pattern = f"*{ext}"
                    if pattern not in current_lines and pattern not in patterns_to_add:
                        patterns_to_add.append(pattern)
                        related_finding_ids.append(finding.id)

            # Check for secret/credential files
            basename = Path(finding.file_path).name.lower()
            if any(x in basename for x in ["secret", "credential", "private"]):
                if basename not in current_lines and basename not in patterns_to_add:
                    patterns_to_add.append(Path(finding.file_path).name)
                    related_finding_ids.append(finding.id)

        if patterns_to_add:
            preview = self._generate_preview(patterns_to_add)
            proposed_fixes.append(
                ProposedFix(
                    fix_type="gitignore_update",
                    description=f"Add {len(patterns_to_add)} security pattern(s) to .gitignore",
                    file_path=str(gitignore_path),
                    preview=preview,
                    finding_ids=list(set(related_finding_ids)),
                    metadata={"patterns_to_add": patterns_to_add},
                )
            )

        return proposed_fixes

    def _generate_preview(self, patterns_to_add: List[str]) -> str:
        """Generate a preview of the changes."""
        lines = ["Lines to be added to .gitignore:", ""]
        lines.append("# Security patterns (auto-added by Security Sensei)")
        for pattern in patterns_to_add:
            lines.append(f"  + {pattern}")
        return "\n".join(lines)

    def apply(self, proposed_fix: ProposedFix) -> AppliedFix:
        """Apply the gitignore fix."""
        gitignore_path = Path(proposed_fix.file_path)
        patterns_to_add = proposed_fix.metadata.get("patterns_to_add", [])

        # Create backup if file exists
        backup_path = self._create_backup(gitignore_path)

        # Read current content
        current_content = ""
        if gitignore_path.exists():
            current_content = gitignore_path.read_text()

        # Build new content (append only)
        new_lines = []
        if current_content.strip():
            new_lines.append(current_content.rstrip())
            new_lines.append("")

        new_lines.append("# Security patterns (auto-added by Security Sensei)")
        new_lines.extend(patterns_to_add)
        new_lines.append("")

        # Write new content
        gitignore_path.write_text("\n".join(new_lines))

        return AppliedFix(
            fix_type="gitignore_update",
            description=f"Added {len(patterns_to_add)} pattern(s) to .gitignore",
            file_path=str(gitignore_path),
            changes_made=f"Added: {', '.join(patterns_to_add)}",
            backup_path=backup_path,
            finding_ids=proposed_fix.finding_ids,
        )


class EnvExampleAutoFix(BaseFixer):
    """Auto-fixer for creating .env.example from .env.

    Safe operations:
    - Create .env.example if .env exists but .env.example doesn't
    - Copy keys with placeholder values
    - Preserve comments
    """

    name = "env_example"
    description = "Create .env.example with placeholder values"

    # Patterns for replacing sensitive values (key pattern, replacement)
    VALUE_REPLACEMENTS = [
        (r"(?i)(api[_-]?key)", "your_api_key_here"),
        (r"(?i)(secret[_-]?key)", "your_secret_key_here"),
        (r"(?i)(jwt[_-]?secret)", "your_jwt_secret_here"),
        (r"(?i)(auth[_-]?token)", "your_auth_token_here"),
        (r"(?i)(password|passwd|pass)", "your_password_here"),
        (r"(?i)(aws[_-]?access[_-]?key)", "your_aws_access_key"),
        (r"(?i)(aws[_-]?secret)", "your_aws_secret_key"),
        (r"(?i)(database[_-]?url)", "your_database_url_here"),
        (r"(?i)(mongo)", "your_mongodb_uri_here"),
        (r"(?i)(redis)", "your_redis_url_here"),
        (r"(?i)(stripe)", "your_stripe_key_here"),
        (r"(?i)(sendgrid)", "your_sendgrid_key_here"),
        (r"(?i)(twilio)", "your_twilio_token_here"),
        (r"(?i)(github[_-]?token)", "your_github_token_here"),
        (r"(?i)(slack)", "your_slack_token_here"),
        (r"(?i)(encryption[_-]?key)", "your_encryption_key_here"),
        (r"(?i)(private[_-]?key)", "your_private_key_here"),
        (r"(?i)(secret)", "your_secret_here"),
        (r"(?i)(token)", "your_token_here"),
    ]

    def analyze(self, findings: List[Finding]) -> List[ProposedFix]:
        """Analyze for .env.example creation opportunity."""
        proposed_fixes = []

        env_path = self.project_path / ".env"
        env_example_path = self.project_path / ".env.example"

        # Only propose if .env exists but .env.example doesn't
        if not env_path.exists() or env_example_path.exists():
            return proposed_fixes

        # Check for .env-related findings
        env_findings = [
            f for f in findings
            if ".env" in f.file_path.lower() and "example" not in f.file_path.lower()
        ]

        # Generate preview content
        example_content = self._generate_example_content(env_path)

        if example_content:
            proposed_fixes.append(
                ProposedFix(
                    fix_type="env_example_create",
                    description="Create .env.example with placeholder values",
                    file_path=str(env_example_path),
                    preview=example_content,
                    finding_ids=[f.id for f in env_findings],
                    metadata={"source_file": str(env_path)},
                )
            )

        return proposed_fixes

    def _generate_example_content(self, env_path: Path) -> str:
        """Generate .env.example content from .env file."""
        try:
            content = env_path.read_text()
        except (IOError, UnicodeDecodeError):
            return ""

        lines = [
            "# Environment variables template",
            "# Copy this file to .env and fill in your values",
            "# Generated by Security Sensei",
            "",
        ]

        for line in content.splitlines():
            stripped = line.strip()

            # Preserve comments and empty lines
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue

            # Skip lines without =
            if "=" not in line:
                lines.append(line)
                continue

            # Split key and value
            key, _, value = line.partition("=")
            key = key.strip()

            # Find appropriate placeholder
            placeholder = "your_value_here"
            for pattern, replacement in self.VALUE_REPLACEMENTS:
                if re.search(pattern, key):
                    placeholder = replacement
                    break

            lines.append(f"{key}={placeholder}")

        return "\n".join(lines)

    def apply(self, proposed_fix: ProposedFix) -> AppliedFix:
        """Apply the .env.example creation."""
        env_example_path = Path(proposed_fix.file_path)

        # Write the example file
        env_example_path.write_text(proposed_fix.preview)

        return AppliedFix(
            fix_type="env_example_create",
            description="Created .env.example with placeholder values",
            file_path=str(env_example_path),
            changes_made="Created new file",
            backup_path=None,
            finding_ids=proposed_fix.finding_ids,
        )


class AutoFixer:
    """Main auto-fixer orchestrator."""

    FIXER_CLASSES: List[Type[BaseFixer]] = [
        GitignoreAutoFix,
        EnvExampleAutoFix,
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self.fixers = [cls(self.project_path) for cls in self.FIXER_CLASSES]

    def analyze(self, findings: List[Finding]) -> List[ProposedFix]:
        """Analyze findings and return all proposed fixes."""
        all_proposed = []

        for fixer in self.fixers:
            try:
                proposed = fixer.analyze(findings)
                all_proposed.extend(proposed)
            except Exception:
                pass  # Continue with other fixers

        return all_proposed

    def apply(self, proposed_fixes: List[ProposedFix]) -> List[AppliedFix]:
        """Apply proposed fixes."""
        applied = []

        for proposed in proposed_fixes:
            fixer = self._get_fixer_for_fix(proposed)
            if not fixer:
                continue

            try:
                result = fixer.apply(proposed)
                applied.append(result)
            except Exception:
                pass  # Continue with other fixes

        return applied

    def _get_fixer_for_fix(self, proposed: ProposedFix) -> Optional[BaseFixer]:
        """Get the appropriate fixer for a proposed fix."""
        fix_type_map = {
            "gitignore_update": GitignoreAutoFix,
            "env_example_create": EnvExampleAutoFix,
        }

        fixer_class = fix_type_map.get(proposed.fix_type)
        if fixer_class:
            return fixer_class(self.project_path)
        return None
