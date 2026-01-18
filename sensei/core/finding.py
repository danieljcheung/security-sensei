"""Finding dataclass for security vulnerabilities."""

from dataclasses import dataclass, field
from typing import Optional
import hashlib


class Severity:
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    _order = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

    @classmethod
    def compare(cls, a: str, b: str) -> int:
        """Compare two severity levels. Returns positive if a > b."""
        return cls._order.get(a, 0) - cls._order.get(b, 0)


class Confidence:
    """Confidence levels for findings."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Represents a security finding."""
    type: str  # e.g., "hardcoded_secret", "sql_injection"
    title: str
    description: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: str  # HIGH/MEDIUM/LOW
    file_path: str
    fix_recommendation: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None  # e.g., "CWE-798"
    owasp_category: Optional[str] = None  # e.g., "A01:2021"
    auto_fixable: bool = False
    metadata: dict = field(default_factory=dict)
    _id: Optional[str] = field(default=None, repr=False)

    @property
    def id(self) -> str:
        """Get the unique identifier for this finding."""
        if self._id is None:
            self._id = self._generate_id()
        return self._id

    def _generate_id(self) -> str:
        """Generate a unique hash ID based on file, line, and type."""
        components = [
            self.file_path,
            str(self.line_number) if self.line_number else "",
            self.type,
        ]
        hash_input = ":".join(components).encode("utf-8")
        return hashlib.sha256(hash_input).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "fix_recommendation": self.fix_recommendation,
            "auto_fixable": self.auto_fixable,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create a Finding from a dictionary."""
        finding = cls(
            type=data["type"],
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            confidence=data["confidence"],
            file_path=data["file_path"],
            fix_recommendation=data["fix_recommendation"],
            line_number=data.get("line_number"),
            code_snippet=data.get("code_snippet"),
            cwe_id=data.get("cwe_id"),
            owasp_category=data.get("owasp_category"),
            auto_fixable=data.get("auto_fixable", False),
            metadata=data.get("metadata", {}),
        )
        finding._id = data.get("id")
        return finding
