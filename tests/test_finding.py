"""Tests for Finding dataclass."""

import json
import pytest

from sensei.core.finding import Finding, Severity, Confidence


class TestSeverity:
    """Tests for Severity class."""

    def test_severity_constants(self):
        """Test severity level constants exist."""
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.LOW == "LOW"
        assert Severity.INFO == "INFO"

    def test_severity_compare_equal(self):
        """Test comparing equal severities."""
        assert Severity.compare(Severity.HIGH, Severity.HIGH) == 0

    def test_severity_compare_greater(self):
        """Test comparing higher severity."""
        assert Severity.compare(Severity.CRITICAL, Severity.HIGH) > 0
        assert Severity.compare(Severity.HIGH, Severity.MEDIUM) > 0
        assert Severity.compare(Severity.MEDIUM, Severity.LOW) > 0
        assert Severity.compare(Severity.LOW, Severity.INFO) > 0

    def test_severity_compare_less(self):
        """Test comparing lower severity."""
        assert Severity.compare(Severity.INFO, Severity.LOW) < 0
        assert Severity.compare(Severity.LOW, Severity.MEDIUM) < 0

    def test_severity_compare_unknown(self):
        """Test comparing unknown severity defaults to 0."""
        assert Severity.compare("UNKNOWN", Severity.INFO) == 0


class TestConfidence:
    """Tests for Confidence class."""

    def test_confidence_constants(self):
        """Test confidence level constants exist."""
        assert Confidence.HIGH == "HIGH"
        assert Confidence.MEDIUM == "MEDIUM"
        assert Confidence.LOW == "LOW"


class TestFinding:
    """Tests for Finding dataclass."""

    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding for tests."""
        return Finding(
            type="hardcoded_secret",
            title="Hardcoded API Key",
            description="API key found in source code.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="config.py",
            line_number=10,
            code_snippet="API_KEY = 'FAKE_KEY_xxx'",
            cwe_id="CWE-798",
            owasp_category="A07:2021",
            fix_recommendation="Use environment variables.",
            auto_fixable=False,
            metadata={"scanner": "secrets"},
        )

    def test_finding_creation(self, sample_finding):
        """Test creating a Finding instance."""
        assert sample_finding.type == "hardcoded_secret"
        assert sample_finding.title == "Hardcoded API Key"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.file_path == "config.py"
        assert sample_finding.line_number == 10

    def test_finding_minimal_creation(self):
        """Test creating a Finding with minimal required fields."""
        finding = Finding(
            type="test",
            title="Test Finding",
            description="A test finding.",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            fix_recommendation="Fix it.",
        )
        assert finding.line_number is None
        assert finding.code_snippet is None
        assert finding.cwe_id is None
        assert finding.auto_fixable is False
        assert finding.metadata == {}

    def test_finding_id_generation(self, sample_finding):
        """Test that finding ID is generated."""
        assert sample_finding.id is not None
        assert len(sample_finding.id) == 16  # First 16 chars of SHA256

    def test_finding_id_consistency(self):
        """Test that same input produces same ID."""
        finding1 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        finding2 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        assert finding1.id == finding2.id

    def test_finding_id_different_for_different_files(self):
        """Test that different files produce different IDs."""
        finding1 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="file1.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        finding2 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="file2.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        assert finding1.id != finding2.id

    def test_finding_id_different_for_different_lines(self):
        """Test that different line numbers produce different IDs."""
        finding1 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        finding2 = Finding(
            type="test",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=10,
            fix_recommendation="Fix.",
        )
        assert finding1.id != finding2.id

    def test_finding_id_different_for_different_types(self):
        """Test that different types produce different IDs."""
        finding1 = Finding(
            type="sql_injection",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        finding2 = Finding(
            type="xss",
            title="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            file_path="test.py",
            line_number=5,
            fix_recommendation="Fix.",
        )
        assert finding1.id != finding2.id

    def test_finding_to_dict(self, sample_finding):
        """Test converting Finding to dictionary."""
        result = sample_finding.to_dict()

        assert isinstance(result, dict)
        assert result["id"] == sample_finding.id
        assert result["type"] == "hardcoded_secret"
        assert result["title"] == "Hardcoded API Key"
        assert result["description"] == "API key found in source code."
        assert result["severity"] == "HIGH"
        assert result["confidence"] == "HIGH"
        assert result["file_path"] == "config.py"
        assert result["line_number"] == 10
        assert result["code_snippet"] == "API_KEY = 'FAKE_KEY_xxx'"
        assert result["cwe_id"] == "CWE-798"
        assert result["owasp_category"] == "A07:2021"
        assert result["fix_recommendation"] == "Use environment variables."
        assert result["auto_fixable"] is False
        assert result["metadata"] == {"scanner": "secrets"}

    def test_finding_to_json(self, sample_finding):
        """Test that Finding can be serialized to JSON."""
        result = sample_finding.to_dict()
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

        # Parse back
        parsed = json.loads(json_str)
        assert parsed["type"] == "hardcoded_secret"
        assert parsed["severity"] == "HIGH"

    def test_finding_from_dict(self, sample_finding):
        """Test creating Finding from dictionary."""
        data = sample_finding.to_dict()
        restored = Finding.from_dict(data)

        assert restored.id == sample_finding.id
        assert restored.type == sample_finding.type
        assert restored.title == sample_finding.title
        assert restored.severity == sample_finding.severity
        assert restored.file_path == sample_finding.file_path
        assert restored.line_number == sample_finding.line_number
        assert restored.metadata == sample_finding.metadata

    def test_finding_roundtrip(self, sample_finding):
        """Test serialization/deserialization roundtrip."""
        data = sample_finding.to_dict()
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        restored = Finding.from_dict(parsed)

        assert restored.id == sample_finding.id
        assert restored.type == sample_finding.type
        assert restored.severity == sample_finding.severity

    def test_finding_from_dict_minimal(self):
        """Test creating Finding from dict with minimal fields."""
        data = {
            "type": "test",
            "title": "Test",
            "description": "Test desc",
            "severity": "LOW",
            "confidence": "LOW",
            "file_path": "test.py",
            "fix_recommendation": "Fix it",
        }
        finding = Finding.from_dict(data)

        assert finding.type == "test"
        assert finding.line_number is None
        assert finding.auto_fixable is False
        assert finding.metadata == {}
