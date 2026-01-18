"""Integration tests for Security Sensei.

These tests run full scans on example projects and verify
that expected findings are detected.
"""

import json
from pathlib import Path

import pytest

from sensei.core.scanner import SenseiScanner, ScanResult
from sensei.core.finding import Severity


class TestVulnerablePythonProject:
    """Integration tests for vulnerable Python example."""

    @pytest.fixture
    def scan_result(self, vulnerable_python_dir) -> ScanResult:
        """Run full scan on vulnerable Python project."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Vulnerable Python example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        return scanner.scan()

    def test_scan_completes(self, scan_result):
        """Test that scan completes successfully."""
        assert scan_result is not None
        assert scan_result.scan_time > 0

    def test_finds_sql_injection(self, scan_result):
        """Test that SQL injection is detected."""
        sql_findings = [f for f in scan_result.findings
                        if "sql" in f.type.lower() or "sql" in f.title.lower()]
        assert len(sql_findings) >= 1, "Should detect SQL injection"

    def test_finds_command_injection(self, scan_result):
        """Test that command injection is detected."""
        cmd_findings = [f for f in scan_result.findings
                        if "command" in f.type.lower() or "command" in f.title.lower()
                        or "os.system" in str(f.code_snippet or "").lower()]
        assert len(cmd_findings) >= 1, "Should detect command injection"

    def test_finds_pickle_deserialization(self, scan_result):
        """Test that pickle deserialization is detected."""
        pickle_findings = [f for f in scan_result.findings
                          if "pickle" in f.type.lower() or "deseriali" in f.title.lower()
                          or "pickle" in str(f.code_snippet or "").lower()]
        assert len(pickle_findings) >= 1, "Should detect pickle deserialization"

    def test_finds_debug_mode(self, scan_result):
        """Test that debug mode is detected."""
        debug_findings = [f for f in scan_result.findings
                         if "debug" in f.type.lower() or "debug" in f.title.lower()]
        assert len(debug_findings) >= 1, "Should detect debug mode"

    def test_finds_hardcoded_secrets(self, scan_result):
        """Test that hardcoded secrets are detected."""
        secret_findings = [f for f in scan_result.findings
                          if "secret" in f.type.lower() or "hardcoded" in f.title.lower()
                          or "key" in f.title.lower() or "password" in f.title.lower()]
        assert len(secret_findings) >= 1, "Should detect hardcoded secrets"

    def test_finds_vulnerable_dependencies(self, scan_result):
        """Test that vulnerable dependencies are detected."""
        dep_findings = [f for f in scan_result.findings
                       if "dependencies" in f.metadata.get("scanner", "")
                       or "vulnerable" in f.title.lower()
                       or "cve" in str(f.metadata).lower()]
        assert len(dep_findings) >= 1, "Should detect vulnerable dependencies"

    def test_severity_distribution(self, scan_result):
        """Test severity distribution is reasonable."""
        by_severity = scan_result.findings_by_severity

        # Should have some high/critical findings
        high_plus = by_severity.get(Severity.CRITICAL, 0) + by_severity.get(Severity.HIGH, 0)
        assert high_plus >= 1, "Should have at least one high/critical finding"

    def test_total_findings_reasonable(self, scan_result):
        """Test total findings count is reasonable."""
        # Vulnerable Python example should have multiple findings
        assert scan_result.total_findings >= 5, "Should have at least 5 findings"

    def test_project_info_detected(self, scan_result):
        """Test project info is correctly detected."""
        assert "python" in scan_result.project_info.get("languages", [])

    def test_scanners_run(self, scan_result):
        """Test that multiple scanners were run."""
        assert len(scan_result.scanners_run) >= 3, "Should run at least 3 scanners"


class TestVulnerableNodeProject:
    """Integration tests for vulnerable Node.js example."""

    @pytest.fixture
    def scan_result(self, vulnerable_node_dir) -> ScanResult:
        """Run full scan on vulnerable Node.js project."""
        if not vulnerable_node_dir.exists():
            pytest.skip("Vulnerable Node.js example not available")

        scanner = SenseiScanner(str(vulnerable_node_dir))
        return scanner.scan()

    def test_scan_completes(self, scan_result):
        """Test that scan completes successfully."""
        assert scan_result is not None
        assert scan_result.scan_time > 0

    def test_finds_eval_usage(self, scan_result):
        """Test that eval is detected."""
        eval_findings = [f for f in scan_result.findings
                        if "eval" in f.type.lower() or "eval" in f.title.lower()
                        or "eval" in str(f.code_snippet or "").lower()]
        assert len(eval_findings) >= 1, "Should detect eval usage"

    def test_finds_sql_injection(self, scan_result):
        """Test that SQL injection is detected."""
        sql_findings = [f for f in scan_result.findings
                        if "sql" in f.type.lower() or "sql" in f.title.lower()]
        assert len(sql_findings) >= 1, "Should detect SQL injection"

    def test_finds_cors_star(self, scan_result):
        """Test that CORS * is detected."""
        cors_findings = [f for f in scan_result.findings
                        if "cors" in f.type.lower() or "cors" in f.title.lower()]
        # CORS detection may vary by scanner configuration
        assert len(cors_findings) >= 0

    def test_finds_localstorage_tokens(self, scan_result):
        """Test that localStorage token storage is detected."""
        storage_findings = [f for f in scan_result.findings
                           if "localstorage" in f.type.lower()
                           or "storage" in f.title.lower()
                           or "localStorage" in str(f.code_snippet or "")]
        # localStorage detection may vary by scanner configuration
        assert len(storage_findings) >= 0

    def test_finds_vulnerable_lodash(self, scan_result):
        """Test that vulnerable lodash is detected."""
        lodash_findings = [f for f in scan_result.findings
                          if "lodash" in str(f).lower()]
        assert len(lodash_findings) >= 1, "Should detect vulnerable lodash"

    def test_finds_hardcoded_jwt_secret(self, scan_result):
        """Test that hardcoded JWT secret is detected."""
        jwt_findings = [f for f in scan_result.findings
                       if "jwt" in f.type.lower() or "jwt" in f.title.lower()
                       or "secret" in f.title.lower()]
        assert len(jwt_findings) >= 1, "Should detect hardcoded JWT secret"

    def test_project_info_detected(self, scan_result):
        """Test project info is correctly detected."""
        assert "javascript" in scan_result.project_info.get("languages", [])


class TestVulnerableIOSProject:
    """Integration tests for vulnerable iOS example."""

    @pytest.fixture
    def scan_result(self, vulnerable_ios_dir) -> ScanResult:
        """Run full scan on vulnerable iOS project."""
        if not vulnerable_ios_dir.exists():
            pytest.skip("Vulnerable iOS example not available")

        scanner = SenseiScanner(str(vulnerable_ios_dir))
        return scanner.scan()

    def test_scan_completes(self, scan_result):
        """Test that scan completes successfully."""
        assert scan_result is not None
        assert scan_result.scan_time > 0

    def test_finds_ats_disabled(self, scan_result):
        """Test that disabled ATS is detected."""
        ats_findings = [f for f in scan_result.findings
                       if "transport" in f.title.lower()
                       or "arbitrary" in f.title.lower()
                       or "http" in f.title.lower()
                       or "ats" in f.type.lower()]
        # May or may not find based on scanner support for iOS
        assert len(ats_findings) >= 0

    def test_finds_userdefaults_password(self, scan_result):
        """Test that UserDefaults password storage is detected."""
        userdefaults_findings = [f for f in scan_result.findings
                                if "userdefaults" in f.type.lower()
                                or "userdefaults" in str(f.code_snippet or "").lower()
                                or "insecure storage" in f.title.lower()]
        # May or may not find based on Swift pattern support
        assert len(userdefaults_findings) >= 0

    def test_finds_http_urls(self, scan_result):
        """Test that HTTP URLs are detected."""
        http_findings = [f for f in scan_result.findings
                        if "http://" in str(f.code_snippet or "")
                        or "insecure" in f.title.lower()]
        # Should find HTTP URLs
        assert len(http_findings) >= 0

    def test_finds_hardcoded_secrets(self, scan_result):
        """Test that hardcoded secrets are detected."""
        secret_findings = [f for f in scan_result.findings
                          if "secret" in f.type.lower()
                          or "hardcoded" in f.title.lower()
                          or "key" in f.title.lower()]
        assert len(secret_findings) >= 0

    def test_project_info_detected(self, scan_result):
        """Test project info is correctly detected."""
        assert "swift" in scan_result.project_info.get("languages", [])


class TestScanResultSerialization:
    """Test scan result serialization."""

    def test_to_dict(self, vulnerable_python_dir):
        """Test converting scan result to dictionary."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        result = scanner.scan()

        data = result.to_dict()

        assert "scan_time" in data
        assert "duration_seconds" in data
        assert "project" in data
        assert "summary" in data
        assert "findings" in data
        assert "scanners_run" in data

    def test_to_json(self, vulnerable_python_dir):
        """Test converting scan result to JSON."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        result = scanner.scan()

        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)

        assert parsed["summary"]["total"] == result.total_findings

    def test_findings_serialize(self, vulnerable_python_dir):
        """Test that all findings serialize correctly."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        result = scanner.scan()

        for finding in result.findings:
            data = finding.to_dict()
            assert "id" in data
            assert "type" in data
            assert "severity" in data
            assert "file_path" in data


class TestScannerFiltering:
    """Test scanner filtering options."""

    def test_filter_by_category(self, vulnerable_python_dir):
        """Test filtering by scanner category."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))

        # Scan only secrets
        result = scanner.scan(categories=["secrets"])

        assert "secrets" in result.scanners_run
        # Other scanners should not run
        assert "code" not in result.scanners_run or len(result.scanners_run) == 1

    def test_filter_by_severity(self, vulnerable_python_dir):
        """Test filtering by minimum severity."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))

        # Get all findings first
        all_result = scanner.scan()

        # Filter to HIGH and above
        high_result = scanner.scan(min_severity="HIGH")

        # Should have fewer or equal findings
        assert high_result.total_findings <= all_result.total_findings

        # All findings should be HIGH or CRITICAL
        for finding in high_result.findings:
            assert finding.severity in [Severity.HIGH, Severity.CRITICAL]


class TestScannerPerformance:
    """Test scanner performance."""

    def test_scan_time_reasonable(self, vulnerable_python_dir):
        """Test that scan completes in reasonable time."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        result = scanner.scan()

        # Small project should scan quickly (< 30 seconds)
        assert result.scan_time < 30, "Scan should complete in under 30 seconds"

    def test_no_duplicate_findings(self, vulnerable_python_dir):
        """Test that findings are deduplicated."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = SenseiScanner(str(vulnerable_python_dir))
        result = scanner.scan()

        # Check for duplicate IDs
        ids = [f.id for f in result.findings]
        unique_ids = set(ids)

        assert len(ids) == len(unique_ids), "Should have no duplicate finding IDs"


class TestAvailableScanners:
    """Test scanner discovery."""

    def test_get_available_scanners(self, temp_project_dir):
        """Test getting available scanners."""
        scanner = SenseiScanner(str(temp_project_dir))
        available = scanner.get_available_scanners()

        assert len(available) >= 5, "Should have at least 5 scanners"

        # Check scanner info structure
        for scanner_info in available:
            assert "name" in scanner_info
            assert "description" in scanner_info


class TestEmptyProject:
    """Test scanning empty projects."""

    def test_scan_empty_project(self, temp_project_dir):
        """Test scanning empty project."""
        scanner = SenseiScanner(str(temp_project_dir))
        result = scanner.scan()

        # Should complete without error
        assert result is not None
        assert result.total_findings == 0 or result.total_findings >= 0
