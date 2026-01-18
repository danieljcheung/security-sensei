"""Dependency scanner for detecting vulnerable and malicious packages."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class DependencyScanner(BaseScanner):
    """Scanner for detecting vulnerable dependencies and typosquatting."""

    name = "dependencies"
    description = "Detects vulnerable dependencies and potential typosquatting"
    applies_to = []  # Applies to all projects with package managers

    # CWE and OWASP mappings
    CWE_VULNERABLE_DEP = "CWE-1395"
    CWE_TYPOSQUATTING = "CWE-829"
    OWASP_CATEGORY = "A06:2021"

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)
        self._npm_vulns = self._load_vuln_db("npm_vulns.json")
        self._pypi_vulns = self._load_vuln_db("pypi_vulns.json")
        self._popular_packages = self._load_popular_packages()

    def _load_vuln_db(self, filename: str) -> List[Dict]:
        """Load vulnerability database from JSON file."""
        rules_path = Path(__file__).parent.parent / "rules" / filename
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("vulnerabilities", [])
        except (IOError, json.JSONDecodeError):
            return []

    def _load_popular_packages(self) -> Dict[str, Set[str]]:
        """Load popular packages for typosquatting detection."""
        rules_path = Path(__file__).parent.parent / "rules" / "popular_packages.json"
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "npm": set(data.get("npm", [])),
                    "pypi": set(data.get("pypi", [])),
                }
        except (IOError, json.JSONDecodeError):
            return {"npm": set(), "pypi": set()}

    def scan(self) -> List[Finding]:
        """Scan for vulnerable dependencies."""
        findings: List[Finding] = []

        # Scan npm packages
        findings.extend(self._scan_npm())

        # Scan pip packages
        findings.extend(self._scan_pip())

        return findings

    # =========================================================================
    # NPM Scanning
    # =========================================================================

    def _scan_npm(self) -> List[Finding]:
        """Scan npm packages for vulnerabilities."""
        findings: List[Finding] = []

        # Check package.json
        package_json = self.project_path / "package.json"
        if package_json.exists():
            findings.extend(self._scan_package_json(package_json))

        # Check package-lock.json for more accurate versions
        package_lock = self.project_path / "package-lock.json"
        if package_lock.exists():
            findings.extend(self._scan_package_lock(package_lock))

        return findings

    def _scan_package_json(self, file_path: Path) -> List[Finding]:
        """Scan package.json for dependencies."""
        findings: List[Finding] = []
        content = self._read_file(file_path)
        if content is None:
            return findings

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        # Get all dependency sections
        dep_sections = [
            ("dependencies", data.get("dependencies", {})),
            ("devDependencies", data.get("devDependencies", {})),
            ("peerDependencies", data.get("peerDependencies", {})),
            ("optionalDependencies", data.get("optionalDependencies", {})),
        ]

        for section_name, deps in dep_sections:
            for pkg_name, version_spec in deps.items():
                # Check for vulnerabilities
                vuln_findings = self._check_npm_vulns(
                    pkg_name, version_spec, file_path, section_name
                )
                findings.extend(vuln_findings)

                # Check for typosquatting
                typo_finding = self._check_typosquatting(
                    pkg_name, "npm", file_path, section_name
                )
                if typo_finding:
                    findings.append(typo_finding)

        return findings

    def _scan_package_lock(self, file_path: Path) -> List[Finding]:
        """Scan package-lock.json for exact versions."""
        findings: List[Finding] = []
        content = self._read_file(file_path)
        if content is None:
            return findings

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        # Handle both lockfile v2/v3 (packages) and v1 (dependencies)
        packages = data.get("packages", {})
        if packages:
            # v2/v3 format
            for pkg_path, pkg_info in packages.items():
                if not pkg_path:  # Skip root package
                    continue
                # Extract package name from path (e.g., "node_modules/lodash")
                parts = pkg_path.replace("node_modules/", "").split("/")
                if parts[0].startswith("@"):
                    pkg_name = "/".join(parts[:2])  # Scoped package
                else:
                    pkg_name = parts[0]

                version = pkg_info.get("version", "")
                if version:
                    vuln_findings = self._check_npm_vulns(
                        pkg_name, version, file_path, "lockfile"
                    )
                    findings.extend(vuln_findings)
        else:
            # v1 format
            dependencies = data.get("dependencies", {})
            findings.extend(self._scan_npm_deps_recursive(dependencies, file_path))

        return findings

    def _scan_npm_deps_recursive(
        self, deps: Dict, file_path: Path, depth: int = 0
    ) -> List[Finding]:
        """Recursively scan npm dependencies from lockfile v1."""
        findings: List[Finding] = []
        if depth > 10:  # Prevent infinite recursion
            return findings

        for pkg_name, pkg_info in deps.items():
            version = pkg_info.get("version", "")
            if version:
                vuln_findings = self._check_npm_vulns(
                    pkg_name, version, file_path, "lockfile"
                )
                findings.extend(vuln_findings)

            # Check nested dependencies
            nested = pkg_info.get("dependencies", {})
            if nested:
                findings.extend(
                    self._scan_npm_deps_recursive(nested, file_path, depth + 1)
                )

        return findings

    def _check_npm_vulns(
        self, pkg_name: str, version_spec: str, file_path: Path, section: str
    ) -> List[Finding]:
        """Check npm package against vulnerability database."""
        findings: List[Finding] = []

        # Clean version string (remove ^, ~, >=, etc.)
        clean_version = self._clean_npm_version(version_spec)
        if not clean_version:
            return findings

        for vuln in self._npm_vulns:
            if vuln["package"].lower() != pkg_name.lower():
                continue

            if self._is_version_vulnerable_npm(clean_version, vuln["vulnerable_versions"]):
                findings.append(self._create_vuln_finding(
                    package=pkg_name,
                    version=clean_version,
                    vuln=vuln,
                    file_path=file_path,
                    ecosystem="npm",
                    section=section,
                ))

        return findings

    def _clean_npm_version(self, version_spec: str) -> Optional[str]:
        """Extract clean version number from npm version specifier."""
        if not version_spec:
            return None

        # Handle various version formats
        # ^1.2.3, ~1.2.3, >=1.2.3, 1.2.3, 1.2.x, *, latest, etc.
        version_spec = version_spec.strip()

        # Skip non-version specifiers
        if version_spec in ("*", "latest", "next", ""):
            return None

        # Remove range prefixes
        clean = re.sub(r"^[\^~>=<]+", "", version_spec)

        # Handle x ranges (1.2.x -> 1.2.0)
        clean = re.sub(r"\.x", ".0", clean)

        # Extract just the version part (handle "1.2.3 - 2.0.0" ranges)
        match = re.match(r"(\d+\.\d+\.\d+)", clean)
        if match:
            return match.group(1)

        # Try simpler version (1.2 -> 1.2.0)
        match = re.match(r"(\d+\.\d+)", clean)
        if match:
            return f"{match.group(1)}.0"

        return None

    def _is_version_vulnerable_npm(self, version: str, vuln_range: str) -> bool:
        """Check if version matches vulnerability range."""
        try:
            version_tuple = self._parse_semver(version)
            if not version_tuple:
                return False

            # Parse vulnerability range (e.g., "<4.17.21", ">=1.0.0 <2.0.0")
            # Handle simple < comparison
            match = re.match(r"<(\d+\.\d+\.\d+)", vuln_range)
            if match:
                vuln_version = self._parse_semver(match.group(1))
                if vuln_version:
                    return version_tuple < vuln_version

            # Handle <= comparison
            match = re.match(r"<=(\d+\.\d+\.\d+)", vuln_range)
            if match:
                vuln_version = self._parse_semver(match.group(1))
                if vuln_version:
                    return version_tuple <= vuln_version

            return False
        except (ValueError, TypeError):
            return False

    def _parse_semver(self, version: str) -> Optional[Tuple[int, int, int]]:
        """Parse semantic version string into tuple."""
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return None

    # =========================================================================
    # Pip Scanning
    # =========================================================================

    def _scan_pip(self) -> List[Finding]:
        """Scan pip packages for vulnerabilities."""
        findings: List[Finding] = []

        # Check requirements.txt files
        for req_file in self.project_path.rglob("requirements*.txt"):
            if self._is_excluded(req_file, set(self.DEFAULT_EXCLUDES)):
                continue
            findings.extend(self._scan_requirements_txt(req_file))

        # Check Pipfile.lock
        pipfile_lock = self.project_path / "Pipfile.lock"
        if pipfile_lock.exists():
            findings.extend(self._scan_pipfile_lock(pipfile_lock))

        # Check pyproject.toml
        pyproject = self.project_path / "pyproject.toml"
        if pyproject.exists():
            findings.extend(self._scan_pyproject_toml(pyproject))

        return findings

    def _scan_requirements_txt(self, file_path: Path) -> List[Finding]:
        """Scan requirements.txt for dependencies."""
        findings: List[Finding] = []
        content = self._read_file(file_path)
        if content is None:
            return findings

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package specification
            parsed = self._parse_pip_requirement(line)
            if not parsed:
                continue

            pkg_name, version, is_pinned = parsed

            # Check for unpinned dependencies
            if not is_pinned:
                findings.append(self._create_unpinned_finding(
                    package=pkg_name,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line,
                ))

            # Check for vulnerabilities
            if version:
                vuln_findings = self._check_pypi_vulns(
                    pkg_name, version, file_path, line_num
                )
                findings.extend(vuln_findings)

            # Check for typosquatting
            typo_finding = self._check_typosquatting(
                pkg_name, "pypi", file_path, f"line {line_num}"
            )
            if typo_finding:
                findings.append(typo_finding)

        return findings

    def _scan_pipfile_lock(self, file_path: Path) -> List[Finding]:
        """Scan Pipfile.lock for dependencies."""
        findings: List[Finding] = []
        content = self._read_file(file_path)
        if content is None:
            return findings

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        # Check default and develop packages
        for section in ["default", "develop"]:
            packages = data.get(section, {})
            for pkg_name, pkg_info in packages.items():
                version = pkg_info.get("version", "").lstrip("=")
                if version:
                    vuln_findings = self._check_pypi_vulns(
                        pkg_name, version, file_path, None
                    )
                    findings.extend(vuln_findings)

                # Check for typosquatting
                typo_finding = self._check_typosquatting(
                    pkg_name, "pypi", file_path, section
                )
                if typo_finding:
                    findings.append(typo_finding)

        return findings

    def _scan_pyproject_toml(self, file_path: Path) -> List[Finding]:
        """Scan pyproject.toml for dependencies."""
        findings: List[Finding] = []
        content = self._read_file(file_path)
        if content is None:
            return findings

        # Simple TOML parsing for dependencies
        # Look for [project.dependencies] or [tool.poetry.dependencies]
        in_deps_section = False
        current_section = ""

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Track section headers
            if stripped.startswith("["):
                in_deps_section = (
                    "dependencies" in stripped.lower() and
                    "dev" not in stripped.lower() and
                    "optional" not in stripped.lower()
                )
                current_section = stripped
                continue

            if not in_deps_section:
                continue

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Parse dependency line
            if "=" in stripped:
                # Poetry style: requests = "^2.28.0" or requests = {version = "^2.28"}
                parts = stripped.split("=", 1)
                pkg_name = parts[0].strip().strip('"').strip("'")

                # Extract version if present
                version_part = parts[1].strip()
                version = None
                is_pinned = False

                # Handle simple string version
                version_match = re.search(r'["\']([^"\']+)["\']', version_part)
                if version_match:
                    version_spec = version_match.group(1)
                    # Check if pinned (exact version like ==2.28.0 or 2.28.0)
                    is_pinned = not any(c in version_spec for c in "^~*><")
                    version = self._clean_pip_version(version_spec)

                # Check for vulnerabilities
                if version:
                    vuln_findings = self._check_pypi_vulns(
                        pkg_name, version, file_path, line_num
                    )
                    findings.extend(vuln_findings)

                # Check for typosquatting
                typo_finding = self._check_typosquatting(
                    pkg_name, "pypi", file_path, f"line {line_num}"
                )
                if typo_finding:
                    findings.append(typo_finding)

            elif stripped.startswith('"') or stripped.startswith("'"):
                # PEP 621 array style: "requests>=2.28.0"
                dep_spec = stripped.strip('"').strip("'").strip(",")
                parsed = self._parse_pip_requirement(dep_spec)
                if parsed:
                    pkg_name, version, is_pinned = parsed

                    if not is_pinned:
                        findings.append(self._create_unpinned_finding(
                            package=pkg_name,
                            file_path=file_path,
                            line_number=line_num,
                            line_content=stripped,
                        ))

                    if version:
                        vuln_findings = self._check_pypi_vulns(
                            pkg_name, version, file_path, line_num
                        )
                        findings.extend(vuln_findings)

                    typo_finding = self._check_typosquatting(
                        pkg_name, "pypi", file_path, f"line {line_num}"
                    )
                    if typo_finding:
                        findings.append(typo_finding)

        return findings

    def _parse_pip_requirement(self, line: str) -> Optional[Tuple[str, Optional[str], bool]]:
        """Parse a pip requirement line.

        Returns:
            Tuple of (package_name, version, is_pinned) or None if unparseable.
        """
        # Remove inline comments
        if "#" in line:
            line = line.split("#")[0].strip()

        # Remove extras (e.g., requests[security])
        line = re.sub(r"\[.*?\]", "", line)

        # Match package name and optional version specifier
        match = re.match(
            r"^([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*)\s*(.*)?$",
            line.strip()
        )
        if not match:
            return None

        pkg_name = match.group(1).lower().replace("_", "-")
        version_spec = match.group(2).strip() if match.group(2) else ""

        if not version_spec:
            return (pkg_name, None, False)

        # Check if pinned (==X.Y.Z)
        is_pinned = version_spec.startswith("==")

        # Extract version number
        version = self._clean_pip_version(version_spec)

        return (pkg_name, version, is_pinned)

    def _clean_pip_version(self, version_spec: str) -> Optional[str]:
        """Extract clean version from pip version specifier."""
        if not version_spec:
            return None

        # Remove comparison operators
        clean = re.sub(r"^[<>=!~]+", "", version_spec.strip())

        # Extract version (handle complex specs like ">=1.0,<2.0")
        clean = clean.split(",")[0].strip()

        # Match version pattern
        match = re.match(r"(\d+(?:\.\d+)*)", clean)
        if match:
            return match.group(1)

        return None

    def _check_pypi_vulns(
        self, pkg_name: str, version: str, file_path: Path, line_num: Optional[int]
    ) -> List[Finding]:
        """Check pip package against vulnerability database."""
        findings: List[Finding] = []

        # Normalize package name
        normalized_name = pkg_name.lower().replace("_", "-")

        for vuln in self._pypi_vulns:
            vuln_pkg = vuln["package"].lower().replace("_", "-")
            if vuln_pkg != normalized_name:
                continue

            if self._is_version_vulnerable_pip(version, vuln["vulnerable_versions"]):
                findings.append(self._create_vuln_finding(
                    package=pkg_name,
                    version=version,
                    vuln=vuln,
                    file_path=file_path,
                    ecosystem="pypi",
                    section=f"line {line_num}" if line_num else "lockfile",
                ))

        return findings

    def _is_version_vulnerable_pip(self, version: str, vuln_range: str) -> bool:
        """Check if pip version matches vulnerability range."""
        try:
            version_tuple = self._parse_pip_version(version)
            if not version_tuple:
                return False

            # Parse vulnerability range
            match = re.match(r"<(\d+(?:\.\d+)*)", vuln_range)
            if match:
                vuln_version = self._parse_pip_version(match.group(1))
                if vuln_version:
                    return self._compare_versions(version_tuple, vuln_version) < 0

            match = re.match(r"<=(\d+(?:\.\d+)*)", vuln_range)
            if match:
                vuln_version = self._parse_pip_version(match.group(1))
                if vuln_version:
                    return self._compare_versions(version_tuple, vuln_version) <= 0

            return False
        except (ValueError, TypeError):
            return False

    def _parse_pip_version(self, version: str) -> Optional[Tuple[int, ...]]:
        """Parse pip version string into tuple."""
        match = re.match(r"(\d+(?:\.\d+)*)", version)
        if match:
            parts = match.group(1).split(".")
            return tuple(int(p) for p in parts)
        return None

    def _compare_versions(self, v1: Tuple[int, ...], v2: Tuple[int, ...]) -> int:
        """Compare two version tuples. Returns -1, 0, or 1."""
        # Pad shorter version with zeros
        max_len = max(len(v1), len(v2))
        v1 = v1 + (0,) * (max_len - len(v1))
        v2 = v2 + (0,) * (max_len - len(v2))

        for a, b in zip(v1, v2):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0

    # =========================================================================
    # Typosquatting Detection
    # =========================================================================

    def _check_typosquatting(
        self, pkg_name: str, ecosystem: str, file_path: Path, section: str
    ) -> Optional[Finding]:
        """Check if package name might be typosquatting a popular package."""
        popular = self._popular_packages.get(ecosystem, set())
        normalized_name = pkg_name.lower().replace("_", "-")

        # Skip if the package IS a popular package
        if normalized_name in popular or pkg_name in popular:
            return None

        # Check edit distance to each popular package
        for popular_pkg in popular:
            distance = self._levenshtein_distance(normalized_name, popular_pkg.lower())
            if distance == 1:
                return self._create_typosquat_finding(
                    package=pkg_name,
                    similar_to=popular_pkg,
                    file_path=file_path,
                    ecosystem=ecosystem,
                    section=section,
                )

        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # j+1 instead of j since previous_row and current_row are one character longer
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    # =========================================================================
    # Finding Creation
    # =========================================================================

    def _create_vuln_finding(
        self,
        package: str,
        version: str,
        vuln: Dict,
        file_path: Path,
        ecosystem: str,
        section: str,
    ) -> Finding:
        """Create a finding for a vulnerable dependency."""
        cve = vuln.get("cve", "Unknown")
        severity = vuln.get("severity", "HIGH")
        fixed_version = vuln.get("fixed_version", "latest")

        return self._create_finding(
            type=f"vulnerable_dependency.{ecosystem}.{vuln['package']}",
            title=f"Vulnerable {ecosystem.upper()} Package: {package}@{version}",
            description=(
                f"{vuln.get('title', 'Known vulnerability')}. "
                f"{vuln.get('description', '')} "
                f"CVE: {cve}, CVSS: {vuln.get('cvss', 'N/A')}."
            ),
            severity=severity,
            confidence=Confidence.HIGH,
            file_path=file_path,
            fix_recommendation=(
                f"Upgrade {package} to version {fixed_version} or later. "
                f"Run: {'npm update ' + package if ecosystem == 'npm' else 'pip install --upgrade ' + package}"
            ),
            cwe_id=self.CWE_VULNERABLE_DEP,
            owasp_category=self.OWASP_CATEGORY,
            auto_fixable=True,
            metadata={
                "scanner": self.name,
                "ecosystem": ecosystem,
                "package": package,
                "installed_version": version,
                "vulnerable_versions": vuln.get("vulnerable_versions"),
                "fixed_version": fixed_version,
                "cve": cve,
                "cvss": vuln.get("cvss"),
                "section": section,
            },
        )

    def _create_unpinned_finding(
        self,
        package: str,
        file_path: Path,
        line_number: int,
        line_content: str,
    ) -> Finding:
        """Create a finding for an unpinned dependency."""
        return self._create_finding(
            type=f"unpinned_dependency.pypi.{package}",
            title=f"Unpinned Dependency: {package}",
            description=(
                f"The package '{package}' does not have a pinned version. "
                f"Unpinned dependencies can lead to unexpected behavior when new versions "
                f"are released, and make builds non-reproducible."
            ),
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            file_path=file_path,
            line_number=line_number,
            code_snippet=line_content,
            fix_recommendation=(
                f"Pin the dependency to a specific version: {package}==X.Y.Z. "
                f"Use 'pip freeze' to see currently installed versions."
            ),
            cwe_id="CWE-1104",
            owasp_category=self.OWASP_CATEGORY,
            auto_fixable=False,
            metadata={
                "scanner": self.name,
                "ecosystem": "pypi",
                "package": package,
                "issue": "unpinned",
            },
        )

    def _create_typosquat_finding(
        self,
        package: str,
        similar_to: str,
        file_path: Path,
        ecosystem: str,
        section: str,
    ) -> Finding:
        """Create a finding for potential typosquatting."""
        return self._create_finding(
            type=f"typosquatting.{ecosystem}.{package}",
            title=f"Possible Typosquatting: {package}",
            description=(
                f"The package '{package}' is very similar to the popular package '{similar_to}'. "
                f"This could be a typosquatting attack where malicious packages use names similar "
                f"to popular packages to trick developers into installing malware."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            file_path=file_path,
            fix_recommendation=(
                f"Verify that '{package}' is the intended package. "
                f"Did you mean '{similar_to}'? Check the package on "
                f"{'npmjs.com' if ecosystem == 'npm' else 'pypi.org'} to verify legitimacy."
            ),
            cwe_id=self.CWE_TYPOSQUATTING,
            owasp_category=self.OWASP_CATEGORY,
            auto_fixable=False,
            metadata={
                "scanner": self.name,
                "ecosystem": ecosystem,
                "package": package,
                "similar_to": similar_to,
                "section": section,
            },
        )
