"""Deployment scanner for detecting security issues in deployment configurations."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class DeploymentScanner(BaseScanner):
    """Scanner for detecting security issues in deployment configurations.

    Checks Dockerfiles, docker-compose.yml, CI/CD configs, and .gitignore
    for common security misconfigurations.
    """

    name = "deployment"
    description = "Detects security issues in deployment configurations"
    applies_to = []  # Applies to all projects with deployment configs

    # CWE mappings
    CWE_HARDCODED_CREDS = "CWE-798"
    CWE_IMPROPER_PRIV = "CWE-250"
    CWE_INFO_EXPOSURE = "CWE-200"
    CWE_SENSITIVE_DATA = "CWE-312"
    CWE_INCOMPLETE_CLEANUP = "CWE-459"

    # Required .gitignore patterns
    GITIGNORE_REQUIRED = {
        "high": [
            (".env", "Environment file with secrets"),
            (".env.*", "Environment files with secrets"),
            (".env.local", "Local environment file"),
            (".env.production", "Production environment file"),
        ],
        "medium": [
            ("*.pem", "Private key files"),
            ("*.key", "Private key files"),
            ("*.p12", "PKCS12 certificate files"),
            ("*.pfx", "PFX certificate files"),
            ("id_rsa", "SSH private key"),
            ("id_dsa", "SSH private key"),
            ("id_ecdsa", "SSH private key"),
            ("id_ed25519", "SSH private key"),
        ],
        "low": [
            (".docker/config.json", "Docker credentials"),
            ("**/secrets/", "Secrets directory"),
            ("**/credentials/", "Credentials directory"),
            ("*.secret", "Secret files"),
            (".npmrc", "NPM auth tokens"),
            (".pypirc", "PyPI credentials"),
        ],
    }

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)

    def scan(self) -> List[Finding]:
        """Scan for deployment security issues."""
        findings: List[Finding] = []

        # Scan Dockerfiles
        findings.extend(self._scan_dockerfiles())

        # Scan docker-compose files
        findings.extend(self._scan_docker_compose())

        # Scan CI/CD configurations
        findings.extend(self._scan_cicd_configs())

        # Check .gitignore completeness
        findings.extend(self._check_gitignore())

        return findings

    # =========================================================================
    # Dockerfile Checks
    # =========================================================================

    def _scan_dockerfiles(self) -> List[Finding]:
        """Scan Dockerfiles for security issues."""
        findings: List[Finding] = []

        # Find all Dockerfiles
        dockerfile_patterns = ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
        for pattern in dockerfile_patterns:
            for file_path in self._find_files([pattern]):
                content = self._read_file(file_path)
                if content is None:
                    continue

                findings.extend(self._check_dockerfile(file_path, content))

        return findings

    def _check_dockerfile(self, file_path: Path, content: str) -> List[Finding]:
        """Check a single Dockerfile for security issues."""
        findings: List[Finding] = []
        lines = content.splitlines()
        has_user_instruction = False
        has_dockerignore = (self.project_path / ".dockerignore").exists()
        copies_everything = False

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            upper_line = stripped.upper()

            # Check for USER instruction
            if upper_line.startswith("USER "):
                has_user_instruction = True

            # Check for secrets in ENV
            if upper_line.startswith("ENV "):
                secret_patterns = [
                    (r'ENV\s+\w*PASSWORD\w*\s*=', "PASSWORD"),
                    (r'ENV\s+\w*SECRET\w*\s*=', "SECRET"),
                    (r'ENV\s+\w*KEY\w*\s*=', "KEY"),
                    (r'ENV\s+\w*TOKEN\w*\s*=', "TOKEN"),
                    (r'ENV\s+\w*API_KEY\w*\s*=', "API_KEY"),
                    (r'ENV\s+\w*PRIVATE\w*\s*=', "PRIVATE"),
                    (r'ENV\s+\w*CREDENTIAL\w*\s*=', "CREDENTIAL"),
                ]
                for pattern, secret_type in secret_patterns:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # Check if it's using a build arg (which is safer)
                        if "${" not in stripped and "$(" not in stripped:
                            findings.append(self._create_finding(
                                type=f"deployment.dockerfile_secret.{secret_type.lower()}",
                                title=f"Secret in Dockerfile ENV ({secret_type})",
                                description=(
                                    f"Dockerfile contains ENV with {secret_type}. "
                                    f"Secrets in ENV are visible in the image history and layers."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._mask_env_value(stripped),
                                fix_recommendation=(
                                    "Use Docker secrets, --mount=type=secret, or pass secrets at runtime: "
                                    "docker run -e SECRET_KEY=$SECRET_KEY"
                                ),
                                cwe_id=self.CWE_HARDCODED_CREDS,
                                owasp_category="A07:2021",
                                metadata={"scanner": self.name, "category": "dockerfile_secret"},
                            ))
                        break

            # Check for :latest tag
            if upper_line.startswith("FROM "):
                image_ref = stripped[5:].strip().split()[0]  # Get image reference
                if image_ref.endswith(":latest") or ":" not in image_ref:
                    findings.append(self._create_finding(
                        type="deployment.dockerfile_latest_tag",
                        title="Docker Image Using :latest Tag",
                        description=(
                            "Dockerfile uses :latest or untagged image. "
                            "This can lead to non-reproducible builds and unexpected updates."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=stripped,
                        fix_recommendation=(
                            "Pin to a specific version: FROM python:3.11-slim instead of FROM python:latest"
                        ),
                        cwe_id=self.CWE_INCOMPLETE_CLEANUP,
                        owasp_category="A05:2021",
                        metadata={"scanner": self.name, "category": "dockerfile_tag"},
                    ))

            # Check for COPY . . pattern
            if re.match(r'COPY\s+\.\s+\.', stripped, re.IGNORECASE):
                copies_everything = True
                if not has_dockerignore:
                    findings.append(self._create_finding(
                        type="deployment.dockerfile_copy_all",
                        title="COPY . . Without .dockerignore",
                        description=(
                            "Dockerfile copies entire directory without .dockerignore. "
                            "This may include sensitive files like .env, .git, or credentials."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=stripped,
                        fix_recommendation=(
                            "Create a .dockerignore file to exclude sensitive files:\n"
                            ".git\n.env\n*.pem\n*.key\nnode_modules\n__pycache__"
                        ),
                        cwe_id=self.CWE_INFO_EXPOSURE,
                        owasp_category="A05:2021",
                        metadata={"scanner": self.name, "category": "dockerfile_copy"},
                    ))

            # Check for COPY .git
            if re.search(r'COPY.*\.git', stripped, re.IGNORECASE):
                findings.append(self._create_finding(
                    type="deployment.dockerfile_copy_git",
                    title=".git Directory Copied to Image",
                    description=(
                        "Dockerfile copies .git directory into the image. "
                        "This exposes entire repository history including potentially deleted secrets."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Add .git to .dockerignore to prevent copying repository history.",
                    cwe_id=self.CWE_INFO_EXPOSURE,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "dockerfile_git"},
                ))

        # Check if no USER instruction (runs as root)
        if not has_user_instruction and len(lines) > 0:
            findings.append(self._create_finding(
                type="deployment.dockerfile_no_user",
                title="Container Runs as Root",
                description=(
                    "Dockerfile has no USER instruction. The container will run as root, "
                    "which increases the impact of container escapes and vulnerabilities."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file_path=file_path,
                fix_recommendation=(
                    "Add a non-root user:\n"
                    "RUN adduser --disabled-password --gecos '' appuser\n"
                    "USER appuser"
                ),
                cwe_id=self.CWE_IMPROPER_PRIV,
                owasp_category="A05:2021",
                metadata={"scanner": self.name, "category": "dockerfile_root"},
            ))

        return findings

    # =========================================================================
    # Docker Compose Checks
    # =========================================================================

    def _scan_docker_compose(self) -> List[Finding]:
        """Scan docker-compose files for security issues."""
        findings: List[Finding] = []

        compose_patterns = [
            "docker-compose.yml", "docker-compose.yaml",
            "docker-compose.*.yml", "docker-compose.*.yaml",
            "compose.yml", "compose.yaml",
        ]

        for pattern in compose_patterns:
            for file_path in self._find_files([pattern]):
                content = self._read_file(file_path)
                if content is None:
                    continue

                findings.extend(self._check_docker_compose(file_path, content))

        return findings

    def _check_docker_compose(self, file_path: Path, content: str) -> List[Finding]:
        """Check a docker-compose file for security issues."""
        findings: List[Finding] = []
        lines = content.splitlines()

        in_environment = False
        environment_indent = 0

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Track environment section
            if stripped.startswith("environment:"):
                in_environment = True
                environment_indent = len(line) - len(line.lstrip())
                continue

            # Check if we've left the environment section
            if in_environment:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= environment_indent and stripped and not stripped.startswith("-"):
                    in_environment = False

            # Check for hardcoded passwords in environment
            if in_environment or "environment:" in line:
                secret_patterns = [
                    (r'PASSWORD\s*[:=]\s*["\']?[^$][^"\'}\s]+', "PASSWORD"),
                    (r'SECRET\s*[:=]\s*["\']?[^$][^"\'}\s]+', "SECRET"),
                    (r'API_KEY\s*[:=]\s*["\']?[^$][^"\'}\s]+', "API_KEY"),
                    (r'TOKEN\s*[:=]\s*["\']?[^$][^"\'}\s]+', "TOKEN"),
                    (r'PRIVATE_KEY\s*[:=]\s*["\']?[^$][^"\'}\s]+', "PRIVATE_KEY"),
                ]
                for pattern, secret_type in secret_patterns:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # Skip if it's referencing an env var
                        if "${" not in stripped and "$(" not in stripped:
                            findings.append(self._create_finding(
                                type=f"deployment.compose_secret.{secret_type.lower()}",
                                title=f"Hardcoded {secret_type} in docker-compose",
                                description=(
                                    f"docker-compose contains hardcoded {secret_type}. "
                                    f"Secrets should not be stored in configuration files."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._mask_compose_value(stripped),
                                fix_recommendation=(
                                    "Use environment variable references: "
                                    f"{secret_type}: ${{{{secret_type}}}}\n"
                                    "Or use Docker secrets for sensitive data."
                                ),
                                cwe_id=self.CWE_HARDCODED_CREDS,
                                owasp_category="A07:2021",
                                metadata={"scanner": self.name, "category": "compose_secret"},
                            ))
                        break

            # Check for privileged mode
            if re.search(r'privileged\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(self._create_finding(
                    type="deployment.compose_privileged",
                    title="Container Running in Privileged Mode",
                    description=(
                        "Container is configured with privileged: true. "
                        "Privileged containers have full access to the host, "
                        "effectively disabling container isolation."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation=(
                        "Remove privileged: true. If elevated permissions are needed, "
                        "use specific capabilities instead: cap_add: [SYS_PTRACE]"
                    ),
                    cwe_id=self.CWE_IMPROPER_PRIV,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "compose_privileged"},
                ))

            # Check for exposed ports (informational)
            if stripped.startswith("ports:") or (stripped.startswith("-") and ":" in stripped):
                # Check for commonly sensitive ports exposed to all interfaces
                sensitive_ports = ["3306", "5432", "27017", "6379", "11211", "9200"]
                for port in sensitive_ports:
                    if re.search(rf'["\']?0\.0\.0\.0:{port}|["\']?{port}:{port}', stripped):
                        findings.append(self._create_finding(
                            type=f"deployment.compose_exposed_port.{port}",
                            title=f"Sensitive Port {port} Exposed to All Interfaces",
                            description=(
                                f"Database/cache port {port} is exposed to all network interfaces. "
                                f"This may expose the service to unauthorized access."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=stripped,
                            fix_recommendation=(
                                "Bind to localhost only: 127.0.0.1:{port}:{port} "
                                "or remove the port mapping if not needed externally."
                            ),
                            cwe_id=self.CWE_INFO_EXPOSURE,
                            owasp_category="A05:2021",
                            metadata={"scanner": self.name, "category": "compose_port"},
                        ))

        return findings

    # =========================================================================
    # CI/CD Configuration Checks
    # =========================================================================

    def _scan_cicd_configs(self) -> List[Finding]:
        """Scan CI/CD configuration files for security issues."""
        findings: List[Finding] = []

        # GitHub Actions
        github_workflows = self.project_path / ".github" / "workflows"
        if github_workflows.exists():
            for workflow_file in github_workflows.glob("*.yml"):
                content = self._read_file(workflow_file)
                if content:
                    findings.extend(self._check_github_actions(workflow_file, content))
            for workflow_file in github_workflows.glob("*.yaml"):
                content = self._read_file(workflow_file)
                if content:
                    findings.extend(self._check_github_actions(workflow_file, content))

        # GitLab CI
        gitlab_ci = self.project_path / ".gitlab-ci.yml"
        if gitlab_ci.exists():
            content = self._read_file(gitlab_ci)
            if content:
                findings.extend(self._check_gitlab_ci(gitlab_ci, content))

        return findings

    def _check_github_actions(self, file_path: Path, content: str) -> List[Finding]:
        """Check GitHub Actions workflow for security issues."""
        findings: List[Finding] = []
        lines = content.splitlines()

        has_pr_target = False
        pr_target_line = 0

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#"):
                continue

            # Check for echoed secrets
            if re.search(r'echo\s+["\']?\$\{?\{?\s*secrets\.', stripped, re.IGNORECASE):
                findings.append(self._create_finding(
                    type="deployment.cicd_echo_secret",
                    title="Secret Echoed in CI/CD",
                    description=(
                        "Secret is being echoed in the workflow. "
                        "This will expose the secret in workflow logs."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Never echo secrets. Use secrets directly in commands without printing them.",
                    cwe_id=self.CWE_INFO_EXPOSURE,
                    owasp_category="A07:2021",
                    metadata={"scanner": self.name, "category": "cicd_secret"},
                ))

            # Check for echo $SECRET or echo ${SECRET} patterns
            if re.search(r'echo\s+["\']?\$\w+|echo\s+["\']?\$\{\w+\}', stripped):
                # Check if it's in a context that might be a secret
                context = self._get_context_lines(content, line_num, 3).lower()
                if any(s in context for s in ["secret", "password", "token", "key", "api"]):
                    findings.append(self._create_finding(
                        type="deployment.cicd_echo_env",
                        title="Potential Secret Echoed in CI/CD",
                        description=(
                            "Environment variable is echoed in a context mentioning secrets. "
                            "Verify this doesn't expose sensitive information in logs."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=stripped,
                        fix_recommendation="Review if this variable contains sensitive data.",
                        cwe_id=self.CWE_INFO_EXPOSURE,
                        owasp_category="A07:2021",
                        metadata={"scanner": self.name, "category": "cicd_echo"},
                    ))

            # Check for unpinned action versions
            if re.search(r'uses:\s*[\w-]+/[\w-]+(?:\s*$|@(?:main|master)\s*$)', stripped):
                findings.append(self._create_finding(
                    type="deployment.cicd_unpinned_action",
                    title="Unpinned GitHub Action Version",
                    description=(
                        "GitHub Action used without version pinning. "
                        "Unpinned actions can be modified by maintainers, posing a supply chain risk."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation=(
                        "Pin to a specific version or commit SHA:\n"
                        "uses: actions/checkout@v4.1.1\n"
                        "Or better: uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"
                    ),
                    cwe_id=self.CWE_INCOMPLETE_CLEANUP,
                    owasp_category="A08:2021",
                    metadata={"scanner": self.name, "category": "cicd_action"},
                ))

            # Check for pull_request_target trigger
            if "pull_request_target" in stripped:
                has_pr_target = True
                pr_target_line = line_num

        # Warn about pull_request_target
        if has_pr_target:
            findings.append(self._create_finding(
                type="deployment.cicd_pr_target",
                title="pull_request_target Trigger Used",
                description=(
                    "Workflow uses pull_request_target trigger. "
                    "This runs in the context of the base repository with access to secrets. "
                    "If the workflow checks out PR code, it can lead to code execution attacks."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file_path=file_path,
                line_number=pr_target_line,
                fix_recommendation=(
                    "If you must use pull_request_target:\n"
                    "1. Never checkout the PR's head branch\n"
                    "2. Don't pass secrets to steps that use PR code\n"
                    "3. Consider using workflow_run instead"
                ),
                cwe_id=self.CWE_IMPROPER_PRIV,
                owasp_category="A05:2021",
                metadata={"scanner": self.name, "category": "cicd_trigger"},
            ))

        return findings

    def _check_gitlab_ci(self, file_path: Path, content: str) -> List[Finding]:
        """Check GitLab CI configuration for security issues."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#"):
                continue

            # Check for echoed secrets
            if re.search(r'echo\s+["\']?\$\w*(?:SECRET|PASSWORD|TOKEN|KEY)', stripped, re.IGNORECASE):
                findings.append(self._create_finding(
                    type="deployment.gitlab_echo_secret",
                    title="Secret Echoed in GitLab CI",
                    description="Secret variable is being echoed, exposing it in CI logs.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Never echo secrets. Mark sensitive variables as 'masked' in GitLab settings.",
                    cwe_id=self.CWE_INFO_EXPOSURE,
                    owasp_category="A07:2021",
                    metadata={"scanner": self.name, "category": "cicd_secret"},
                ))

        return findings

    # =========================================================================
    # .gitignore Checks
    # =========================================================================

    def _check_gitignore(self) -> List[Finding]:
        """Check .gitignore for completeness."""
        findings: List[Finding] = []

        gitignore_path = self.project_path / ".gitignore"

        if not gitignore_path.exists():
            # Check if there are files that should be ignored
            has_env = (self.project_path / ".env").exists()
            has_key_files = any(self.project_path.glob("*.pem")) or any(self.project_path.glob("*.key"))

            if has_env or has_key_files:
                findings.append(self._create_finding(
                    type="deployment.no_gitignore",
                    title="Missing .gitignore File",
                    description=(
                        "No .gitignore file found but sensitive files exist. "
                        "This may lead to accidental commits of secrets."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=self.project_path / ".gitignore",
                    fix_recommendation="Create a .gitignore file with patterns for sensitive files.",
                    cwe_id=self.CWE_INFO_EXPOSURE,
                    owasp_category="A05:2021",
                    auto_fixable=True,
                    metadata={"scanner": self.name, "category": "gitignore"},
                ))
            return findings

        # Read .gitignore content
        gitignore_content = self._read_file(gitignore_path) or ""
        gitignore_lower = gitignore_content.lower()

        # Check for required patterns
        missing_patterns: Dict[str, List[tuple]] = {"high": [], "medium": [], "low": []}

        for severity, patterns in self.GITIGNORE_REQUIRED.items():
            for pattern, description in patterns:
                # Check if pattern or similar is in gitignore
                pattern_lower = pattern.lower()
                # Simple check - could be more sophisticated
                if pattern_lower not in gitignore_lower:
                    # Check for wildcards that would cover this
                    covered = False
                    if pattern.startswith("*."):
                        ext = pattern[1:]  # e.g., ".pem"
                        if ext in gitignore_lower or f"*{ext}" in gitignore_lower:
                            covered = True
                    if pattern == ".env" and ".env" in gitignore_lower:
                        covered = True

                    if not covered:
                        missing_patterns[severity].append((pattern, description))

        # Create findings for missing patterns
        for severity_str, patterns in missing_patterns.items():
            if not patterns:
                continue

            severity_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = severity_map[severity_str]

            for pattern, description in patterns:
                # Check if the file/pattern actually exists in the project
                if "*" in pattern:
                    exists = any(self.project_path.rglob(pattern.replace("**", "*")))
                else:
                    exists = (self.project_path / pattern).exists()

                # Only report if the file exists or it's a high-priority pattern
                if exists or severity == Severity.HIGH:
                    findings.append(self._create_finding(
                        type=f"deployment.gitignore_missing.{pattern.replace('.', '_').replace('*', 'star').replace('/', '_')}",
                        title=f"Missing .gitignore Pattern: {pattern}",
                        description=f".gitignore is missing '{pattern}' ({description}). This file type may be accidentally committed.",
                        severity=severity,
                        confidence=Confidence.HIGH if exists else Confidence.MEDIUM,
                        file_path=gitignore_path,
                        fix_recommendation=f"Add '{pattern}' to .gitignore",
                        cwe_id=self.CWE_INFO_EXPOSURE,
                        owasp_category="A05:2021",
                        auto_fixable=True,
                        metadata={
                            "scanner": self.name,
                            "category": "gitignore",
                            "pattern": pattern,
                            "fix_content": pattern,
                        },
                    ))

        return findings

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _mask_env_value(self, line: str) -> str:
        """Mask environment variable values."""
        # Mask values after = sign
        match = re.match(r'(ENV\s+\w+\s*=\s*)(.+)', line, re.IGNORECASE)
        if match:
            return f"{match.group(1)}****"
        return line

    def _mask_compose_value(self, line: str) -> str:
        """Mask docker-compose secret values."""
        # Mask values after : or =
        match = re.match(r'(\s*-?\s*\w+\s*[:=]\s*)(["\']?)(.+)(["\']?)', line)
        if match:
            return f"{match.group(1)}{match.group(2)}****{match.group(4)}"
        return line
