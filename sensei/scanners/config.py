"""Configuration scanner for detecting security misconfigurations."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class ConfigScanner(BaseScanner):
    """Scanner for detecting security misconfigurations.

    Detects issues like debug mode enabled, default credentials,
    CORS misconfigurations, missing security headers, and exposed endpoints.
    """

    name = "config"
    description = "Detects security misconfigurations in config files"
    applies_to = []  # Applies to all projects

    # Files to specifically check
    CONFIG_FILE_PATTERNS = [
        "*.config.js",
        "*.config.ts",
        "*.config.mjs",
        "*.config.cjs",
        "settings.py",
        "config.py",
        "config/*.py",
        "settings/*.py",
        ".env",
        ".env.*",
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.*.yml",
        "docker-compose.*.yaml",
        "nginx.conf",
        "nginx/*.conf",
        "apache.conf",
        "httpd.conf",
        ".htaccess",
        "webpack.config.js",
        "vite.config.js",
        "vite.config.ts",
        "next.config.js",
        "next.config.mjs",
        "nuxt.config.js",
        "nuxt.config.ts",
        "app.yaml",
        "app.yml",
        "serverless.yml",
        "serverless.yaml",
        "Dockerfile",
        "package.json",
    ]

    # CWE mappings
    CWE_DEBUG = "CWE-489"
    CWE_DEFAULT_CREDS = "CWE-798"
    CWE_CORS = "CWE-942"
    CWE_SECURITY_HEADERS = "CWE-693"
    CWE_INFO_EXPOSURE = "CWE-200"

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)

    def scan(self) -> List[Finding]:
        """Scan for security misconfigurations."""
        findings: List[Finding] = []

        # Get all config files
        config_files = self._get_config_files()

        for file_path in config_files:
            content = self._read_file(file_path)
            if content is None:
                continue

            # Run all checks
            findings.extend(self._check_debug_mode(file_path, content))
            findings.extend(self._check_default_credentials(file_path, content))
            findings.extend(self._check_cors_misconfiguration(file_path, content))
            findings.extend(self._check_exposed_endpoints(file_path, content))
            findings.extend(self._check_security_headers(file_path, content))

        # Check for .env exposure
        findings.extend(self._check_env_exposure())

        return findings

    def _get_config_files(self) -> List[Path]:
        """Get all configuration files to scan."""
        all_files: List[Path] = []

        for pattern in self.CONFIG_FILE_PATTERNS:
            all_files.extend(self._find_files([pattern]))

        # Also check root-level config files
        root_configs = [
            ".env", ".env.local", ".env.development", ".env.production",
            ".env.staging", ".env.test", "config.json", "config.yaml",
            "config.yml", "settings.json",
        ]
        for config_name in root_configs:
            config_path = self.project_path / config_name
            if config_path.exists() and config_path.is_file():
                all_files.append(config_path)

        return list(set(all_files))

    # =========================================================================
    # Debug Mode Detection
    # =========================================================================

    def _check_debug_mode(self, file_path: Path, content: str) -> List[Finding]:
        """Check for debug mode enabled in configuration."""
        findings: List[Finding] = []
        filename = file_path.name.lower()
        lines = content.splitlines()

        # Determine if this is a production file (increases severity)
        is_production_file = any(
            prod in filename for prod in ["prod", "production", "live"]
        )

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Python DEBUG = True
            if re.search(r'\bDEBUG\s*=\s*True\b', line, re.IGNORECASE):
                severity = Severity.HIGH if is_production_file else Severity.MEDIUM
                findings.append(self._create_finding(
                    type="config.debug_enabled.python",
                    title="Debug Mode Enabled",
                    description=(
                        "DEBUG = True in configuration. Debug mode can expose "
                        "sensitive information, stack traces, and internal paths."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Set DEBUG = False in production environments.",
                    cwe_id=self.CWE_DEBUG,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "debug_mode"},
                ))

            # JSON/JS "debug": true
            if re.search(r'["\']?debug["\']?\s*[:=]\s*true', line, re.IGNORECASE):
                severity = Severity.HIGH if is_production_file else Severity.MEDIUM
                findings.append(self._create_finding(
                    type="config.debug_enabled.json",
                    title="Debug Mode Enabled",
                    description=(
                        "Debug mode is enabled in configuration. This may expose "
                        "sensitive debugging information in production."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Disable debug mode in production configurations.",
                    cwe_id=self.CWE_DEBUG,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "debug_mode"},
                ))

            # Flask/Django debug in app config
            if re.search(r'app\.debug\s*=\s*True', line, re.IGNORECASE):
                severity = Severity.HIGH if is_production_file else Severity.MEDIUM
                findings.append(self._create_finding(
                    type="config.debug_enabled.flask",
                    title="Flask Debug Mode Enabled",
                    description=(
                        "Flask debug mode exposes an interactive debugger that allows "
                        "arbitrary code execution. Never enable in production."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped,
                    fix_recommendation="Set app.debug = False or use environment-based configuration.",
                    cwe_id=self.CWE_DEBUG,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "debug_mode"},
                ))

            # NODE_ENV check missing patterns
            if "NODE_ENV" in line and "production" not in line.lower():
                if re.search(r'NODE_ENV\s*[!=]=\s*["\']development["\']', line):
                    # This is checking for development, might be missing production check
                    pass  # Informational, not flagged

        return findings

    # =========================================================================
    # Default Credentials Detection
    # =========================================================================

    def _check_default_credentials(self, file_path: Path, content: str) -> List[Finding]:
        """Check for default or weak credentials."""
        findings: List[Finding] = []
        lines = content.splitlines()

        # Default username/password combinations
        default_creds = [
            (r'admin.*admin', "admin/admin"),
            (r'root.*root', "root/root"),
            (r'user.*user', "user/user"),
            (r'test.*test', "test/test"),
            (r'password.*password', "password/password"),
            (r'guest.*guest', "guest/guest"),
        ]

        # Weak/default secret patterns
        weak_secrets = [
            (r'(?:secret|jwt_secret|secret_key|api_key)\s*[:=]\s*["\'](?:secret|changeme|your[_-]?secret[_-]?(?:key)?|change[_-]?me|default|password|123456)["\']', "default secret value"),
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\'](?:password|123456|admin|root|changeme|default)["\']', "weak password"),
            (r'SECRET_KEY\s*=\s*["\'](?:secret|changeme|your[_-]?secret[_-]?key|django-insecure)["\']', "insecure Django SECRET_KEY"),
        ]

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            lower_line = line.lower()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check for default credential patterns (only in lines with both user and pass context)
            if ("user" in lower_line or "admin" in lower_line or "root" in lower_line) and \
               ("pass" in lower_line or "pwd" in lower_line or "auth" in lower_line):
                for pattern, cred_type in default_creds:
                    if re.search(pattern, lower_line, re.IGNORECASE):
                        findings.append(self._create_finding(
                            type="config.default_credentials",
                            title=f"Default Credentials Detected ({cred_type})",
                            description=(
                                f"Possible default credentials ({cred_type}) found. "
                                f"Default credentials are commonly known and easily exploited."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._mask_sensitive(stripped),
                            fix_recommendation="Use strong, unique credentials stored in environment variables.",
                            cwe_id=self.CWE_DEFAULT_CREDS,
                            owasp_category="A07:2021",
                            metadata={"scanner": self.name, "category": "default_credentials"},
                        ))
                        break

            # Check for weak secrets
            for pattern, secret_type in weak_secrets:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._create_finding(
                        type="config.weak_secret",
                        title=f"Weak or Default Secret ({secret_type})",
                        description=(
                            f"A weak or default secret value was detected. "
                            f"These values are commonly known and provide no security."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._mask_sensitive(stripped),
                        fix_recommendation=(
                            "Generate a strong, random secret. Use environment variables "
                            "to store secrets: SECRET_KEY = os.environ.get('SECRET_KEY')"
                        ),
                        cwe_id=self.CWE_DEFAULT_CREDS,
                        owasp_category="A07:2021",
                        metadata={"scanner": self.name, "category": "weak_secret"},
                    ))
                    break

        return findings

    # =========================================================================
    # CORS Misconfiguration Detection
    # =========================================================================

    def _check_cors_misconfiguration(self, file_path: Path, content: str) -> List[Finding]:
        """Check for CORS misconfigurations."""
        findings: List[Finding] = []
        lines = content.splitlines()

        has_wildcard_origin = False
        has_credentials = False
        wildcard_line_num = 0
        wildcard_line_content = ""

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check for Access-Control-Allow-Origin: *
            if re.search(r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*', line, re.IGNORECASE):
                has_wildcard_origin = True
                wildcard_line_num = line_num
                wildcard_line_content = stripped

            # Check for CORS origin: '*' in various frameworks
            if re.search(r'(?:origin|allowedOrigins?)\s*[:=]\s*["\']?\*["\']?', line, re.IGNORECASE):
                has_wildcard_origin = True
                wildcard_line_num = line_num
                wildcard_line_content = stripped

            # Check for credentials: true
            if re.search(r'credentials\s*[:=]\s*true', line, re.IGNORECASE):
                has_credentials = True

            # Check for Access-Control-Allow-Credentials: true
            if re.search(r'Access-Control-Allow-Credentials["\']?\s*[:=]\s*["\']?true', line, re.IGNORECASE):
                has_credentials = True

        # Wildcard origin alone is medium severity
        if has_wildcard_origin:
            if has_credentials:
                # Wildcard with credentials is HIGH severity
                findings.append(self._create_finding(
                    type="config.cors_credentials_wildcard",
                    title="CORS: Wildcard Origin with Credentials",
                    description=(
                        "CORS is configured with wildcard origin (*) and credentials allowed. "
                        "This is a critical misconfiguration that can enable CSRF attacks "
                        "and credential theft from any origin."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=wildcard_line_num,
                    code_snippet=wildcard_line_content,
                    fix_recommendation=(
                        "Specify explicit allowed origins instead of '*' when credentials are enabled. "
                        "Example: origin: ['https://trusted-site.com']"
                    ),
                    cwe_id=self.CWE_CORS,
                    owasp_category="A01:2021",
                    metadata={"scanner": self.name, "category": "cors"},
                ))
            else:
                # Wildcard without credentials is medium severity
                findings.append(self._create_finding(
                    type="config.cors_wildcard_origin",
                    title="CORS: Wildcard Origin Allowed",
                    description=(
                        "CORS is configured to allow requests from any origin (*). "
                        "While this may be intentional for public APIs, it can expose "
                        "your API to unintended cross-origin requests."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    file_path=file_path,
                    line_number=wildcard_line_num,
                    code_snippet=wildcard_line_content,
                    fix_recommendation=(
                        "Consider restricting to specific trusted origins if this API "
                        "handles sensitive data or authenticated requests."
                    ),
                    cwe_id=self.CWE_CORS,
                    owasp_category="A01:2021",
                    metadata={"scanner": self.name, "category": "cors"},
                ))

        return findings

    # =========================================================================
    # Exposed Endpoints Detection
    # =========================================================================

    def _check_exposed_endpoints(self, file_path: Path, content: str) -> List[Finding]:
        """Check for potentially exposed sensitive endpoints."""
        findings: List[Finding] = []
        lines = content.splitlines()

        # Sensitive endpoints that may need auth
        sensitive_endpoints = [
            (r'["\'/]admin["\'/]', "/admin", "Administrative interface"),
            (r'["\'/]debug["\'/]', "/debug", "Debug endpoint"),
            (r'["\'/]swagger["\'/]', "/swagger", "API documentation (Swagger)"),
            (r'["\'/]api-docs["\'/]', "/api-docs", "API documentation"),
            (r'["\'/]graphql["\'/]', "/graphql", "GraphQL endpoint"),
            (r'["\'/]graphiql["\'/]', "/graphiql", "GraphQL IDE"),
            (r'["\'/]phpinfo["\'/]', "/phpinfo", "PHP info page"),
            (r'["\'/]actuator["\'/]', "/actuator", "Spring Boot Actuator"),
            (r'["\'/]metrics["\'/]', "/metrics", "Metrics endpoint"),
            (r'["\'/]health["\'/]', "/health", "Health check endpoint"),
            (r'["\'/]status["\'/]', "/status", "Status endpoint"),
            (r'["\'/]\.well-known["\'/]', "/.well-known", "Well-known directory"),
        ]

        seen_endpoints: Set[str] = set()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            lower_line = line.lower()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, endpoint, desc in sensitive_endpoints:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if already found
                    if endpoint in seen_endpoints:
                        continue
                    seen_endpoints.add(endpoint)

                    # Check if auth is mentioned nearby
                    context = self._get_context_lines(content, line_num, 5).lower()
                    has_auth = any(
                        auth in context for auth in
                        ["auth", "login", "permission", "protected", "middleware", "guard", "authenticate"]
                    )

                    if not has_auth:
                        findings.append(self._create_finding(
                            type=f"config.exposed_endpoint.{endpoint.strip('/')}",
                            title=f"Exposed Endpoint: {endpoint}",
                            description=(
                                f"{desc} detected without obvious authentication. "
                                f"Ensure this endpoint is properly protected."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=stripped,
                            fix_recommendation=(
                                f"Verify that {endpoint} requires authentication and authorization. "
                                f"Consider restricting access by IP or adding authentication middleware."
                            ),
                            cwe_id=self.CWE_INFO_EXPOSURE,
                            owasp_category="A01:2021",
                            metadata={"scanner": self.name, "category": "exposed_endpoint", "endpoint": endpoint},
                        ))

        return findings

    # =========================================================================
    # Security Headers Detection
    # =========================================================================

    def _check_security_headers(self, file_path: Path, content: str) -> List[Finding]:
        """Check for missing security headers configuration."""
        findings: List[Finding] = []
        filename = file_path.name.lower()
        lower_content = content.lower()

        # Only check relevant files
        is_express_config = filename in ("app.js", "server.js", "index.js") or "express" in lower_content
        is_nginx_config = "nginx" in filename or filename == ".htaccess"

        if is_express_config:
            # Check for helmet() usage in Express apps
            if "express" in lower_content and "helmet" not in lower_content:
                findings.append(self._create_finding(
                    type="config.missing_helmet",
                    title="Missing Security Headers (Helmet)",
                    description=(
                        "Express application detected without Helmet.js. Helmet helps secure "
                        "Express apps by setting various HTTP headers (CSP, X-Frame-Options, etc.)."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    file_path=file_path,
                    fix_recommendation=(
                        "Install and use helmet: npm install helmet\n"
                        "const helmet = require('helmet'); app.use(helmet());"
                    ),
                    cwe_id=self.CWE_SECURITY_HEADERS,
                    owasp_category="A05:2021",
                    metadata={"scanner": self.name, "category": "security_headers"},
                ))

            # Check for missing CSP
            if "contentSecurityPolicy" not in content and "content-security-policy" not in lower_content:
                # Only flag if there's evidence of HTML rendering
                if any(x in lower_content for x in ["render", "html", "template", "view"]):
                    findings.append(self._create_finding(
                        type="config.missing_csp",
                        title="Missing Content Security Policy",
                        description=(
                            "No Content Security Policy (CSP) configuration detected. "
                            "CSP helps prevent XSS attacks by controlling resource loading."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        file_path=file_path,
                        fix_recommendation=(
                            "Implement CSP using helmet.contentSecurityPolicy() or set the "
                            "Content-Security-Policy header manually."
                        ),
                        cwe_id=self.CWE_SECURITY_HEADERS,
                        owasp_category="A05:2021",
                        metadata={"scanner": self.name, "category": "security_headers"},
                    ))

        # Check nginx/apache configs for security headers
        if is_nginx_config:
            security_headers = [
                ("X-Frame-Options", "clickjacking"),
                ("X-Content-Type-Options", "MIME sniffing"),
                ("X-XSS-Protection", "XSS filter"),
            ]
            for header, protection in security_headers:
                if header.lower() not in lower_content:
                    findings.append(self._create_finding(
                        type=f"config.missing_header.{header.lower().replace('-', '_')}",
                        title=f"Missing Security Header: {header}",
                        description=f"The {header} header is not configured. This provides {protection} protection.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        fix_recommendation=f"Add header {header} to your server configuration.",
                        cwe_id=self.CWE_SECURITY_HEADERS,
                        owasp_category="A05:2021",
                        metadata={"scanner": self.name, "category": "security_headers", "header": header},
                    ))

        return findings

    # =========================================================================
    # .env Exposure Detection
    # =========================================================================

    def _check_env_exposure(self) -> List[Finding]:
        """Check if .env files might be exposed."""
        findings: List[Finding] = []

        # Check if .gitignore exists and includes .env
        gitignore_path = self.project_path / ".gitignore"
        env_files = list(self.project_path.glob(".env*"))

        if env_files:
            if gitignore_path.exists():
                gitignore_content = self._read_file(gitignore_path) or ""

                # Check if .env patterns are in .gitignore
                env_patterns = [".env", ".env.*", ".env*", "*.env"]
                has_env_ignore = any(
                    pattern in gitignore_content for pattern in env_patterns
                )

                if not has_env_ignore:
                    for env_file in env_files:
                        findings.append(self._create_finding(
                            type="config.env_not_gitignored",
                            title=".env File Not in .gitignore",
                            description=(
                                f"The file {env_file.name} exists but .env is not in .gitignore. "
                                f"Environment files often contain secrets and should not be committed."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=env_file,
                            fix_recommendation=(
                                "Add .env to .gitignore:\n"
                                "echo '.env' >> .gitignore\n"
                                "echo '.env.*' >> .gitignore"
                            ),
                            cwe_id=self.CWE_INFO_EXPOSURE,
                            owasp_category="A05:2021",
                            metadata={"scanner": self.name, "category": "env_exposure"},
                        ))
            else:
                # No .gitignore at all
                for env_file in env_files:
                    findings.append(self._create_finding(
                        type="config.env_no_gitignore",
                        title=".env File Without .gitignore",
                        description=(
                            f"The file {env_file.name} exists but there is no .gitignore file. "
                            f"Environment files contain secrets and must not be committed."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=env_file,
                        fix_recommendation="Create a .gitignore file and add .env patterns to it.",
                        cwe_id=self.CWE_INFO_EXPOSURE,
                        owasp_category="A05:2021",
                        metadata={"scanner": self.name, "category": "env_exposure"},
                    ))

        # Check for .env files with sensitive content
        for env_file in env_files:
            content = self._read_file(env_file)
            if content:
                lines = content.splitlines()
                for line_num, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    # Check for actual secrets (not placeholders)
                    if "=" in stripped:
                        key, _, value = stripped.partition("=")
                        value = value.strip().strip('"').strip("'")

                        # Skip empty or placeholder values
                        if not value or any(
                            placeholder in value.lower() for placeholder in
                            ["your_", "changeme", "xxx", "todo", "placeholder", "<", ">"]
                        ):
                            continue

                        # Flag if it looks like a real secret
                        secret_keys = ["password", "secret", "key", "token", "api_key", "private"]
                        if any(sk in key.lower() for sk in secret_keys) and len(value) > 8:
                            findings.append(self._create_finding(
                                type="config.env_contains_secret",
                                title="Secret in .env File",
                                description=(
                                    f"The .env file contains what appears to be a real secret for '{key}'. "
                                    f"Ensure this file is not committed to version control."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                file_path=env_file,
                                line_number=line_num,
                                code_snippet=f"{key}=****",
                                fix_recommendation=(
                                    "Ensure .env is in .gitignore. Consider using a secrets manager "
                                    "for production environments."
                                ),
                                cwe_id=self.CWE_INFO_EXPOSURE,
                                owasp_category="A05:2021",
                                metadata={"scanner": self.name, "category": "env_exposure", "key": key},
                            ))
                            break  # Only flag once per file

        return findings

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive values in text for display."""
        # Mask password/secret values
        patterns = [
            (r'((?:password|passwd|pwd|secret|key|token)\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1****\3'),
        ]
        result = text
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result
