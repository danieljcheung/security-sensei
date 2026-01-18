"""Web security scanner for JavaScript/TypeScript projects."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sensei.scanners.base import BaseScanner
from sensei.core.finding import Finding, Severity, Confidence


class WebScanner(BaseScanner):
    """Scanner for web security vulnerabilities in JavaScript/TypeScript projects.

    Focuses on client-side security issues, insecure storage, cookie configuration,
    eval patterns, React-specific issues, and missing security dependencies.
    """

    name = "web"
    description = "Detects web security vulnerabilities in JS/TS projects"
    applies_to = ["javascript", "typescript"]

    # CWE mappings
    CWE_INSECURE_STORAGE = "CWE-922"
    CWE_SENSITIVE_COOKIE = "CWE-614"
    CWE_CODE_INJECTION = "CWE-94"
    CWE_XSS = "CWE-79"
    CWE_CSRF = "CWE-352"
    CWE_CORS = "CWE-942"
    CWE_MISSING_SECURITY = "CWE-693"

    # OWASP mappings
    OWASP_XSS = "A03:2021"
    OWASP_ACCESS_CONTROL = "A01:2021"
    OWASP_SECURITY_MISCONFIG = "A05:2021"

    # File extensions to scan
    JS_EXTENSIONS = [".js", ".jsx", ".mjs", ".cjs"]
    TS_EXTENSIONS = [".ts", ".tsx"]

    def __init__(self, project_path: Path, config: Optional[Dict] = None):
        super().__init__(project_path, config)
        self._is_express_app = False
        self._is_react_app = False
        self._package_json_data: Optional[Dict] = None

    def scan(self) -> List[Finding]:
        """Scan for web security vulnerabilities."""
        findings: List[Finding] = []

        # Check if this is a JS/TS project
        package_json_path = self.project_path / "package.json"
        if not package_json_path.exists():
            return findings  # Not a JS/TS project

        # Load and analyze package.json
        self._package_json_data = self._load_package_json(package_json_path)
        if self._package_json_data is None:
            return findings

        # Detect app type
        self._detect_app_type()

        # Run package.json checks
        findings.extend(self._check_package_json(package_json_path))

        # Scan JavaScript/TypeScript files
        all_extensions = self.JS_EXTENSIONS + self.TS_EXTENSIONS
        for ext in all_extensions:
            for file_path in self._find_files([f"*{ext}"]):
                content = self._read_file(file_path)
                if content is None:
                    continue

                findings.extend(self._scan_js_file(file_path, content))

        # Check config files for CORS and rate limiting
        findings.extend(self._check_config_files())

        return findings

    def _load_package_json(self, path: Path) -> Optional[Dict]:
        """Load and parse package.json."""
        content = self._read_file(path)
        if content is None:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def _detect_app_type(self) -> None:
        """Detect the type of application (Express, React, etc.)."""
        if self._package_json_data is None:
            return

        all_deps = {}
        all_deps.update(self._package_json_data.get("dependencies", {}))
        all_deps.update(self._package_json_data.get("devDependencies", {}))

        self._is_express_app = "express" in all_deps
        self._is_react_app = "react" in all_deps or "next" in all_deps

    # =========================================================================
    # Package.json Checks
    # =========================================================================

    def _check_package_json(self, file_path: Path) -> List[Finding]:
        """Check package.json for security issues."""
        findings: List[Finding] = []

        if self._package_json_data is None:
            return findings

        all_deps = {}
        all_deps.update(self._package_json_data.get("dependencies", {}))
        all_deps.update(self._package_json_data.get("devDependencies", {}))

        # Express-specific checks
        if self._is_express_app:
            # Check for helmet
            if "helmet" not in all_deps:
                findings.append(self._create_finding(
                    type="web.missing_helmet",
                    title="Missing Helmet Security Middleware",
                    description=(
                        "Express application detected without helmet dependency. "
                        "Helmet helps secure Express apps by setting various HTTP headers "
                        "like Content-Security-Policy, X-Frame-Options, and more."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    fix_recommendation=(
                        "Install helmet: npm install helmet\n"
                        "Then use it: const helmet = require('helmet'); app.use(helmet());"
                    ),
                    cwe_id=self.CWE_MISSING_SECURITY,
                    owasp_category=self.OWASP_SECURITY_MISCONFIG,
                    metadata={"scanner": self.name, "category": "missing_security"},
                ))

            # Check for CSRF protection
            if "csurf" not in all_deps and "csrf" not in all_deps and "csrf-csrf" not in all_deps:
                findings.append(self._create_finding(
                    type="web.missing_csrf",
                    title="Missing CSRF Protection",
                    description=(
                        "Express application detected without CSRF protection. "
                        "Applications with form submissions or state-changing requests "
                        "should implement CSRF protection."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    file_path=file_path,
                    fix_recommendation=(
                        "Install CSRF protection: npm install csrf-csrf\n"
                        "Or use csurf for legacy projects (deprecated): npm install csurf"
                    ),
                    cwe_id=self.CWE_CSRF,
                    owasp_category=self.OWASP_ACCESS_CONTROL,
                    metadata={"scanner": self.name, "category": "missing_security"},
                ))

            # Check for rate limiting
            if "express-rate-limit" not in all_deps and "rate-limiter-flexible" not in all_deps:
                findings.append(self._create_finding(
                    type="web.missing_rate_limit",
                    title="Missing Rate Limiting",
                    description=(
                        "Express application detected without rate limiting dependency. "
                        "Rate limiting helps protect against brute force and DoS attacks."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    file_path=file_path,
                    fix_recommendation=(
                        "Install rate limiting: npm install express-rate-limit\n"
                        "Then use it: const rateLimit = require('express-rate-limit'); "
                        "app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }));"
                    ),
                    cwe_id=self.CWE_MISSING_SECURITY,
                    owasp_category=self.OWASP_SECURITY_MISCONFIG,
                    metadata={"scanner": self.name, "category": "missing_security"},
                ))

        return findings

    # =========================================================================
    # JavaScript/TypeScript Code Checks
    # =========================================================================

    def _scan_js_file(self, file_path: Path, content: str) -> List[Finding]:
        """Scan a JavaScript/TypeScript file for security issues."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # Check for insecure token storage
            findings.extend(self._check_insecure_storage(file_path, line_num, line))

            # Check for insecure cookie settings
            findings.extend(self._check_insecure_cookies(file_path, line_num, line, content))

            # Check for eval patterns
            findings.extend(self._check_eval_patterns(file_path, line_num, line))

            # Check for React-specific issues
            if self._is_react_app:
                findings.extend(self._check_react_issues(file_path, line_num, line, content))

            # Check for fetch/axios without validation
            findings.extend(self._check_api_calls(file_path, line_num, line, content))

        return findings

    def _check_insecure_storage(
        self, file_path: Path, line_num: int, line: str
    ) -> List[Finding]:
        """Check for insecure token storage in localStorage/sessionStorage."""
        findings: List[Finding] = []

        # Patterns for insecure storage of sensitive data
        storage_patterns = [
            (r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|access_token|refresh_token|session|apiKey|api_key)["\']', "localStorage"),
            (r'sessionStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|access_token|refresh_token|session|apiKey|api_key)["\']', "sessionStorage"),
            (r'localStorage\s*\[\s*["\'](?:token|jwt|auth|access_token|refresh_token)["\']', "localStorage"),
            (r'sessionStorage\s*\[\s*["\'](?:token|jwt|auth|access_token|refresh_token)["\']', "sessionStorage"),
        ]

        for pattern, storage_type in storage_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(self._create_finding(
                    type=f"web.insecure_storage.{storage_type}",
                    title=f"Sensitive Token Stored in {storage_type}",
                    description=(
                        f"Authentication token stored in {storage_type}. "
                        f"Browser storage is accessible via JavaScript and vulnerable to XSS attacks. "
                        f"An attacker exploiting XSS can steal these tokens."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    fix_recommendation=(
                        "Use httpOnly cookies for authentication tokens. "
                        "HttpOnly cookies cannot be accessed via JavaScript, protecting against XSS token theft. "
                        "Set cookies server-side with: res.cookie('token', value, { httpOnly: true, secure: true, sameSite: 'strict' })"
                    ),
                    cwe_id=self.CWE_INSECURE_STORAGE,
                    owasp_category=self.OWASP_XSS,
                    metadata={"scanner": self.name, "category": "insecure_storage", "storage_type": storage_type},
                ))
                break

        return findings

    def _check_insecure_cookies(
        self, file_path: Path, line_num: int, line: str, content: str
    ) -> List[Finding]:
        """Check for insecure cookie configurations."""
        findings: List[Finding] = []

        # Check for cookie setting patterns
        cookie_patterns = [
            r'\.cookie\s*\(',
            r'res\.cookie\s*\(',
            r'cookies\.set\s*\(',
            r'setCookie\s*\(',
            r'document\.cookie\s*=',
        ]

        for pattern in cookie_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Get context around the cookie setting
                context = self._get_context_lines(content, line_num, 5)
                lower_context = context.lower()

                # Check for missing httpOnly
                if "httponly" not in lower_context:
                    findings.append(self._create_finding(
                        type="web.cookie_no_httponly",
                        title="Cookie Without httpOnly Flag",
                        description=(
                            "Cookie is set without the httpOnly flag. "
                            "Without httpOnly, cookies can be accessed via JavaScript, "
                            "making them vulnerable to theft via XSS attacks."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation="Add httpOnly: true to cookie options to prevent JavaScript access.",
                        cwe_id=self.CWE_SENSITIVE_COOKIE,
                        owasp_category=self.OWASP_XSS,
                        metadata={"scanner": self.name, "category": "insecure_cookie"},
                    ))

                # Check for missing secure flag
                if "secure" not in lower_context or "secure: false" in lower_context:
                    findings.append(self._create_finding(
                        type="web.cookie_no_secure",
                        title="Cookie Without Secure Flag",
                        description=(
                            "Cookie is set without the secure flag. "
                            "Without secure, cookies can be transmitted over unencrypted HTTP, "
                            "allowing interception by attackers."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation="Add secure: true to cookie options to ensure HTTPS-only transmission.",
                        cwe_id=self.CWE_SENSITIVE_COOKIE,
                        owasp_category=self.OWASP_SECURITY_MISCONFIG,
                        metadata={"scanner": self.name, "category": "insecure_cookie"},
                    ))

                # Check for missing sameSite
                if "samesite" not in lower_context:
                    findings.append(self._create_finding(
                        type="web.cookie_no_samesite",
                        title="Cookie Without SameSite Attribute",
                        description=(
                            "Cookie is set without the sameSite attribute. "
                            "SameSite helps protect against CSRF attacks by controlling "
                            "when cookies are sent with cross-origin requests."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation="Add sameSite: 'strict' or 'lax' to cookie options for CSRF protection.",
                        cwe_id=self.CWE_CSRF,
                        owasp_category=self.OWASP_ACCESS_CONTROL,
                        metadata={"scanner": self.name, "category": "insecure_cookie"},
                    ))

                break  # Only report once per line

        return findings

    def _check_eval_patterns(
        self, file_path: Path, line_num: int, line: str
    ) -> List[Finding]:
        """Check for dangerous eval and code execution patterns."""
        findings: List[Finding] = []

        # eval() with variable
        if re.search(r'\beval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', line):
            findings.append(self._create_finding(
                type="web.eval_variable",
                title="Eval with Dynamic Input",
                description=(
                    "eval() called with a variable argument. "
                    "If this variable contains user input, it enables arbitrary code execution."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                fix_recommendation=(
                    "Avoid eval() entirely. Use JSON.parse() for JSON data, "
                    "or consider safer alternatives like a sandboxed interpreter."
                ),
                cwe_id=self.CWE_CODE_INJECTION,
                owasp_category=self.OWASP_XSS,
                metadata={"scanner": self.name, "category": "code_injection"},
            ))

        # new Function() with variable
        if re.search(r'new\s+Function\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', line):
            findings.append(self._create_finding(
                type="web.function_constructor",
                title="Function Constructor with Dynamic Input",
                description=(
                    "Function constructor called with a variable argument. "
                    "This is equivalent to eval() and can execute arbitrary code."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                fix_recommendation="Avoid the Function constructor with dynamic input. Use safer alternatives.",
                cwe_id=self.CWE_CODE_INJECTION,
                owasp_category=self.OWASP_XSS,
                metadata={"scanner": self.name, "category": "code_injection"},
            ))

        # setTimeout/setInterval with string argument
        if re.search(r'\b(setTimeout|setInterval)\s*\(\s*["\'][^"\']+["\']', line):
            findings.append(self._create_finding(
                type="web.settimeout_string",
                title="setTimeout/setInterval with String Argument",
                description=(
                    "setTimeout or setInterval called with a string argument. "
                    "String arguments are evaluated like eval(), which can be dangerous."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                fix_recommendation="Use a function reference instead of a string: setTimeout(myFunction, 1000)",
                cwe_id=self.CWE_CODE_INJECTION,
                owasp_category=self.OWASP_XSS,
                metadata={"scanner": self.name, "category": "code_injection"},
            ))

        # setTimeout/setInterval with variable (potential string)
        if re.search(r'\b(setTimeout|setInterval)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*,', line):
            # Check if it's likely a function reference (lowercase is often a function)
            match = re.search(r'\b(setTimeout|setInterval)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)', line)
            if match:
                var_name = match.group(2)
                # Skip common function references
                if var_name not in ("function", "callback", "fn", "handler", "cb"):
                    findings.append(self._create_finding(
                        type="web.settimeout_variable",
                        title="setTimeout/setInterval with Variable",
                        description=(
                            "setTimeout or setInterval called with a variable. "
                            "If this variable is a string, it will be evaluated like eval()."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation="Ensure the variable is a function reference, not a string.",
                        cwe_id=self.CWE_CODE_INJECTION,
                        owasp_category=self.OWASP_XSS,
                        metadata={"scanner": self.name, "category": "code_injection"},
                    ))

        return findings

    def _check_react_issues(
        self, file_path: Path, line_num: int, line: str, content: str
    ) -> List[Finding]:
        """Check for React-specific security issues."""
        findings: List[Finding] = []

        # dangerouslySetInnerHTML
        if "dangerouslySetInnerHTML" in line:
            # Check context for sanitization
            context = self._get_context_lines(content, line_num, 10).lower()
            has_sanitization = any(
                sanitizer in context for sanitizer in
                ["dompurify", "sanitize", "xss", "escape", "encode"]
            )

            severity = Severity.LOW if has_sanitization else Severity.MEDIUM
            confidence = Confidence.MEDIUM if has_sanitization else Confidence.HIGH

            findings.append(self._create_finding(
                type="web.react_dangerous_html",
                title="React dangerouslySetInnerHTML Usage",
                description=(
                    "dangerouslySetInnerHTML bypasses React's XSS protections. "
                    "If the content includes user input without proper sanitization, "
                    "it can lead to XSS vulnerabilities."
                ),
                severity=severity,
                confidence=confidence,
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                fix_recommendation=(
                    "Avoid dangerouslySetInnerHTML if possible. "
                    "If you must use it, sanitize content with DOMPurify: "
                    "dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}"
                ),
                cwe_id=self.CWE_XSS,
                owasp_category=self.OWASP_XSS,
                metadata={
                    "scanner": self.name,
                    "category": "xss",
                    "has_sanitization": has_sanitization
                },
            ))

        # Unvalidated href with javascript: protocol potential
        if re.search(r'href\s*=\s*\{[^}]*\}', line):
            # This could be a dynamic href that might allow javascript: URLs
            if "javascript" not in line.lower():  # Don't double-report obvious cases
                context = self._get_context_lines(content, line_num, 5).lower()
                if "javascript" in context or "validate" not in context:
                    pass  # Could add a LOW severity finding here for dynamic hrefs

        return findings

    def _check_api_calls(
        self, file_path: Path, line_num: int, line: str, content: str
    ) -> List[Finding]:
        """Check for potentially unsafe API call patterns."""
        findings: List[Finding] = []

        # Check for fetch/axios calls with user-controlled URLs
        url_patterns = [
            (r'fetch\s*\(\s*[`$]', "fetch with template literal"),
            (r'axios\.\w+\s*\(\s*[`$]', "axios with template literal"),
            (r'fetch\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]', "fetch with variable URL"),
            (r'axios\.\w+\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]', "axios with variable URL"),
        ]

        for pattern, desc in url_patterns:
            if re.search(pattern, line):
                # Check for URL validation in context
                context = self._get_context_lines(content, line_num, 5).lower()
                has_validation = any(
                    check in context for check in
                    ["validate", "sanitize", "whitelist", "allowlist", "parseurl", "url.parse"]
                )

                if not has_validation:
                    findings.append(self._create_finding(
                        type="web.unvalidated_api_url",
                        title="API Call with Unvalidated URL",
                        description=(
                            f"{desc.capitalize()} detected. If the URL includes user input "
                            f"without validation, it could lead to SSRF or open redirect vulnerabilities."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation=(
                            "Validate URLs against an allowlist of permitted hosts. "
                            "Avoid including raw user input in API URLs."
                        ),
                        cwe_id="CWE-918",
                        owasp_category=self.OWASP_ACCESS_CONTROL,
                        metadata={"scanner": self.name, "category": "api_security"},
                    ))
                    break

        return findings

    # =========================================================================
    # Config File Checks
    # =========================================================================

    def _check_config_files(self) -> List[Finding]:
        """Check configuration files for security issues."""
        findings: List[Finding] = []

        # Check for CORS configuration
        config_patterns = [
            "*.config.js", "*.config.ts", "*.config.mjs",
            "server.js", "app.js", "index.js",
        ]

        for pattern in config_patterns:
            for file_path in self._find_files([pattern]):
                content = self._read_file(file_path)
                if content is None:
                    continue

                findings.extend(self._check_cors_config(file_path, content))

        return findings

    def _check_cors_config(self, file_path: Path, content: str) -> List[Finding]:
        """Check for CORS misconfigurations in config files."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Check for wildcard CORS origin
            if re.search(r'origin\s*:\s*["\']?\*["\']?', line, re.IGNORECASE):
                findings.append(self._create_finding(
                    type="web.cors_wildcard",
                    title="CORS Wildcard Origin",
                    description=(
                        "CORS configured to allow any origin (*). "
                        "This allows any website to make requests to your API, "
                        "which may expose sensitive data or enable attacks."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    fix_recommendation=(
                        "Specify explicit allowed origins instead of '*': "
                        "origin: ['https://your-frontend.com']"
                    ),
                    cwe_id=self.CWE_CORS,
                    owasp_category=self.OWASP_SECURITY_MISCONFIG,
                    metadata={"scanner": self.name, "category": "cors"},
                ))

            # Check for CORS with credentials and origin function that might return true
            if re.search(r'origin\s*:\s*(?:true|function)', line, re.IGNORECASE):
                context = self._get_context_lines(content, line_num, 5).lower()
                if "credentials" in context and "true" in context:
                    findings.append(self._create_finding(
                        type="web.cors_dynamic_origin",
                        title="CORS with Dynamic Origin Validation",
                        description=(
                            "CORS uses dynamic origin validation with credentials enabled. "
                            "Ensure the origin callback properly validates against an allowlist "
                            "and doesn't blindly reflect the Origin header."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_recommendation=(
                            "Verify the origin callback checks against a strict allowlist. "
                            "Never reflect the Origin header directly when credentials are enabled."
                        ),
                        cwe_id=self.CWE_CORS,
                        owasp_category=self.OWASP_SECURITY_MISCONFIG,
                        metadata={"scanner": self.name, "category": "cors"},
                    ))

        return findings
