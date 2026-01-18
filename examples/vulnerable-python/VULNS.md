# Vulnerable Python Example

This project contains **intentionally vulnerable code** for testing and educational purposes.

**DO NOT deploy this code or use it as a template for real applications.**

## Vulnerabilities

### app.py

| Vulnerability | Line | CWE | OWASP |
|--------------|------|-----|-------|
| SQL Injection | `f"SELECT * FROM users WHERE id = {user_id}"` | CWE-89 | A03:2021 |
| Command Injection | `os.system(f"ping {host}")` | CWE-78 | A03:2021 |
| Command Injection | `subprocess.check_output(..., shell=True)` | CWE-78 | A03:2021 |
| Insecure Deserialization | `pickle.loads(user_data)` | CWE-502 | A08:2021 |
| XSS (Reflected) | `render_template_string(f"...{name}...")` | CWE-79 | A03:2021 |
| Path Traversal | `open(f"./uploads/{filename}")` | CWE-22 | A01:2021 |
| Hardcoded Password | `password='admin123'` | CWE-798 | A07:2021 |
| Debug Mode | `app.run(debug=True)` | CWE-489 | A05:2021 |

### config.py

| Vulnerability | Description | CWE |
|--------------|-------------|-----|
| Debug Mode | `DEBUG = True` | CWE-489 |
| Hardcoded Secret Key | `SECRET_KEY = "super-secret-key-123"` | CWE-798 |
| Hardcoded DB Password | `DB_PASSWORD = "admin123"` | CWE-798 |
| Hardcoded API Keys | Stripe, SendGrid keys in code | CWE-798 |
| Weak JWT Secret | `JWT_SECRET = "jwt-secret"` | CWE-798 |
| Insecure Cookies | `SESSION_COOKIE_SECURE = False` | CWE-614 |
| Permissive CORS | `CORS_ORIGINS = "*"` | CWE-942 |
| Default Credentials | `ADMIN_PASSWORD = "password123"` | CWE-798 |

### requirements.txt

| Package | Version | Known Vulnerabilities |
|---------|---------|----------------------|
| requests | 2.25.0 | CVE-2021-33503 (ReDoS) |
| pyyaml | 5.3 | CVE-2020-14343 (RCE) |
| celery | 5.0.0 | CVE-2021-23727 (ReDoS) |
| pillow | 6.2.0 | CVE-2019-16865 (DoS) |
| urllib3 | 1.25.0 | CVE-2021-28363 (SSRF) |
| django | 2.2.0 | CVE-2021-23336 (Cache Poisoning) |

### .env (Committed!)

| Secret Type | Example |
|------------|---------|
| API Key | `API_KEY=sk_live_...` |
| AWS Credentials | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| Database URL | Contains embedded password |
| JWT Secret | Exposed in version control |
| Various tokens | GitHub, Slack, Stripe, etc. |

## Expected Scanner Findings

When you run `sensei scan examples/vulnerable-python/`, you should see:
- **CRITICAL**: Hardcoded secrets, AWS credentials, API keys
- **HIGH**: SQL injection, command injection, insecure deserialization
- **MEDIUM**: Debug mode, XSS, path traversal, vulnerable dependencies
- **LOW**: Insecure cookie settings

## Learning Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://snyk.io/blog/python-security-best-practices/)
