# Security Sensei

**Find vulnerabilities. Learn why they matter.**

A security scanner that doesn't just flag problems—it teaches you how to fix them and why they're dangerous.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

```bash
pip install security-sensei
sensei scan ./my-project
```

---

## What Makes This Different

Most security scanners give you a list of problems. Security Sensei gives you an education.

**The hybrid approach:** Deterministic scanning finds the vulnerabilities. AI-powered analysis teaches you why they matter.

For every finding, Sensei provides:

- **What it is** — Clear explanation of the vulnerability type
- **Why it's dangerous** — Real attack scenarios showing how it could be exploited
- **How to fix it** — Concrete code examples, not just generic advice
- **Certification mapping** — Links to Security+, CEH, and OWASP standards

This isn't just a tool—it's a learning experience that makes you a better developer.

---

## Demo

```
$ sensei scan ./my-app

Security Sensei v0.1.0
Scanning: ./my-app
Languages detected: python, javascript
Frameworks detected: fastapi, react

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] Hardcoded API Key Found
  File: src/config.py:23
  Code: OPENAI_KEY = "sk-proj-abc123..."

  CWE-798 | OWASP A01:2021 - Broken Access Control

  Why this matters:
  An attacker who gains access to your repository (via leak, insider threat,
  or compromised CI) can extract this key and make API calls on your behalf.
  For OpenAI keys, this could mean thousands of dollars in charges.

  Fix: Move to environment variables
  - export OPENAI_KEY="sk-proj-..."
  + OPENAI_KEY = os.environ.get("OPENAI_KEY")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[HIGH] SQL Injection Vulnerability
  File: api/users.py:47
  Code: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

  CWE-89 | OWASP A03:2021 - Injection

  Attack scenario:
  If user_id = "1; DROP TABLE users; --", this query becomes:
  SELECT * FROM users WHERE id = 1; DROP TABLE users; --
  Your entire users table is now gone.

  Fix: Use parameterized queries
  - cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  + cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scan complete: 2 critical, 1 high, 3 medium, 5 low
```

---

## Features

| Category | What It Catches | Languages |
|----------|-----------------|-----------|
| **Secrets** | API keys, tokens, passwords, private keys, secrets in git history | All |
| **Dependencies** | Known CVEs, outdated packages, typosquatting attacks | Python, Node.js |
| **Code** | SQL injection, XSS, command injection, path traversal | Python, JavaScript, Swift |
| **Config** | Debug mode enabled, permissive CORS, default credentials | All |
| **iOS** | ATS exceptions, Keychain misuse, Info.plist issues | Swift |
| **Web** | localStorage tokens, missing security headers, eval() usage | JavaScript/TypeScript |
| **Deployment** | Dockerfile issues, CI/CD misconfigs, missing .gitignore entries | All |

---

## Installation

**From PyPI:**
```bash
pip install security-sensei
```

**For development:**
```bash
git clone https://github.com/danieljcheung/security-sensei.git
cd security-sensei
pip install -e ".[dev]"
```

---

## Usage

### Basic Scan
```bash
sensei scan .
sensei scan ./src --severity high
```

### JSON Output (for CI/CD)
```bash
sensei scan . --format json > results.json
sensei scan . --format sarif > results.sarif
```

### Include Git History
Scan for secrets that were committed and later removed:
```bash
sensei scan . --include-history
```

### Baseline Accepted Risks
Mark known issues as accepted so they don't fail your build:
```bash
# Accept a specific finding
sensei baseline --accept abc123def

# View current baseline
sensei baseline --list

# Clear baseline
sensei baseline --clear
```

### Auto-Fix Safe Issues
Let Sensei fix simple issues automatically:
```bash
sensei scan . --fix
```

---

## Claude Integration

Security Sensei's JSON output is designed to feed directly into Claude for deeper analysis.

```bash
# Generate findings
sensei scan . --format json > findings.json

# Ask Claude to explain
claude "Explain the SQL injection finding in findings.json and show me 3 ways an attacker could exploit it"
```

Claude can provide:
- **Personalized explanations** based on your codebase context
- **Attack scenarios** specific to your application
- **Follow-up Q&A** to deepen your understanding
- **Custom fix suggestions** that match your coding style

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git scanning

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Security Sensei
        run: pip install security-sensei

      - name: Run Security Scan
        run: sensei scan . --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No issues found (or all issues baselined) |
| `1` | Security issues found |
| `2` | Scanner error (invalid config, etc.) |

---

## Why I Built This

I learn security by building. After vibe-coding several projects, I realized they all needed a security review before going to production—but most scanners just give you a wall of findings with no context.

I wanted a tool that:
- **Teaches while it scans** — Every finding is a learning opportunity
- **Explains the "why"** — Real attack scenarios, not just CVE numbers
- **Fits my workflow** — CLI-first, CI/CD ready, Claude-compatible

Security Sensei is the tool I wished I had when I started learning application security.

---

## Roadmap

- [ ] More language support (Go, Rust, Java)
- [ ] SARIF output for GitHub Security tab
- [ ] VS Code extension
- [ ] More auto-fix capabilities
- [ ] Container image scanning
- [ ] Infrastructure as Code scanning (Terraform, CloudFormation)

---

## Contributing

Contributions are welcome! Whether it's:
- Adding new vulnerability patterns
- Supporting new languages/frameworks
- Improving documentation
- Fixing bugs

Check out the [open issues](https://github.com/danieljcheung/security-sensei/issues) or open a new one.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Security Sensei</strong> — Because understanding vulnerabilities makes you dangerous (to attackers).
</p>
