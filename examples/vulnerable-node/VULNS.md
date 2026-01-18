# Vulnerable Node.js Example

This project contains **intentionally vulnerable code** for testing and educational purposes.

**DO NOT deploy this code or use it as a template for real applications.**

## Vulnerabilities

### server.js

| Vulnerability | Code | CWE | OWASP |
|--------------|------|-----|-------|
| Code Injection | `eval(userInput)` | CWE-94 | A03:2021 |
| SQL Injection | `"SELECT * FROM users WHERE id = '" + userId + "'"` | CWE-89 | A03:2021 |
| SQL Injection | Template literal with `${searchTerm}` | CWE-89 | A03:2021 |
| XSS (DOM) | `innerHTML = '${content}'` | CWE-79 | A03:2021 |
| Command Injection | `exec('ping -c 4 ' + host)` | CWE-78 | A03:2021 |
| Insecure Storage | `localStorage.setItem('authToken', token)` | CWE-922 | A04:2021 |
| Insecure Storage | `sessionStorage.setItem('userPassword', ...)` | CWE-922 | A04:2021 |
| Insecure Cookies | Missing httpOnly, secure, sameSite | CWE-614 | A05:2021 |
| Path Traversal | `fs.readFileSync('./uploads/' + filename)` | CWE-22 | A01:2021 |
| SSRF | `fetch(url)` with user-controlled URL | CWE-918 | A10:2021 |
| Hardcoded Secrets | `DB_PASSWORD`, `API_KEY` in code | CWE-798 | A07:2021 |

### config.js

| Vulnerability | Description | CWE |
|--------------|-------------|-----|
| Permissive CORS | `origin: '*'` with credentials | CWE-942 |
| Hardcoded JWT Secret | `secret: 'my-super-secret-jwt-key'` | CWE-798 |
| Hardcoded DB Password | `password: 'admin123'` | CWE-798 |
| Hardcoded AWS Credentials | Full access keys exposed | CWE-798 |
| Hardcoded Stripe Keys | Live API keys in code | CWE-798 |
| Debug Mode | `debug: true` | CWE-489 |
| Insecure Cookies | `secure: false`, `httpOnly: false` | CWE-614 |
| Default Credentials | `password: 'password123'` | CWE-798 |
| Exposed Webhook | Slack webhook URL in code | CWE-798 |

### package.json

| Package | Version | Known Vulnerabilities |
|---------|---------|----------------------|
| lodash | 4.17.0 | CVE-2019-10744 (Prototype Pollution) |
| axios | 0.21.0 | CVE-2021-3749 (ReDoS) |
| node-serialize | 0.0.4 | CVE-2017-5941 (RCE) |
| js-yaml | 3.13.0 | CVE-2019-7548 (Code Execution) |
| minimist | 1.2.0 | CVE-2020-7598 (Prototype Pollution) |
| handlebars | 4.5.0 | CVE-2019-19919 (Prototype Pollution) |
| marked | 0.6.0 | CVE-2022-21680 (ReDoS) |
| tar | 4.4.0 | CVE-2021-32803 (Arbitrary File Write) |
| mongoose | 5.10.0 | CVE-2022-2564 (Prototype Pollution) |

### .env (Committed!)

| Secret Type | Example |
|------------|---------|
| Database URLs | PostgreSQL, MongoDB with passwords |
| API Keys | Stripe, SendGrid, Twilio |
| AWS Credentials | Access key and secret |
| JWT Secrets | Signing and refresh keys |
| Platform Tokens | GitHub, Slack bot tokens |

## Expected Scanner Findings

When you run `sensei scan examples/vulnerable-node/`, you should see:
- **CRITICAL**: Hardcoded API keys, AWS credentials, eval usage
- **HIGH**: SQL injection, command injection, XSS, prototype pollution dependencies
- **MEDIUM**: CORS *, insecure cookies, localStorage token storage
- **LOW**: Missing security headers

## Learning Resources

- [Node.js Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [NPM Security Best Practices](https://snyk.io/blog/ten-npm-security-best-practices/)
- [Express.js Security Tips](https://expressjs.com/en/advanced/best-practice-security.html)
