# Vulnerable iOS Example

This project contains **intentionally vulnerable code** for testing and educational purposes.

**DO NOT deploy this code or use it as a template for real applications.**

## Vulnerabilities

### Info.plist

| Vulnerability | Setting | CWE | Impact |
|--------------|---------|-----|--------|
| Insecure Transport | `NSAllowsArbitraryLoads: true` | CWE-319 | All network traffic can be sent over HTTP, vulnerable to MITM attacks |
| Arbitrary Media Loads | `NSAllowsArbitraryLoadsForMedia: true` | CWE-319 | Media content loaded without TLS |
| Arbitrary Web Content | `NSAllowsArbitraryLoadsInWebContent: true` | CWE-319 | WebViews can load insecure content |
| Hardcoded API Key | `APIKey` in plist | CWE-798 | API key extractable from app bundle |
| Hardcoded Google Key | `GoogleMapsAPIKey` in plist | CWE-798 | Google API key exposed |
| Hardcoded Firebase Key | `FirebaseAPIKey` in plist | CWE-798 | Firebase credentials exposed |
| Debug Mode Enabled | `EnableDebugMode: true` | CWE-489 | Debug features accessible in production |

### Config.swift

| Vulnerability | Code | CWE | OWASP Mobile |
|--------------|------|-----|--------------|
| Insecure HTTP | `http://api.example.com` | CWE-319 | M3 |
| UserDefaults Password | `UserDefaults.standard.set(password, ...)` | CWE-312 | M9 |
| UserDefaults Token | `UserDefaults.standard.set(token, ...)` | CWE-312 | M9 |
| UserDefaults SSN | `UserDefaults.standard.set(ssn, ...)` | CWE-312 | M9 |
| Hardcoded API Key | `static let apiKey = "sk_live_..."` | CWE-798 | M10 |
| Hardcoded DB Password | `static let dbPassword = "password123"` | CWE-798 | M10 |
| Hardcoded Encryption Key | `static let encryptionKey = "..."` | CWE-798 | M10 |
| Weak Encryption Key | `"1234567890123456"` | CWE-326 | M5 |
| MD5 Password Hashing | `password.md5()` | CWE-328 | M5 |
| Debug Logging Credentials | `print("password: \(password)")` | CWE-532 | M10 |
| Logging Auth Tokens | `print("Auth token: \(token)")` | CWE-532 | M10 |
| Test Credentials | `adminPassword = "admin123"` | CWE-798 | M10 |

### Package.swift

| Dependency | Version | Potential Issues |
|------------|---------|------------------|
| Alamofire | 4.9.0 | Outdated, check for security updates |
| SwiftyJSON | 4.0.0 | Outdated version |
| realm-swift | 5.0.0 | Check for data-at-rest encryption |
| CryptoSwift | 1.0.0 | May have deprecated crypto functions |

## iOS-Specific Security Issues

### Insecure Data Storage

Storing sensitive data in `UserDefaults` is insecure because:
- Data is stored in plain text in a plist file
- Accessible via backup extraction
- Readable on jailbroken devices
- Not encrypted at rest

**Correct approach:** Use iOS Keychain for sensitive data:
```swift
let keychain = Keychain(service: "com.example.app")
keychain["password"] = password
```

### App Transport Security (ATS)

Disabling ATS (`NSAllowsArbitraryLoads: true`) removes:
- HTTPS requirement
- TLS 1.2+ enforcement
- Forward secrecy requirements
- Certificate validation

**Impact:** All network traffic can be intercepted via MITM attacks.

### Hardcoded Secrets in App Bundle

Secrets in Swift files or Info.plist are:
- Compiled into the binary
- Extractable with tools like `strings`, `otool`, or reverse engineering tools
- Visible in app backups

**Correct approach:** Fetch secrets from a secure backend or use obfuscation (defense in depth).

## Expected Scanner Findings

When you run `sensei scan examples/vulnerable-ios/`, you should see:
- **CRITICAL**: Hardcoded API keys, disabled ATS
- **HIGH**: Password storage in UserDefaults, HTTP endpoints for auth
- **MEDIUM**: Debug logging of credentials, weak crypto
- **LOW**: Outdated dependencies

## Learning Resources

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Apple ATS Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
- [Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
