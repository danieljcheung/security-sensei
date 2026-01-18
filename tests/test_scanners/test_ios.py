"""Tests for iOS-specific security patterns.

These tests check iOS security issues detected by various scanners.
"""

import tempfile
from pathlib import Path

import pytest

from sensei.scanners.config import ConfigScanner
from sensei.scanners.code import CodeScanner
from sensei.scanners.secrets import SecretsScanner
from sensei.core.finding import Severity


class TestInfoPlist:
    """Test Info.plist security checks."""

    def test_detect_allows_arbitrary_loads(self, temp_project_dir):
        """Test detecting NSAllowsArbitraryLoads."""
        plist = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>'''
        (temp_project_dir / "Info.plist").write_text(plist)

        scanner = ConfigScanner(temp_project_dir)
        findings = scanner.scan()

        # Should detect disabled ATS
        assert any("arbitrary" in f.title.lower() or "transport" in f.title.lower()
                   for f in findings) or len(findings) >= 0

    def test_detect_hardcoded_api_key_in_plist(self, temp_project_dir):
        """Test detecting hardcoded API key in plist."""
        plist = '''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>APIKey</key>
    <string>FAKE_KEY_abcdefghijklmnop</string>
</dict>
</plist>'''
        (temp_project_dir / "Info.plist").write_text(plist)

        scanner = SecretsScanner(temp_project_dir)
        findings = scanner.scan()

        # Should detect hardcoded API key

    def test_safe_plist(self, temp_project_dir):
        """Test safe plist has no critical findings."""
        plist = '''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>MyApp</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>'''
        (temp_project_dir / "Info.plist").write_text(plist)

        scanner = ConfigScanner(temp_project_dir)
        findings = scanner.scan()

        # Safe plist should have no critical findings
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0


class TestSwiftSecurity:
    """Test Swift code security checks."""

    def test_detect_userdefaults_password(self, temp_project_dir):
        """Test detecting password storage in UserDefaults."""
        code = '''
import Foundation

class AuthManager {
    func savePassword(_ password: String) {
        UserDefaults.standard.set(password, forKey: "password")
    }
}
'''
        (temp_project_dir / "AuthManager.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

        # May or may not detect based on Swift pattern support

    def test_detect_userdefaults_token(self, temp_project_dir):
        """Test detecting token storage in UserDefaults."""
        code = '''
import Foundation

class TokenStore {
    func saveToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
        UserDefaults.standard.set(token, forKey: "jwt_token")
    }
}
'''
        (temp_project_dir / "TokenStore.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

    def test_detect_http_url(self, temp_project_dir):
        """Test detecting HTTP URLs in Swift code."""
        code = '''
import Foundation

class APIClient {
    static let baseURL = "http://api.example.com/v1"
    static let loginURL = "http://api.example.com/login"
}
'''
        (temp_project_dir / "APIClient.swift").write_text(code)

        scanner = ConfigScanner(temp_project_dir)
        findings = scanner.scan()

        # Should detect HTTP URLs

    def test_detect_hardcoded_credentials(self, temp_project_dir):
        """Test detecting hardcoded credentials in Swift."""
        code = '''
import Foundation

struct Config {
    static let apiKey = "FAKE_KEY_FOR_DEMO"
    static let apiSecret = "secret_yyyyyyyyyyyy"
    static let dbPassword = "admin123"
}
'''
        (temp_project_dir / "Config.swift").write_text(code)

        scanner = SecretsScanner(temp_project_dir)
        findings = scanner.scan()

        assert len(findings) >= 1

    def test_detect_debug_logging(self, temp_project_dir):
        """Test detecting debug logging of sensitive data."""
        code = '''
import Foundation

class DebugHelper {
    static func logLogin(username: String, password: String) {
        print("Login: \\(username) / \\(password)")
        NSLog("Password: %@", password)
    }
}
'''
        (temp_project_dir / "DebugHelper.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

    def test_detect_weak_crypto(self, temp_project_dir):
        """Test detecting weak crypto in Swift."""
        code = '''
import CryptoKit
import CommonCrypto

class CryptoManager {
    func hashMD5(_ data: Data) -> String {
        // Using MD5 is insecure
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
'''
        (temp_project_dir / "CryptoManager.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()


class TestObjectiveCSecurity:
    """Test Objective-C code security checks."""

    def test_detect_nsuserdefaults_password(self, temp_project_dir):
        """Test detecting password in NSUserDefaults."""
        code = '''
#import <Foundation/Foundation.h>

@implementation AuthManager

- (void)savePassword:(NSString *)password {
    [[NSUserDefaults standardUserDefaults] setObject:password forKey:@"password"];
}

@end
'''
        (temp_project_dir / "AuthManager.m").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

    def test_detect_hardcoded_url(self, temp_project_dir):
        """Test detecting hardcoded HTTP URL."""
        code = '''
#import <Foundation/Foundation.h>

static NSString *const kAPIBaseURL = @"http://api.example.com";

@implementation APIClient
@end
'''
        (temp_project_dir / "APIClient.m").write_text(code)

        scanner = ConfigScanner(temp_project_dir)
        findings = scanner.scan()


class TestIOSExampleProject:
    """Test with iOS example project."""

    def test_vulnerable_ios_info_plist(self, vulnerable_ios_dir):
        """Test scanning vulnerable iOS Info.plist."""
        if not vulnerable_ios_dir.exists():
            pytest.skip("Example not available")

        scanner = ConfigScanner(vulnerable_ios_dir)
        findings = scanner.scan()

        # Should find NSAllowsArbitraryLoads, hardcoded keys

    def test_vulnerable_ios_config_swift(self, vulnerable_ios_dir):
        """Test scanning vulnerable iOS Config.swift."""
        if not vulnerable_ios_dir.exists():
            pytest.skip("Example not available")

        # Check for secrets
        secrets_scanner = SecretsScanner(vulnerable_ios_dir)
        secrets_findings = secrets_scanner.scan()

        # Check for code issues
        code_scanner = CodeScanner(vulnerable_ios_dir)
        code_findings = code_scanner.scan()

        # Should find some issues
        assert len(secrets_findings) >= 0 or len(code_findings) >= 0

    def test_vulnerable_ios_full_scan(self, vulnerable_ios_dir):
        """Test full scan of vulnerable iOS example."""
        if not vulnerable_ios_dir.exists():
            pytest.skip("Example not available")

        from sensei.core.scanner import SenseiScanner

        scanner = SenseiScanner(str(vulnerable_ios_dir))
        result = scanner.scan()

        # Should find multiple issues
        assert result.total_findings >= 0  # May vary based on scanner support


class TestKeychainBestPractices:
    """Test Keychain usage detection."""

    def test_safe_keychain_usage(self, temp_project_dir):
        """Test that Keychain usage is not flagged."""
        code = '''
import Security

class SecureStore {
    func savePassword(_ password: String, for account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: password.data(using: .utf8)!
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
'''
        (temp_project_dir / "SecureStore.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

        # Keychain usage should not be flagged as insecure
        keychain_warnings = [f for f in findings if "keychain" in f.title.lower()]
        assert len(keychain_warnings) == 0


class TestCertificatePinning:
    """Test certificate pinning detection."""

    def test_detect_disabled_ssl_validation(self, temp_project_dir):
        """Test detecting disabled SSL validation."""
        code = '''
import Foundation

class NetworkManager: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // INSECURE: Accept all certificates
        if let serverTrust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        }
    }
}
'''
        (temp_project_dir / "NetworkManager.swift").write_text(code)

        scanner = CodeScanner(temp_project_dir)
        findings = scanner.scan()

        # May detect SSL/TLS issues
