/**
 * Intentionally vulnerable iOS configuration for security testing.
 * DO NOT use in production!
 */

import Foundation

class AppConfig {
    // VULNERABLE: Hardcoded HTTP URLs (not HTTPS)
    static let apiBaseURL = "http://api.example.com/v1"
    static let imageServer = "http://images.example.com"
    static let analyticsEndpoint = "http://analytics.example.com/track"
    static let paymentGateway = "http://payments.example.com/process"

    // VULNERABLE: Hardcoded credentials
    static let apiKey = "FAKE_API_KEY_FOR_DEMO"
    static let apiSecret = "FAKE_SECRET_FOR_DEMO"
    static let encryptionKey = "my-hardcoded-encryption-key-123"

    // VULNERABLE: Hardcoded database credentials
    static let dbHost = "db.example.com"
    static let dbUser = "admin"
    static let dbPassword = "password123"
}


class AuthManager {
    static let shared = AuthManager()

    // VULNERABLE: Storing password in UserDefaults (not Keychain)
    func saveCredentials(username: String, password: String) {
        UserDefaults.standard.set(username, forKey: "username")
        UserDefaults.standard.set(password, forKey: "password")
        UserDefaults.standard.set(password, forKey: "user_password")
        UserDefaults.standard.synchronize()
    }

    // VULNERABLE: Storing auth token in UserDefaults
    func saveAuthToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
        UserDefaults.standard.set(token, forKey: "accessToken")
        UserDefaults.standard.set(token, forKey: "jwt_token")
    }

    // VULNERABLE: Storing sensitive data in UserDefaults
    func saveUserData(ssn: String, creditCard: String) {
        UserDefaults.standard.set(ssn, forKey: "userSSN")
        UserDefaults.standard.set(creditCard, forKey: "creditCardNumber")
    }

    func getPassword() -> String? {
        return UserDefaults.standard.string(forKey: "password")
    }
}


class NetworkManager {
    // VULNERABLE: Disabling SSL certificate validation
    func createUnsafeSession() -> URLSession {
        let config = URLSessionConfiguration.default
        // In real vulnerable code, this would disable certificate pinning
        return URLSession(configuration: config)
    }

    // VULNERABLE: HTTP requests for sensitive data
    func fetchUserProfile() {
        let url = URL(string: "http://api.example.com/user/profile")!
        URLSession.shared.dataTask(with: url) { data, response, error in
            // Handle response
        }.resume()
    }

    // VULNERABLE: Sending credentials over HTTP
    func login(username: String, password: String) {
        let url = URL(string: "http://api.example.com/auth/login")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        URLSession.shared.dataTask(with: request).resume()
    }
}


class CryptoManager {
    // VULNERABLE: Weak encryption
    static let encryptionKey = "1234567890123456"  // Weak key

    // VULNERABLE: Using MD5 for password hashing
    func hashPassword(_ password: String) -> String {
        // MD5 is cryptographically broken
        return password.md5()  // Assuming MD5 extension exists
    }

    // VULNERABLE: ECB mode encryption (pattern-preserving)
    func encryptData(_ data: Data) -> Data {
        // ECB mode is insecure
        // AES-ECB would be used here
        return data
    }
}


class DebugHelper {
    // VULNERABLE: Debug logging of sensitive data
    static func logUserLogin(username: String, password: String) {
        print("DEBUG: User login - username: \(username), password: \(password)")
        NSLog("Login attempt: %@ / %@", username, password)
    }

    // VULNERABLE: Logging auth tokens
    static func logAuthToken(_ token: String) {
        print("DEBUG: Auth token: \(token)")
    }
}


// VULNERABLE: Hardcoded test credentials
struct TestCredentials {
    static let adminUsername = "admin"
    static let adminPassword = "admin123"
    static let testAPIKey = "FAKE_TEST_KEY_FOR_DEMO"
}
