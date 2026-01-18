/**
 * Intentionally vulnerable configuration for security testing.
 * DO NOT use in production!
 */

module.exports = {
    // VULNERABLE: Overly permissive CORS
    cors: {
        origin: '*',
        credentials: true
    },

    // VULNERABLE: Hardcoded JWT secret
    jwt: {
        secret: 'my-super-secret-jwt-key',
        algorithm: 'HS256',
        expiresIn: '7d'
    },

    // VULNERABLE: Hardcoded database credentials
    database: {
        host: 'localhost',
        port: 5432,
        username: 'admin',
        password: 'admin123',
        database: 'production'
    },

    // VULNERABLE: Hardcoded API keys
    stripe: {
        secretKey: 'FAKE_stripe_secret_key_for_demo',
        publishableKey: 'FAKE_stripe_public_key_for_demo'
    },

    // VULNERABLE: Hardcoded third-party credentials
    aws: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1'
    },

    // VULNERABLE: Debug mode enabled
    debug: true,

    // VULNERABLE: Insecure session config
    session: {
        secret: 'keyboard cat',
        cookie: {
            secure: false,
            httpOnly: false,
            sameSite: 'none'
        }
    },

    // VULNERABLE: Default admin credentials
    admin: {
        username: 'admin',
        password: 'password123'
    },

    // VULNERABLE: Slack webhook exposed
    slack: {
        webhookUrl: 'https://example.com/fake-slack-webhook-for-demo'
    }
};
