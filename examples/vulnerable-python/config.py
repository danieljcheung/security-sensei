"""Intentionally vulnerable configuration for security testing."""

# VULNERABLE: Debug mode enabled in production
DEBUG = True

# VULNERABLE: Hardcoded secret key
SECRET_KEY = "super-secret-key-123"

# VULNERABLE: Hardcoded database credentials
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASSWORD = "admin123"
DB_NAME = "production_db"

# VULNERABLE: Hardcoded API keys
STRIPE_API_KEY = "FAKE_stripe_key_for_demo"
SENDGRID_API_KEY = "FAKE_sendgrid_key_for_demo"

# VULNERABLE: Weak JWT configuration
JWT_SECRET = "jwt-secret"
JWT_ALGORITHM = "HS256"

# VULNERABLE: Insecure session configuration
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

# VULNERABLE: Overly permissive CORS
CORS_ORIGINS = "*"

# VULNERABLE: Default admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

# Database connection string with embedded password
DATABASE_URL = "postgresql://admin:admin123@localhost:5432/myapp"
