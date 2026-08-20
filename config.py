import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Core ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.getenv("SECRET_KEY", secrets.token_hex(32)))
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///insyrium.db",
    )
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # ── Tokens / sessions ─────────────────────────────────────────────────
    ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", 15))
    REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", 30))

    # ── OTP / MFA ─────────────────────────────────────────────────────────
    OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", 300))
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", 5))
    MFA_REQUIRED_ROLES = {
        "admin_support",
        "admin_content",
        "admin_platform",
        "supreme_admin",
    }

    # ── Account lockout ───────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", 15))

    # ── Mail ──────────────────────────────────────────────────────────────
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "no-reply@insyrium.com")
    # When no SMTP is configured, codes / links are printed to the server console.
    DEV_CONSOLE_OTP = os.getenv("DEV_CONSOLE_OTP", "true").lower() == "true"

    # ── Security headers ──────────────────────────────────────────────────
    HSTS_SECONDS = int(os.getenv("HSTS_SECONDS", 31536000))
    FORCE_HTTPS = os.getenv("FORCE_HTTPS", "false").lower() == "true"

    # ── Portal ────────────────────────────────────────────────────────────
    PORTAL_NAME = os.getenv("PORTAL_NAME", "Insyrium Portal")
    ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "true").lower() == "true"
