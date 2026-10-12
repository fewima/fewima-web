import os

from .base import *

ON_RENDER = os.environ.get("RENDER") == "true"
DEBUG = (not ON_RENDER) and os.environ.get("DEBUG", "0") == "1"

# ---------------------------------------------------------------------------
# Hosts, HTTPS and cookie security
# ---------------------------------------------------------------------------
if DEBUG:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
    CSRF_TRUSTED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]

    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0
else:
    ALLOWED_HOSTS = [
        "fewima.com",
        "www.fewima.com",
        "fewima-web.onrender.com",
    ]
    CSRF_TRUSTED_ORIGINS = [
        "https://fewima.com",
        "https://www.fewima.com",
        "https://fewima-web.onrender.com",
    ]

    # Any other hostname Render assigns
    RENDER_HOST = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
    if RENDER_HOST and RENDER_HOST not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(RENDER_HOST)
        CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_HOST}")

    # HTTPS behind Render's proxy
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 3600          # raise to 31536000 once everything works
    # Turn these two on together with the 31536000 value above:
    # SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    # SECURE_HSTS_PRELOAD = True
    SECURE_REFERRER_POLICY = "same-origin"
    X_FRAME_OPTIONS = "DENY"

# Cookie hardening (all environments)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

# Sessions: expire on browser close, 8h hard limit, refreshed on activity
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 8 * 3600
SESSION_SAVE_EVERY_REQUEST = True
SESSION_IDLE_SECONDS = 30 * 60          # read by views.py (idle timeout)
SESSION_ABSOLUTE_SECONDS = 8 * 3600     # read by views.py (absolute timeout)

# Browser protections
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",     # needs argon2-cffi in requirements.txt
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",     # keeps existing hashes working
]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Content Security Policy (django-csp 4.x; needs django-csp in requirements.txt)
# ---------------------------------------------------------------------------
if "csp.middleware.CSPMiddleware" not in MIDDLEWARE:
    MIDDLEWARE = [*MIDDLEWARE, "csp.middleware.CSPMiddleware"]

CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "style-src": ["'self'", "'unsafe-inline'"],   # remove 'unsafe-inline' once templates have no inline styles
        "script-src": ["'self'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
    }
}


REGISTRATION_INVITE_CODE = os.environ.get("REGISTRATION_INVITE_CODE", "")

CSRF_FAILURE_VIEW = "core.views.csrf_failed"

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "fewimaconsulting@gmail.com"
EMAIL_HOST_PASSWORD = "nwtf lwpz byeq tyum"   # a Google App Password, not your normal password
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER


STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if DEBUG
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        )
    },
}