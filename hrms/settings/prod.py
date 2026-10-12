from .base import *

DEBUG = os.environ.get("DEBUG", "0") == "1"

if DEBUG:
    # Localhost / development
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
    CSRF_TRUSTED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]

    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0
else:
    # Production (fewima.com)
    ALLOWED_HOSTS = ["fewima.com", "www.fewima.com"]
    CSRF_TRUSTED_ORIGINS = ["https://fewima.com", "https://www.fewima.com"]

    # HTTPS behind Nginx
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 3600          # raise to 31536000 once everything works
    SECURE_REFERRER_POLICY = "same-origin"
    X_FRAME_OPTIONS = "DENY"

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

# LOGGING = {
#     "version": 1,
#     "disable_existing_loggers": False,
#     "handlers": {"console": {"class": "logging.StreamHandler"}},
#     "root": {"handlers": ["console"], "level": "DEBUG" if DEBUG else "WARNING"},
# }