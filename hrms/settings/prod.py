# hrms/settings/prod.py
import os

from .base import *

# Debug is only ever on locally. On Render (RENDER=true) it is always off.
ON_RENDER = os.environ.get("RENDER") == "true"
DEBUG = (not ON_RENDER) and os.environ.get("DEBUG", "0") == "1"

if DEBUG:
    # ---------- Local development ----------
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
    CSRF_TRUSTED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]

    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0
else:
    # ---------- Production ----------
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

