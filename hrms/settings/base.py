import os
from pathlib import Path

from dotenv import load_dotenv

# base.py -> settings -> hrms -> project root (where manage.py and .env live)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ["SECRET_KEY"]   # dev.py/prod.py handle fallbacks

INSTALLED_APPS = ["django.contrib.staticfiles", "django.contrib.messages", "core"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
ROOT_URLCONF = "hrms.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "hrms.wsgi.application"

DATABASES = {}
MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError(f"MONGO_URI is not set. Expected a .env file at {BASE_DIR / '.env'}")
MONGO_DB = os.environ.get("MONGO_DB", "hrms")

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
MESSAGE_STORAGE = "django.contrib.messages.storage.cookie.CookieStorage"

CURRENCY = os.environ.get("CURRENCY", "₦")
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
USE_TZ = False
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"