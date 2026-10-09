import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
DEBUG = os.environ.get("DEBUG", "1") == "1"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = ["django.contrib.staticfiles", "django.contrib.messages", "core"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
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

# All data lives in MongoDB (via pymongo); Django's ORM is not used.
DATABASES = {}
MONGO_URI = os.environ["MONGO_URI"]  # required: set it in .env
MONGO_DB = os.environ.get("MONGO_DB", "hrms")

# Sessions and flash messages are stored in signed cookies, so no SQL database is needed.
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
MESSAGE_STORAGE = "django.contrib.messages.storage.cookie.CookieStorage"

CURRENCY = os.environ.get("CURRENCY", "₦")
STATIC_URL = "static/"
USE_TZ = False
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
