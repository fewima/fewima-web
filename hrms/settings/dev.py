# hrms/settings/base.py
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ["SECRET_KEY"]   # no fallback in base
# delete the DEBUG and ALLOWED_HOSTS lines; dev/prod set them

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",   # add this
    # ...rest unchanged
]
STATIC_ROOT = BASE_DIR / "staticfiles"