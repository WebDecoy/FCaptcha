import os
from pathlib import Path
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "local-example-only-not-for-production")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]
ROOT_URLCONF = "fcaptcha_example.urls"
WSGI_APPLICATION = "fcaptcha_example.wsgi.application"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "contact",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.common.CommonMiddleware",
]
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
    ]},
}]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

APP_ORIGIN = os.environ.get("APP_ORIGIN", "http://127.0.0.1:8000").rstrip("/")
FCAPTCHA_ORIGIN = os.environ.get("FCAPTCHA_ORIGIN", "http://127.0.0.1:3000").rstrip("/")
FCAPTCHA_SITE_KEY = os.environ.get("FCAPTCHA_SITE_KEY", "django-demo")
FCAPTCHA_VERIFY_SECRET = os.environ.get("FCAPTCHA_VERIFY_SECRET", "")
FCAPTCHA_EXPECTED_HOSTNAME = urlsplit(APP_ORIGIN).hostname
