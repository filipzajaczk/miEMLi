"""Ustawienia miemli. Cała konfiguracja pochodzi ze zmiennych środowiskowych (.env)."""

import os
from pathlib import Path

import dj_database_url
from django.utils.csp import CSP

BASE_DIR = Path(__file__).resolve().parent.parent


def _lista(nazwa: str) -> list[str]:
    return [x.strip() for x in os.environ.get(nazwa, "").split(",") if x.strip()]


def _bool(nazwa: str, domyslnie: bool) -> bool:
    wartosc = os.environ.get(nazwa)
    if wartosc is None:
        return domyslnie
    return wartosc.strip().lower() in {"1", "true", "tak", "yes"}


SECRET_KEY = os.environ["SECRET_KEY"]
DEBUG = _bool("DEBUG", False)
ALLOWED_HOSTS = _lista("ALLOWED_HOSTS") or (["*"] if DEBUG else [])
CSRF_TRUSTED_ORIGINS = _lista("CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_rq",
    "analizy",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
]

# CSP dla stron aplikacji: tylko własne skrypty i style, bez inline. Podgląd maila ustawia własną, ostrzejszą.
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "script-src": [CSP.SELF],
    "style-src": [CSP.SELF],
    "img-src": [CSP.SELF, "data:"],
    "frame-src": [CSP.SELF],
    "connect-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.SELF],
}

ROOT_URLCONF = "miemli.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "analizy.kontekst.piaskownica",
            ],
        },
    },
]

WSGI_APPLICATION = "miemli.wsgi.application"

DATABASES = {
    "default": dj_database_url.parse(
        os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
    )
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
# JSON zamiast pickle: zapis do Redisa nie może prowadzić do wykonania kodu w workerze
RQ_QUEUES = {"default": {"URL": REDIS_URL, "SERIALIZER": "rq.serializers.JSONSerializer"}}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]

LANGUAGE_CODE = "pl"
TIME_ZONE = "Europe/Warsaw"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "analizy:lista"
LOGOUT_REDIRECT_URL = "login"

# Sesje i ciasteczka
SECURE_COOKIES = _bool("SECURE_COOKIES", True)
SESSION_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_SECURE = SECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Pliki tylko w pamięci, nigdy na dysku
MAKS_ROZMIAR_PLIKU = 50 * 1024 * 1024
FILE_UPLOAD_HANDLERS = ["django.core.files.uploadhandler.MemoryFileUploadHandler"]
FILE_UPLOAD_MAX_MEMORY_SIZE = MAKS_ROZMIAR_PLIKU
DATA_UPLOAD_MAX_MEMORY_SIZE = MAKS_ROZMIAR_PLIKU

# Sandbox parsera (kontener "parser"). Pusty = analiza w procesie web — tylko do pracy lokalnej i testów.
PIASKOWNICA_URL = os.environ.get("PIASKOWNICA_URL", "http://parser:8000").rstrip("/")
PARSER_WYMAGA_GVISOR = _bool("PARSER_WYMAGA_GVISOR", False)
# Analiza w procesie web (pusty PIASKOWNICA_URL) dozwolona tylko przy DEBUG albo jawnie tą flagą
PIASKOWNICA_W_PROCESIE = _bool("PIASKOWNICA_W_PROCESIE", False)

MIEMLI_IGNOROWANE_DOMENY = frozenset(d.lower() for d in _lista("MIEMLI_IGNOROWANE_DOMENY"))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"prosty": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"stdout": {"class": "logging.StreamHandler", "formatter": "prosty"}},
    "root": {"handlers": ["stdout"], "level": "INFO"},
    # httpx na INFO loguje pełne URL-e (z parametrami, np. organization_id z .env)
    "loggers": {"httpx": {"level": "WARNING"}, "httpcore": {"level": "WARNING"}},
}

# Wzbogacenie IOC — klucze tylko w .env
GTI_API_KEY = os.environ.get("GTI_API_KEY", "").strip()
CENSYS_API_TOKEN = os.environ.get("CENSYS_API_TOKEN", "").strip()
CENSYS_ORG_ID = os.environ.get("CENSYS_ORG_ID", "").strip()  # opcjonalne
# Kontener web nie dostaje kluczy (ma je tylko worker) — wie jedynie, którzy dostawcy są włączeni
GTI_WLACZONE = _bool("GTI_WLACZONE", bool(GTI_API_KEY))
CENSYS_WLACZONE = _bool("CENSYS_WLACZONE", bool(CENSYS_API_TOKEN))
