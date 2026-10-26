"""Ustawienia dla pytest: bezpieczne wartości domyślne zamiast .env."""

import os

os.environ.setdefault("SECRET_KEY", "test")
os.environ.setdefault("SECURE_COOKIES", "0")
os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")

from .settings import *  # noqa: E402,F401,F403

# Brak collectstatic w testach — whitenoise serwuje z STATICFILES_DIRS
STATIC_ROOT = None
WHITENOISE_USE_FINDERS = True

# Testy nigdy nie używają prawdziwych kluczy API (testy wzbogacenia ustawiają własne)
GTI_API_KEY = ""
CENSYS_API_TOKEN = ""
CENSYS_ORG_ID = ""
