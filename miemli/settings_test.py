"""Ustawienia dla pytest: bezpieczne wartości domyślne zamiast .env."""

import os

os.environ.setdefault("SECRET_KEY", "test")
os.environ.setdefault("SECURE_COOKIES", "0")
os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")

from .settings import *  # noqa: E402,F401,F403

# Brak collectstatic w testach — whitenoise serwuje z STATICFILES_DIRS
STATIC_ROOT = None
WHITENOISE_USE_FINDERS = True
