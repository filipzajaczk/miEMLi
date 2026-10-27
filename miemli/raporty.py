import re

from django.views.debug import SafeExceptionReporterFilter


class FiltrRaportu(SafeExceptionReporterFilter):
    """Domyślny filtr Django nie rozpoznaje polskich nazw (np. JOE_KLUCZ_PRYWATNY, REDIS_HASLO)."""

    hidden_settings = re.compile(
        "API|AUTH|TOKEN|KEY|SECRET|PASS|SIGNATURE|HTTP_COOKIE|KLUCZ|HASLO|HASŁO|PRYWATN|DATABASE_URL|REDIS_URL",
        flags=re.I,
    )
