from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from analizy import zadania
from integracje.wspolne import WynikDostawcy


@pytest.fixture
def atrapa(monkeypatch, settings):
    settings.GTI_API_KEY = "tajny-klucz-gti"
    settings.CENSYS_API_TOKEN = "tajny-token"
    stan = {"wynik": WynikDostawcy("gotowe")}
    monkeypatch.setattr(zadania, "_klient", lambda d: (lambda typ, wartosc: stan["wynik"]))
    return stan


def uruchom() -> str:
    out = StringIO()
    call_command("sprawdz_api", stdout=out)
    return out.getvalue()


def test_gotowe(atrapa):
    wyjscie = uruchom()
    assert "gti plik gotowe" in wyjscie and "gti ip gotowe" in wyjscie and "censys ip gotowe" in wyjscie
    assert "tajny" not in wyjscie


def test_blad_kod_1(atrapa):
    atrapa["wynik"] = WynikDostawcy("blad", blad="Odmowa dostępu (HTTP 403).")
    with pytest.raises(CommandError):
        uruchom()


def test_brak_klucza(atrapa, settings):
    settings.CENSYS_API_TOKEN = ""
    assert "censys: brak klucza" in uruchom()


def test_httpx_nie_loguje_adresow(settings):
    # httpx na poziomie INFO wypisuje pełne URL-e, a w nich np. organization_id z .env
    assert settings.LOGGING["loggers"]["httpx"]["level"] == "WARNING"
